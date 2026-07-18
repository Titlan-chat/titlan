// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.crypto

import android.app.KeyguardManager
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-1 acceptance: Keystore wrap/unwrap round-trip and the maintainer-resolved
 * key lifecycle (F1: non-invalidating, not unlock-bound). Red until the
 * DbKeyManager green commit.
 */
@RunWith(AndroidJUnit4::class)
class DbKeyManagerTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun freshState() {
        // Reset key AND DB state coherently (run 29613625849: key-only
        // resets leave a stale SQLCipher DB under the old key for any
        // later test that opens it).
        for (name in listOf(
            "titlan.db", "titlan.db-journal", "titlan.db-wal", "titlan.db-shm",
            DbKeyManager.WRAP_FILE, "${DbKeyManager.WRAP_FILE}.tmp",
        )) {
            File(context.filesDir, name).delete()
        }
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            deleteEntry(DbKeyManager.KEYSTORE_ALIAS)
        }
    }

    @Test
    fun firstCallCreatesWrappedKeyAtRest() {
        val key = DbKeyManager(context).getOrCreateDbKey()
        assertEquals("DB key must be exactly 32 bytes", 32, key.size)

        val blob = File(context.filesDir, DbKeyManager.WRAP_FILE)
        assertTrue("wrapped blob must exist after first call", blob.exists())

        val blobBytes = blob.readBytes()
        assertFalse(
            "wrapped blob must not contain the raw key (INV-1)",
            containsSubsequence(blobBytes, key),
        )
    }

    @Test
    fun unwrapRoundTripAcrossInstances() {
        val born = DbKeyManager(context).getOrCreateDbKey()
        val unwrapped = DbKeyManager(context).getOrCreateDbKey()
        assertArrayEquals(
            "a fresh manager instance (process-restart proxy) must unwrap the same key",
            born,
            unwrapped,
        )
    }

    @Test
    fun wrappingKeyLifecycleMatchesResolvedF1() {
        DbKeyManager(context).getOrCreateDbKey()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = ks.getKey(DbKeyManager.KEYSTORE_ALIAS, null) as SecretKey
        val info = SecretKeyFactory.getInstance(entry.algorithm, "AndroidKeyStore")
            .getKeySpec(entry, KeyInfo::class.java) as KeyInfo

        assertFalse(
            "F1: wrapping key must not require user authentication " +
                "(survives lock-screen changes; usable while locked)",
            info.isUserAuthenticationRequired,
        )
        assertFalse(
            "F1: wrapping key must not be invalidated by biometric enrollment",
            info.isInvalidatedByBiometricEnrollment,
        )
        // NOTE: unlockedDeviceRequired has NO KeyInfo getter (verified
        // against android-36 android.jar) — that F1 property is asserted
        // behaviorally in keyUsableWhileDeviceLocked below.
        // Security level is informational (emulator = software, device =
        // StrongBox/TEE); the query itself must succeed so the settings
        // diagnostic can surface it.
        check(info.securityLevel >= KeyProperties.SECURITY_LEVEL_SOFTWARE)
    }

    @Test
    fun keyUsableWhileDeviceLocked() {
        // F1's operative guarantee: the foreground service must unwrap the
        // DB key and persist messages while the device is locked. KeyInfo
        // cannot report unlockedDeviceRequired, so engage a real keyguard
        // and exercise the unwrap under it.
        //
        // STABILIZATION RULE (maintainer-set 2026-07-16): stabilization
        // passes may touch waits, polling, and cleanup — NEVER the asserted
        // property (unwrap succeeds while isDeviceLocked). If this cannot
        // be stabilized on the CI emulator, the fallback is a device-only
        // annotation + documented manual verification per the §6 Phase-5
        // pattern — not deletion, not weakening.
        val born = DbKeyManager(context).getOrCreateDbKey()
        shell("locksettings set-pin 1234")
        try {
            shell("input keyevent 26") // power: screen off, keyguard engages
            val km = context.getSystemService(KeyguardManager::class.java)!!
            val deadline = System.currentTimeMillis() + 10_000
            while (!km.isDeviceLocked && System.currentTimeMillis() < deadline) {
                Thread.sleep(250)
            }
            assertTrue(
                "positive control failed: keyguard did not engage — the " +
                    "locked-unwrap assertion below would be meaningless",
                km.isDeviceLocked,
            )
            val unwrapped = DbKeyManager(context).getOrCreateDbKey()
            assertArrayEquals(
                "DB key must unwrap while the device is locked (F1: no " +
                    "unlockedDeviceRequired on the wrapping key)",
                born,
                unwrapped,
            )
        } finally {
            shell("input keyevent 224") // wake
            shell("locksettings clear --old 1234")
        }
    }

    private fun shell(cmd: String): String =
        InstrumentationRegistry.getInstrumentation().uiAutomation
            .executeShellCommand(cmd).use { pfd ->
                java.io.FileInputStream(pfd.fileDescriptor).readBytes()
                    .toString(Charsets.UTF_8)
            }

    @Test
    fun wrappingIsRandomized() {
        DbKeyManager(context).getOrCreateDbKey()
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val wrapKey = ks.getKey(DbKeyManager.KEYSTORE_ALIAS, null) as SecretKey

        // Wrap the same payload twice with the actual wrapping key: Keystore
        // GCM must produce a fresh IV per operation (randomized encryption),
        // so blobs never repeat even for an identical DB key.
        val payload = ByteArray(32)
        fun wrap(): Pair<ByteArray, ByteArray> {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
            return cipher.iv to cipher.doFinal(payload)
        }
        val (iv1, ct1) = wrap()
        val (iv2, ct2) = wrap()
        assertFalse("GCM IV must differ across wraps", iv1.contentEquals(iv2))
        assertFalse("wrapped blob must differ across wraps", ct1.contentEquals(ct2))
    }

    @Test
    fun tamperedBlobFailsToUnwrap() {
        DbKeyManager(context).getOrCreateDbKey()

        val blob = File(context.filesDir, DbKeyManager.WRAP_FILE)
        val bytes = blob.readBytes()
        bytes[bytes.size - 1] = (bytes.last().toInt() xor 0x01).toByte()
        blob.writeBytes(bytes)

        try {
            DbKeyManager(context).getOrCreateDbKey()
            fail(
                "tampered blob must fail GCM authentication, not unwrap — " +
                    "and must NOT be silently regenerated (that would mask " +
                    "tampering as unexplained total data loss)",
            )
        } catch (expected: GeneralSecurityException) {
            // AEADBadTagException or a wrapper of it.
        }
    }

    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
