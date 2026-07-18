// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.core.CoreClientFactory
import app.titlan.crypto.DbKeyManager
import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-1 acceptance (the plaintext-grep check, INV-1): after a real
 * key-wrap + core open + identity generation, nothing plaintext-sensitive
 * exists anywhere in app-accessible storage. Red until the 4b-1 green commit
 * wires DbKeyManager and the UniFFI bindings.
 */
@RunWith(AndroidJUnit4::class)
class Inv1AtRestTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /** Plaintext SQLite magic; a SQLCipher DB starts with its random salt. */
    private val sqliteMagic = "SQLite format 3\u0000".toByteArray(Charsets.ISO_8859_1)

    @Test
    fun noPlaintextAtRestAfterIdentityCreation() {
        val key = DbKeyManager(context).getOrCreateDbKey()
        val dbFile = File(context.filesDir, "titlan.db")

        // relay.invalid: config-only placeholder (RFC 2606); open() makes no
        // connection in 4b-1, and the real default stays in core (INV-5).
        CoreClientFactory.open(dbFile.path, key, "wss://relay.invalid").use { client ->
            client.initializeIdentity()
            assertTrue(client.isInitialized())
        }

        assertTrue("encrypted DB must exist", dbFile.exists())
        val header = dbFile.readBytes().copyOf(sqliteMagic.size)
        assertFalse(
            "DB file must not carry the plaintext SQLite magic (INV-1)",
            header.contentEquals(sqliteMagic),
        )

        val keyHexLower = key.joinToString("") { "%02x".format(it) }
        val keyBase64 = Base64.encodeToString(key, Base64.NO_WRAP)
        for (root in listOfNotNull(context.filesDir, context.cacheDir)) {
            root.walkTopDown().filter { it.isFile }.forEach { f ->
                val bytes = f.readBytes()
                assertFalse(
                    "raw DB key bytes found at rest in ${f.path} (INV-1)",
                    containsSubsequence(bytes, key),
                )
                val asLatin1 = String(bytes, Charsets.ISO_8859_1)
                assertFalse(
                    "hex-encoded DB key found at rest in ${f.path} (INV-1)",
                    asLatin1.contains(keyHexLower, ignoreCase = true),
                )
                assertFalse(
                    "Base64-encoded DB key found at rest in ${f.path} (INV-1)",
                    asLatin1.contains(keyBase64),
                )
            }
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
