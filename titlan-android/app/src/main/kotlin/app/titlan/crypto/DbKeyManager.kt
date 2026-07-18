// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import app.titlan.core.CoreClientFactory
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Owns the SQLCipher DB key's on-device lifecycle (INV-1's at-rest moment,
 * deferred by Phase 2 to the Android side):
 *
 * - Birth: 32 bytes from the OS CSPRNG in Rust (`tezca-core`
 *   `generate_db_key`, maintainer decision 5a) — INV-6: no custom crypto.
 * - At rest: only ever AES-GCM-wrapped under a non-exportable Android
 *   Keystore key (StrongBox where available, TEE fallback) in [WRAP_FILE]
 *   as `IV ‖ ciphertext`.
 * - Lifecycle (maintainer-resolved F1): the wrapping key requires no user
 *   authentication and is NOT invalidated by lock-screen or biometric
 *   changes; not unlock-bound (the sync service must decrypt while the
 *   device is locked); uninstall destroys key and blob together
 *   (recovery = §10.7 re-pair).
 */
class DbKeyManager(private val context: Context) {

    /**
     * Returns the raw 32-byte DB key, creating and wrapping it on first
     * call, unwrapping it thereafter. The caller passes it straight to
     * the core client and zeroizes its copy.
     *
     * A blob that fails GCM authentication (tampering, corruption) throws
     * [GeneralSecurityException] — it is NEVER silently regenerated, which
     * would mask tampering as unexplained total data loss. The caller
     * surfaces it as a fatal, diagnosable error.
     */
    fun getOrCreateDbKey(): ByteArray {
        val blobFile = File(context.filesDir, WRAP_FILE)
        val wrapKey = getOrCreateWrapKey()

        if (blobFile.exists()) {
            val blob = blobFile.readBytes()
            if (blob.size <= GCM_IV_BYTES) {
                throw GeneralSecurityException(
                    "wrapped DB key blob is truncated (${blob.size} bytes) — not regenerating",
                )
            }
            val cipher = Cipher.getInstance(CIPHER_TRANSFORM)
            cipher.init(
                Cipher.DECRYPT_MODE,
                wrapKey,
                GCMParameterSpec(GCM_TAG_BITS, blob, 0, GCM_IV_BYTES),
            )
            // AEADBadTagException (a GeneralSecurityException) propagates on
            // tamper — by design, never caught to regenerate.
            return cipher.doFinal(blob, GCM_IV_BYTES, blob.size - GCM_IV_BYTES)
        }

        val key = CoreClientFactory.generateDbKey()
        val cipher = Cipher.getInstance(CIPHER_TRANSFORM)
        // Keystore keys keep randomized encryption REQUIRED (default): a
        // fresh IV is generated per init, so identical keys wrap to
        // distinct blobs.
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
        val wrapped = cipher.iv + cipher.doFinal(key)
        val tmp = File(context.filesDir, "$WRAP_FILE.tmp")
        tmp.writeBytes(wrapped)
        if (!tmp.renameTo(blobFile)) {
            tmp.delete()
            throw GeneralSecurityException("could not persist wrapped DB key blob")
        }
        return key
    }

    private fun getOrCreateWrapKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )

        fun spec(strongBox: Boolean): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // F1 (maintainer-resolved): no user-auth binding — survives
                // lock-screen and biometric changes, usable while locked.
                .setUserAuthenticationRequired(false)
                .apply { if (strongBox) setIsStrongBoxBacked(true) }
                .build()

        return try {
            generator.init(spec(strongBox = true))
            generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            generator.init(spec(strongBox = false))
            generator.generateKey()
        }
    }

    companion object {
        /** Wrapped-blob file name under [Context.getFilesDir]. */
        const val WRAP_FILE: String = "dbkey.wrapped"

        /** Android Keystore alias of the AES-GCM wrapping key. */
        const val KEYSTORE_ALIAS: String = "titlan-dbkey-wrap"

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val CIPHER_TRANSFORM = "AES/GCM/NoPadding"
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BITS = 128
    }
}
