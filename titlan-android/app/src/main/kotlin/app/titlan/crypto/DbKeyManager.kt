// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.crypto

import android.content.Context

/**
 * Owns the SQLCipher DB key's on-device lifecycle (INV-1's at-rest moment,
 * deferred by Phase 2 to the Android side):
 *
 * - Birth: 32 bytes from the platform CSPRNG on first launch (INV-6: the OS
 *   CSPRNG, no custom crypto).
 * - At rest: only ever GCM-wrapped under a non-exportable Android Keystore
 *   key (StrongBox where available, TEE fallback) in [WRAP_FILE].
 * - Lifecycle (maintainer-resolved F1): the wrapping key requires no user
 *   authentication and is NOT invalidated by lock-screen or biometric
 *   changes; uninstall destroys key and blob together (recovery = §10.7
 *   re-pair).
 *
 * Interface-level stub per the 4b-1 red commit; implementation lands in the
 * green commit.
 */
class DbKeyManager(private val context: Context) {

    /**
     * Returns the raw 32-byte DB key, creating and wrapping it on first
     * call, unwrapping it thereafter. The caller passes it straight to
     * `FfiClient.open` and zeroizes its copy.
     *
     * A blob that fails GCM authentication (tampering, corruption) throws
     * [java.security.GeneralSecurityException] — it is NEVER silently
     * regenerated, which would mask tampering as unexplained total data
     * loss. The caller surfaces it as a fatal, diagnosable error.
     */
    fun getOrCreateDbKey(): ByteArray = TODO("4b-1 green: Keystore wrap/unwrap")

    companion object {
        /** Wrapped-blob file name under [Context.getFilesDir]. */
        const val WRAP_FILE: String = "dbkey.wrapped"

        /** Android Keystore alias of the AES-GCM wrapping key. */
        const val KEYSTORE_ALIAS: String = "titlan-dbkey-wrap"
    }
}
