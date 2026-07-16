// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.core

/**
 * Thin app-facing facade over the UniFFI-generated tezca-core bindings (A3:
 * Kotlin is UI-only; everything behind this interface is Rust). The 4b-1
 * surface is deliberately minimal — open + identity; sync and pairing arrive
 * in 4b-2.
 *
 * Interface only per the 4b-1 red commit; the green commit implements it
 * over the generated `uniffi.tezca_core` bindings and the cargo-ndk build.
 */
interface CoreClient : AutoCloseable {
    /** Generates and persists the device identity if absent. */
    fun initializeIdentity()

    /** True once an identity exists in the encrypted store. */
    fun isInitialized(): Boolean
}

object CoreClientFactory {
    /**
     * Opens the encrypted store at [dbPath] with the raw 32-byte [dbKey]
     * (from [app.titlan.crypto.DbKeyManager]). [relayUrl] is stored config
     * only at open time — no connection is made until sync starts (4b-2).
     */
    fun open(dbPath: String, dbKey: ByteArray, relayUrl: String): CoreClient =
        TODO("4b-1 green: UniFFI bindings + cargo-ndk wiring")
}
