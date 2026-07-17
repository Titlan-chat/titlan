// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.core

import uniffi.tezca_core.FfiClient

/**
 * Thin app-facing facade over the UniFFI-generated tezca-core bindings (A3:
 * Kotlin is UI-only; everything behind this interface is Rust). The 4b-1
 * surface is deliberately minimal — open + identity; sync and pairing arrive
 * in 4b-2. All uniffi imports stay inside this file so the rest of the app
 * never touches generated types.
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
        FfiCoreClient(FfiClient.open(dbPath, dbKey, relayUrl))

    /** Fresh 32-byte DB key from the OS CSPRNG in Rust (decision 5a). */
    fun generateDbKey(): ByteArray = uniffi.tezca_core.generateDbKey()
}

private class FfiCoreClient(private val ffi: FfiClient) : CoreClient {
    override fun initializeIdentity() = ffi.initializeIdentity()
    override fun isInitialized(): Boolean = ffi.isInitialized()
    override fun close() = ffi.close()
}
