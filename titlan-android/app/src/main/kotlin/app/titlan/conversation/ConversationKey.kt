// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

/**
 * A conversation id as lower-case hex (5e-1, CU-D3). The UI keys everything
 * by this value type, never by `ByteArray`: a `data class` over a byte array
 * compares by reference, which is how the 4b-2 `OfferLifecycle.Paired(ByteArray)`
 * shape could never be looked up. The id is a local random value
 * (tezca-core `storage::random_id`), not a secret.
 */
@JvmInline
value class ConversationKey(val hex: String) {

    /** The 16 raw bytes core expects on every FFI call. */
    val bytes: ByteArray
        get() = ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }

    /** The first 8 hex characters — the only label a conversation has (CU-D7). */
    val shortHex: String
        get() = hex.take(8)

    companion object {
        fun of(bytes: ByteArray): ConversationKey = ConversationKey(bytes.toHexLower())
    }
}

/** Lower-case hex of a byte array (ids only — never key material or text). */
internal fun ByteArray.toHexLower(): String =
    joinToString("") { "%02x".format(it.toInt() and 0xFF) }
