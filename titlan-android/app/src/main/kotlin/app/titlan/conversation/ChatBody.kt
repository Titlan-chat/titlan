// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

/**
 * Body decoding and composer admission (5e-1, CU-D6). Pure functions; no
 * Android types, so the plain-JVM suite pins them.
 */
object ChatBody {
    /** `PayloadType::Chat` in the envelope registry (proto/envelope.md). */
    const val CHAT_PAYLOAD_TYPE: Int = 0x01

    /** The one chat version this client renders. */
    const val CHAT_TYPE_VERSION: Int = 1

    /**
     * CU-D6 decoding rule: `chat/1` → strict UTF-8 text, malformed UTF-8 →
     * [DecodedBody.Undecodable]; any other type or version →
     * [DecodedBody.Unsupported] with the body never decoded.
     */
    fun decode(payloadType: Int, typeVersion: Int, body: ByteArray): DecodedBody = TODO()

    /** UTF-8 byte length of [text]. */
    fun utf8Length(text: String): Int = TODO()

    /**
     * CU-D6 send rule: trim; blank → [SendCheck.Blank]; UTF-8 length over
     * [ChatLimits.MAX_CHAT_UTF8_BYTES] → [SendCheck.TooLong]; else
     * [SendCheck.Ok] with the trimmed text.
     */
    fun admit(text: String): SendCheck = TODO()
}
