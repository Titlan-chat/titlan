// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

/**
 * One message as the chat screen renders it (5e-1, CU-D6). [id] is the
 * message id as lower-case hex; [body] is the decoded form — text for a
 * `chat/1` frame, or one of the two placeholders. No timestamp and no
 * delivery state cross the FFI in this version (freeze CU-D0/CU-D6).
 */
data class UiMessage(val id: String, val incoming: Boolean, val body: DecodedBody)

/** The chat screen's view of a stored message body (CU-D6 decoding rule). */
sealed interface DecodedBody {
    /** A `chat/1` frame whose payload decoded as strict UTF-8. */
    data class Text(val text: String) : DecodedBody

    /** A `chat/1` frame whose payload is not valid UTF-8; rendered as a fixed placeholder. */
    data object Undecodable : DecodedBody

    /** Any other payload type or type version; the body is never decoded. */
    data object Unsupported : DecodedBody
}

/** Composer admission (CU-D6 send rule). */
sealed interface SendCheck {
    /** Trimmed text within the cap. */
    data class Ok(val text: String) : SendCheck

    data object Blank : SendCheck

    /** UTF-8 length exceeds [ChatLimits.MAX_CHAT_UTF8_BYTES]. */
    data class TooLong(val utf8Bytes: Int) : SendCheck
}

/** Result of [ConversationStore.send]. */
sealed interface SendOutcome {
    /** Persisted as pending in core; delivery and retry belong to the sync engine. */
    data object Queued : SendOutcome

    data class Rejected(val why: SendCheck) : SendOutcome
}
