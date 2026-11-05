// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

/**
 * One message as the chat screen renders it (5e-1, CU-D6; 1.1, L-D2). [id]
 * is the message id as lower-case hex; [body] is the decoded form — text for
 * a `chat/1` frame, or one of the two placeholders; [epochSeconds] is the
 * local clock at insert on this device's side (`sent_at` for an outgoing
 * message, `received_at` for an incoming one), Unix seconds, `null` for a
 * message stored before 1.1 — rendered without a time, never back-filled.
 * No delivery state crosses the FFI until P6 (plan of record PL-D2).
 */
data class UiMessage(
    val id: String,
    val incoming: Boolean,
    val body: DecodedBody,
    val epochSeconds: Long?,
)

/**
 * One conversation as the list renders it (1.1, L-D4): the local-only
 * [label] (`null` = unlabelled — the row shows the hex form) and the
 * last-activity time core computed, Unix seconds.
 */
data class ConversationRow(
    val key: ConversationKey,
    val label: String?,
    val lastActivityEpochSeconds: Long,
)

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

    /** Core failed to persist it (5e-2, finding F-J); the screen restores the draft. */
    data object Failed : SendOutcome
}
