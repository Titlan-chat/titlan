// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

/**
 * The offerer completion signal (5e-1, CU-D4): while an offer is Active the
 * store is polled every [DEFAULT_POLL_MILLIS] on IO and the first
 * conversation key not in the pre-mint set is the paired conversation. The
 * signal means "proof-of-scan verified and the conversation created"
 * (tezca-core relay_client/mod.rs:326-339), one round trip before the handoff
 * deposit. Bounded by the offer's own validity window.
 */
object OfferWatcher {
    const val DEFAULT_POLL_MILLIS: Long = 2_000L

    /**
     * Suspends until a key outside [before] appears or [deadlineEpochMillis]
     * passes; returns the key, or null at the deadline.
     */
    suspend fun awaitNewConversation(
        before: Set<ConversationKey>,
        deadlineEpochMillis: Long,
        pollMillis: Long = DEFAULT_POLL_MILLIS,
    ): ConversationKey? = TODO()
}
