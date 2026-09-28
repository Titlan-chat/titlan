// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import app.titlan.sync.ConnectionState
import app.titlan.sync.SyncEvents
import kotlinx.coroutines.flow.StateFlow

/**
 * The one UI sink and the only source Compose reads (5e-1, CU-D3). This
 * object IS the app's [SyncEvents] implementation.
 *
 * Callback rule (freeze CU-D3, tezca-core relay_client/mod.rs:124-128 and
 * :497-499): core holds its callback mutex while a Kotlin callback runs, so
 * every [SyncEvents] method here returns immediately after updating in-memory
 * state or posting work to an IO dispatcher; no method calls core on the
 * callback thread, and startSync/stopSync are never invoked from a callback.
 *
 * Events carry ids only (frozen 4b-2 §1); bodies are re-read from the store.
 */
object ConversationStore : SyncEvents {

    /** Most-recent-first, as core lists them. */
    val conversations: StateFlow<List<ConversationKey>>
        get() = TODO()

    /** Last reported per-conversation connection state; absent until the first event. */
    val connection: StateFlow<Map<ConversationKey, ConnectionState>>
        get() = TODO()

    /** Conversations whose recovery is exhausted (re-pair is the last resort). */
    val needsRepair: StateFlow<Set<ConversationKey>>
        get() = TODO()

    /** Message ids (hex) the relay refused for good — process lifetime only. */
    val notDelivered: StateFlow<Set<String>>
        get() = TODO()

    /** True once core reported a storage error; the detail is never kept. */
    val storageError: StateFlow<Boolean>
        get() = TODO()

    /** The [SyncEvents] to hand to SyncController.start — this object. */
    val events: SyncEvents
        get() = this

    /** Messages of one conversation in store order; empty until first refreshed. */
    fun messages(key: ConversationKey): StateFlow<List<UiMessage>> = TODO()

    /** Re-reads the conversation list from core (IO) and publishes it. */
    suspend fun refreshConversations(): List<ConversationKey> = TODO()

    /** Re-reads one conversation's messages from core (IO) and publishes them. */
    suspend fun refreshMessages(key: ConversationKey): List<UiMessage> = TODO()

    /** Refreshes the list and, when given, one conversation (Activity ON_START). */
    suspend fun refreshAll(open: ConversationKey?): Unit = TODO()

    /**
     * CU-D6 send: [ChatBody.admit] first; on [SendCheck.Ok] hands the trimmed
     * text to core's sendChat on IO and re-reads the messages.
     */
    suspend fun send(key: ConversationKey, text: String): SendOutcome = TODO()

    override fun onMessageArrived(conversationId: ByteArray, messageId: ByteArray): Unit = TODO()

    override fun onConnectionState(
        conversationId: ByteArray,
        relayEndpoint: String,
        state: ConnectionState,
    ): Unit = TODO()

    override fun onConversationNeedsRepair(conversationId: ByteArray): Unit = TODO()

    override fun onPermanentSendFailure(conversationId: ByteArray, messageId: ByteArray): Unit = TODO()

    override fun onStorageError(detail: String): Unit = TODO()
}
