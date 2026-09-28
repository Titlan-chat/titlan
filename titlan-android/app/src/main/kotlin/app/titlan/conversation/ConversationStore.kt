// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import app.titlan.core.AppCore
import app.titlan.sync.ConnectionState
import app.titlan.sync.SyncEvents
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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
 * A3: no protocol logic here — every read and write is a core call.
 */
object ConversationStore : SyncEvents {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _conversations = MutableStateFlow<List<ConversationKey>>(emptyList())

    /** Most-recent-first, as core lists them. */
    val conversations: StateFlow<List<ConversationKey>> = _conversations.asStateFlow()

    private val _connection = MutableStateFlow<Map<ConversationKey, ConnectionState>>(emptyMap())

    /** Last reported per-conversation connection state; absent until the first event. */
    val connection: StateFlow<Map<ConversationKey, ConnectionState>> = _connection.asStateFlow()

    private val _needsRepair = MutableStateFlow<Set<ConversationKey>>(emptySet())

    /** Conversations whose recovery is exhausted (re-pair is the last resort). */
    val needsRepair: StateFlow<Set<ConversationKey>> = _needsRepair.asStateFlow()

    private val _notDelivered = MutableStateFlow<Set<String>>(emptySet())

    /** Message ids (hex) the relay refused for good — process lifetime only. */
    val notDelivered: StateFlow<Set<String>> = _notDelivered.asStateFlow()

    private val _storageError = MutableStateFlow(false)

    /** True once core reported a storage error; the detail is never kept. */
    val storageError: StateFlow<Boolean> = _storageError.asStateFlow()

    /** The [SyncEvents] to hand to SyncController.start — this object. */
    val events: SyncEvents
        get() = this

    private val messageFlows = ConcurrentHashMap<ConversationKey, MutableStateFlow<List<UiMessage>>>()

    private fun flowFor(key: ConversationKey): MutableStateFlow<List<UiMessage>> =
        messageFlows.getOrPut(key) { MutableStateFlow(emptyList()) }

    /** Messages of one conversation in store order; empty until first refreshed. */
    fun messages(key: ConversationKey): StateFlow<List<UiMessage>> = flowFor(key).asStateFlow()

    /** Re-reads the conversation list from core (IO) and publishes it. */
    suspend fun refreshConversations(): List<ConversationKey> = withContext(Dispatchers.IO) {
        val keys = AppCore.get().listConversations().map { ConversationKey.of(it) }
        _conversations.value = keys
        keys
    }

    /** Re-reads one conversation's messages from core (IO) and publishes them. */
    suspend fun refreshMessages(key: ConversationKey): List<UiMessage> = withContext(Dispatchers.IO) {
        val list = AppCore.get().messages(key.bytes).map { m ->
            UiMessage(
                id = m.id.toHexLower(),
                incoming = m.incoming,
                body = ChatBody.decode(m.payloadType, m.typeVersion, m.body),
            )
        }
        flowFor(key).value = list
        list
    }

    /** Refreshes the list and, when given, one conversation (Activity ON_START). */
    suspend fun refreshAll(open: ConversationKey?) {
        refreshConversations()
        if (open != null) refreshMessages(open)
    }

    /**
     * CU-D6 send: [ChatBody.admit] first; on [SendCheck.Ok] hands the trimmed
     * text to core's sendChat on IO (persisted pending; delivery and retry are
     * the sync engine's) and re-reads the messages.
     */
    suspend fun send(key: ConversationKey, text: String): SendOutcome {
        return when (val check = ChatBody.admit(text)) {
            is SendCheck.Ok -> {
                withContext(Dispatchers.IO) { AppCore.get().sendChat(key.bytes, check.text) }
                refreshMessages(key)
                SendOutcome.Queued
            }
            else -> SendOutcome.Rejected(check)
        }
    }

    /** CU-D3 refresh rule: an event for a key not yet listed re-reads the list. */
    private fun ensureListed(key: ConversationKey) {
        if (key !in _conversations.value) scope.launch { refreshConversations() }
    }

    override fun onMessageArrived(conversationId: ByteArray, messageId: ByteArray) {
        val key = ConversationKey.of(conversationId)
        ensureListed(key)
        scope.launch { refreshMessages(key) }
    }

    override fun onConnectionState(
        conversationId: ByteArray,
        relayEndpoint: String,
        state: ConnectionState,
    ) {
        val key = ConversationKey.of(conversationId)
        _connection.update { it + (key to state) }
        ensureListed(key)
    }

    override fun onConversationNeedsRepair(conversationId: ByteArray) {
        val key = ConversationKey.of(conversationId)
        _needsRepair.update { it + key }
        ensureListed(key)
    }

    override fun onPermanentSendFailure(conversationId: ByteArray, messageId: ByteArray) {
        _notDelivered.update { it + messageId.toHexLower() }
        ensureListed(ConversationKey.of(conversationId))
    }

    override fun onStorageError(detail: String) {
        // The detail may name a path or a query; it is neither shown nor logged (INV-1).
        _storageError.value = true
    }
}
