// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.core

import android.util.Log
import app.titlan.BuildConfig
import app.titlan.sync.ConnectionState
import app.titlan.sync.SyncEvents
import uniffi.tezca_core.FfiClient
import uniffi.tezca_core.FfiConnectionObserver
import uniffi.tezca_core.FfiConnectionState
import uniffi.tezca_core.FfiMessage
import uniffi.tezca_core.FfiMessageReceiver

/**
 * Thin app-facing facade over the UniFFI-generated tezca-core bindings (A3:
 * Kotlin is UI-only; everything behind this interface is Rust). All `uniffi`
 * imports stay inside this file so the rest of the app never touches generated
 * types — the sync/pairing surface added in 4b-2 GREEN is adapted to app types
 * (`SyncEvents`, `ConnectionState`) right here.
 */
interface CoreClient : AutoCloseable {
    /** Generates and persists the device identity if absent. */
    fun initializeIdentity()

    /** True once an identity exists in the encrypted store. */
    fun isInitialized(): Boolean

    /** Offerer side: mints a v2 pairing offer (bundle + relay + secret). */
    fun exportPairingOffer(): ByteArray

    /** Responder side: consumes a scanned offer; returns the conversation id. */
    fun beginPairingFromOffer(offerBytes: ByteArray): ByteArray

    /** Reads a scanned offer's relay without establishing a session (§3). */
    fun peekOfferRelay(offerBytes: ByteArray): String

    /** All known conversation ids (16 bytes each). */
    fun listConversations(): List<ByteArray>

    /** Overrides the relay for one conversation (INV-5). */
    fun setConversationRelay(conversationId: ByteArray, relayUrl: String)

    /** Queues a chat message; the sync engine delivers + retries. */
    fun sendChat(conversationId: ByteArray, text: String)

    /**
     * Starts receive-sync, fanning core callbacks into [events]. Idempotent in
     * core (rehydrates from SQLCipher). Called after the service is foreground.
     */
    fun startSync(events: SyncEvents)

    /** Stops all sync tasks in core. */
    fun stopSync()
}

object CoreClientFactory {
    /**
     * Opens the encrypted store at [dbPath] with the raw 32-byte [dbKey]
     * (from [app.titlan.crypto.DbKeyManager]). [relayUrl] is stored config
     * only at open time — no connection is made until sync starts.
     */
    fun open(dbPath: String, dbKey: ByteArray, relayUrl: String): CoreClient =
        FfiCoreClient(FfiClient.open(dbPath, dbKey, relayUrl))

    /** Fresh 32-byte DB key from the OS CSPRNG in Rust (decision 5a). */
    fun generateDbKey(): ByteArray = uniffi.tezca_core.generateDbKey()
}

private class FfiCoreClient(private val ffi: FfiClient) : CoreClient {
    override fun initializeIdentity() = ffi.initializeIdentity()
    override fun isInitialized(): Boolean = ffi.isInitialized()
    override fun exportPairingOffer(): ByteArray = ffi.exportPairingOffer()
    override fun beginPairingFromOffer(offerBytes: ByteArray): ByteArray =
        ffi.beginPairingFromOffer(offerBytes)

    override fun peekOfferRelay(offerBytes: ByteArray): String = ffi.peekOfferRelay(offerBytes)

    override fun listConversations(): List<ByteArray> = ffi.listConversations()
    override fun setConversationRelay(conversationId: ByteArray, relayUrl: String) =
        ffi.setConversationRelay(conversationId, relayUrl)

    override fun sendChat(conversationId: ByteArray, text: String) =
        ffi.sendChat(conversationId, text)

    override fun startSync(events: SyncEvents) =
        ffi.startSync(ObserverAdapter(events), ReceiverAdapter(events))

    override fun stopSync() = ffi.stopSync()
    override fun close() = ffi.close()
}

/**
 * Debug delivery sentinel (device checklist f, maintainer-ratified F1): ONE
 * fixed logcat line marking the moment an inbound chat completes the
 * ack-after-persist contract (frozen §1: core invokes the receiver only after
 * decrypt AND durable persist), giving the doze-latency measurement its t1.
 * Both values are frozen pure literals — never interpolate identifiers,
 * counts, or any state into this line (§9d/INV-1;
 * scripts/check-invariants.sh §6 pins the shape, and
 * scripts/device-doze-latency.sh waits on these exact strings).
 */
private const val DELIVERY_SENTINEL_TAG = "TitlanDelivery"
private const val DELIVERY_SENTINEL_TEXT = "chat delivery persisted"

/** Fans core message delivery into the app's [SyncEvents]. */
private class ReceiverAdapter(private val events: SyncEvents) : FfiMessageReceiver {
    override fun onMessage(conversationId: ByteArray, message: FfiMessage) {
        // Emitted before the event fans out so an observer failure can never
        // suppress the marker; debug builds only.
        if (BuildConfig.DEBUG) Log.i(DELIVERY_SENTINEL_TAG, DELIVERY_SENTINEL_TEXT)
        // Body is read from the store by id (frozen §1); the event carries ids
        // only, so a leaked event object never carries plaintext.
        events.onMessageArrived(conversationId, message.id)
    }
}

/** Fans core state/failure callbacks into the app's [SyncEvents]. */
private class ObserverAdapter(private val events: SyncEvents) : FfiConnectionObserver {
    override fun onState(conversationId: ByteArray, state: FfiConnectionState) {
        // Core does not surface a per-socket endpoint string yet (INV-5's N
        // states are per-conversation here); pass "" until it does.
        val mapped = when (state) {
            is FfiConnectionState.Connecting -> ConnectionState.CONNECTING
            is FfiConnectionState.Online -> ConnectionState.ONLINE
            is FfiConnectionState.Offline -> ConnectionState.OFFLINE
            is FfiConnectionState.Backoff -> ConnectionState.BACKOFF
            is FfiConnectionState.Recovering -> ConnectionState.RECOVERING
            // Exhaustion is delivered via onConversationNeedsRepair, not as a
            // state (the app ConnectionState enum deliberately omits it).
            is FfiConnectionState.RePairRequired -> return
        }
        events.onConnectionState(conversationId, "", mapped)
    }

    override fun onConversationNeedsRepair(conversationId: ByteArray) =
        events.onConversationNeedsRepair(conversationId)

    override fun onPermanentSendFailure(conversationId: ByteArray, messageId: ByteArray) =
        events.onPermanentSendFailure(conversationId, messageId)

    override fun onStorageError(detail: String) = events.onStorageError(detail)
}
