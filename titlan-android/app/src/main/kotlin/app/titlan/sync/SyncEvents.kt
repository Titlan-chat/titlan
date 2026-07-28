// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

/**
 * The sync engine's callback vocabulary (frozen design §1). The UI implements
 * this to receive delivery and state; the minimum set is fixed so the UI can
 * always distinguish "reconnecting, wait" from "unrecoverable, act".
 *
 * Wired to tezca-core's `FfiMessageReceiver` / `FfiConnectionObserver` in the
 * 4b-2 GREEN commit — this interface is the app-side shape those callbacks
 * fan into.
 */
interface SyncEvents {

    /**
     * A message was decrypted AND durably persisted (frozen design §1: core
     * acks the relay only after persist, never on delivery to Kotlin — a
     * process death between persist and display must not lose a message). The
     * body is read from the store by id; it is not passed through the event.
     */
    fun onMessageArrived(conversationId: ByteArray, messageId: ByteArray)

    /**
     * Connection state for ONE relay endpoint (INV-5: N sockets, N states).
     * The UI aggregates across endpoints for display; a single scalar is
     * rejected by the design.
     */
    fun onConnectionState(conversationId: ByteArray, relayEndpoint: String, state: ConnectionState)

    /**
     * §10.7 recovery is exhausted (relative generation offset ≥ W, or probe
     * cycles spent): routing cannot be re-established in-band. The UI surfaces
     * re-pair as the last resort. This is the "unrecoverable, act" signal.
     */
    fun onConversationNeedsRepair(conversationId: ByteArray)

    /** A queued send has permanently failed (not a transient retry). */
    fun onPermanentSendFailure(conversationId: ByteArray, messageId: ByteArray)

    /** The encrypted store could not be read/written (e.g. locked CE storage). */
    fun onStorageError(detail: String)
}

/**
 * Per-endpoint connection state (frozen design §1). "reconnecting, wait"
 * states are [CONNECTING]/[BACKOFF]/[RECOVERING]; [OFFLINE] with no path is
 * the actionable one. Recovery exhaustion is a separate event
 * ([SyncEvents.onConversationNeedsRepair]), not a state here.
 */
enum class ConnectionState {
    CONNECTING,
    ONLINE,
    OFFLINE,
    BACKOFF,
    RECOVERING,
}
