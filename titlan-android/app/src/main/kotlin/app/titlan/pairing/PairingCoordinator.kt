// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

/**
 * Drives the asymmetric pairing offer flow (frozen design §3). PRODUCTION
 * HOME, stubbed in the 4b-2 RED commit.
 *
 * A3: all cryptography and framing live in tezca-core. This coordinator is the
 * UI-side orchestration — mint an offer, render it ([QrCodec]), accept a
 * scanned offer, verify proof-of-scan (in core), surface the resulting
 * conversation. The 4b-2 GREEN commit wires each step to the tezca-core FFI
 * surface (offer/proof-of-scan/rotation), which is itself extended in green.
 */
object PairingCoordinator {

    /**
     * Offerer side: mints a single-use offer (bundle + relay + pairing mailbox
     * + 256-bit pairing secret), creates the pairing mailbox, and returns the
     * offer for display. TTL 1 h; single-use (frozen design §3).
     */
    fun createOffer(): PairingOffer =
        TODO("4b-2 green: core.export_pairing_offer + create pairing mailbox")

    /**
     * Responder side: consumes scanned/linked `offerBytes` — runs PQXDH,
     * creates this side's inbox, sends the proof-of-scan `inbox-handoff`, and
     * on the offerer's verified acceptance yields the new conversation id.
     * A non-default relay in the offer is surfaced to the user before this
     * runs (frozen design §3); this method assumes that confirmation.
     */
    fun acceptScannedOffer(offerBytes: ByteArray): ByteArray =
        TODO("4b-2 green: core.begin_pairing_from_offer with proof-of-scan MAC")

    /** Cancels an outstanding offer, releasing its one-time pre-key. */
    fun cancelOffer(offer: PairingOffer): Unit =
        TODO("4b-2 green: DELETE pairing mailbox; release one-time pre-key")
}

/**
 * A minted offer: the byte-identical payload ([QrCodec] renders it two ways)
 * plus its expiry. `bytes` are exactly what the QR / link carry.
 */
class PairingOffer(val bytes: ByteArray, val expiresAtEpochMillis: Long)
