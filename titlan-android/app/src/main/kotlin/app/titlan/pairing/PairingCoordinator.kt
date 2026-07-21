// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import app.titlan.core.AppCore

/**
 * Drives the asymmetric pairing offer flow (frozen design §3). A3: all
 * cryptography and framing live in tezca-core; this coordinator is the UI-side
 * orchestration — mint an offer, render it ([QrCodec]), accept a scanned offer
 * (proof-of-scan verified in core), surface the resulting conversation. Every
 * step routes through the single process-wide core ([AppCore]).
 */
object PairingCoordinator {

    /** Offer time-to-live (frozen design §3: 1 h, single-use). */
    private const val OFFER_TTL_MS = 60L * 60L * 1000L

    /**
     * Offerer side: mints a single-use offer (bundle + relay + pairing mailbox
     * + 256-bit pairing secret), creates the pairing mailbox, and returns the
     * offer for display. TTL 1 h; single-use (frozen design §3).
     */
    fun createOffer(): PairingOffer {
        val bytes = AppCore.get().exportPairingOffer()
        // The core mints + owns the TTL/expiry semantics; the UI countdown is a
        // display convenience computed from mint time.
        return PairingOffer(bytes, nowMillis() + OFFER_TTL_MS)
    }

    /**
     * Responder side: consumes scanned/linked `offerBytes` — runs PQXDH,
     * creates this side's inbox, sends the proof-of-scan `pair-ack/2`, and on
     * the offerer's verified acceptance yields the new conversation id. A
     * non-default relay in the offer is surfaced to the user before this runs
     * (frozen design §3); this method assumes that confirmation.
     */
    fun acceptScannedOffer(offerBytes: ByteArray): ByteArray =
        AppCore.get().beginPairingFromOffer(offerBytes)

    // There is deliberately NO cancelOffer here: true cancellation (stop the
    // core pairing listener, forget the secret, DELETE the pairing mailbox on
    // the relay) needs a core FFI cancel method — new FFI surface, flagged
    // rather than added (F3, 2026-07-21; ledgered in
    // docs/acceptance-venues.md). Until it lands, a dismissed offer remains
    // single-use and lapses at its 1 h TTL, and the UI says so honestly
    // instead of claiming a cancellation that does not happen.

    private fun nowMillis(): Long = System.currentTimeMillis()
}

/**
 * A minted offer: the byte-identical payload ([QrCodec] renders it two ways)
 * plus its expiry. `bytes` are exactly what the QR / link carry.
 */
class PairingOffer(val bytes: ByteArray, val expiresAtEpochMillis: Long)
