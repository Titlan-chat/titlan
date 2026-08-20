// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import uniffi.tezca_core.TitlanException

/**
 * The pairing-failure vocabulary (P5-D2, ratified 2026-08-05; pair-offer v3
 * freeze §5 seam): the four ratified user classes — network-unreachable /
 * expired / malformed / crypto — plus INTERNAL for device-local faults that
 * are none of the peer's doing (storage failures, unexpected errors).
 */
enum class PairingFailureClass {
    NETWORK_UNREACHABLE,
    EXPIRED,
    MALFORMED,
    CRYPTO,
    INTERNAL,
}

/**
 * Maps a pairing-flow failure to its [PairingFailureClass] and user-facing
 * dialog copy — the four-way vocabulary that replaced the 4b-3 unified
 * dialog. A3: classification rides the typed [TitlanException] variants the
 * core surfaces — never string inspection.
 */
object PairingFailure {

    fun classify(t: Throwable): PairingFailureClass = when (t) {
        is TitlanException.Network -> PairingFailureClass.NETWORK_UNREACHABLE
        // A consumed/lapsed pairing inbox is a stale offer: same user story
        // and remedy as an expired one (re-mint).
        is TitlanException.OfferExpired,
        is TitlanException.PairingUnavailable,
        -> PairingFailureClass.EXPIRED
        is TitlanException.Malformed -> PairingFailureClass.MALFORMED
        // Signature, proof-of-scan, and libsignal processing failures
        // (key decode / PQXDH) are all cryptographic rejections here.
        is TitlanException.OfferSignatureInvalid,
        is TitlanException.ProofOfScanFailed,
        is TitlanException.Protocol,
        -> PairingFailureClass.CRYPTO
        else -> PairingFailureClass.INTERNAL
    }

    /**
     * User copy per class. The EXPIRED copy is the frozen §5 wording
     * VERBATIM (V3-D2: one surface for both expiry details); the other
     * strings are drafted by 5a-2 and enumerated in its report for
     * maintainer copy-review — their DISTINCTNESS and class-correctness are
     * what the tests freeze, not their wording.
     */
    fun userMessage(cls: PairingFailureClass): String = when (cls) {
        PairingFailureClass.NETWORK_UNREACHABLE ->
            "Can't reach the relay — check this device's connection and try again."
        PairingFailureClass.EXPIRED ->
            "offer expired or not yet valid — check both devices' clocks, then re-mint"
        PairingFailureClass.MALFORMED ->
            "That code isn't a valid pairing offer — re-scan it, or mint a fresh one on the other device."
        PairingFailureClass.CRYPTO ->
            "Pairing failed a cryptographic check — stop and mint a fresh offer on the other device."
        PairingFailureClass.INTERNAL ->
            "Pairing failed from an internal error on this device — try again."
    }

    /** User copy for a caught pairing-flow failure. */
    fun userMessage(t: Throwable): String = userMessage(classify(t))
}
