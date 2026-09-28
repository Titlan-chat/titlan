// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import app.titlan.R
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
 * dialog copy (a string resource since 5e-1) — the four-way vocabulary that replaced the 4b-3 unified
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
     * The class's string resource (5e-1, CU-D9: every user-visible string is
     * a resource; the plain-JVM CopyConventionTest pins the frozen EXPIRED
     * wording verbatim in strings.xml and the four-way DISTINCTNESS here).
     * The EXPIRED resource is the pair-offer v3 freeze §5 wording VERBATIM
     * (V3-D2: one surface for both expiry details).
     */
    fun userMessageRes(cls: PairingFailureClass): Int = when (cls) {
        PairingFailureClass.NETWORK_UNREACHABLE -> R.string.pairing_failure_network
        PairingFailureClass.EXPIRED -> R.string.pairing_failure_expired
        PairingFailureClass.MALFORMED -> R.string.pairing_failure_malformed
        PairingFailureClass.CRYPTO -> R.string.pairing_failure_crypto
        PairingFailureClass.INTERNAL -> R.string.pairing_failure_internal
    }

    /** The resource for a caught pairing-flow failure. */
    fun userMessageRes(t: Throwable): Int = userMessageRes(classify(t))
}
