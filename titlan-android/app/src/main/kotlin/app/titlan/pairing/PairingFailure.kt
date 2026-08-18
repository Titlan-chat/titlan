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
 * dialog copy. A3: classification rides the typed [TitlanException] variants
 * the core surfaces — never string inspection.
 */
object PairingFailure {

    /**
     * RED STUB (5a-2 valid-red compile surface): legacy behavior — no
     * classification exists; everything is INTERNAL. Green builds the
     * four-way mapping.
     */
    fun classify(t: Throwable): PairingFailureClass = PairingFailureClass.INTERNAL

    /** User copy for a failure class. RED STUB: the unified 4b-3 dialog. */
    fun userMessage(cls: PairingFailureClass): String =
        "Pairing failed — the offer may be stale or malformed. Try a fresh one."

    /** User copy for a caught pairing-flow failure. */
    fun userMessage(t: Throwable): String = userMessage(classify(t))
}
