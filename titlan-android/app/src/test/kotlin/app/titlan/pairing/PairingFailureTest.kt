// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.tezca_core.FfiOfferExpiryDetail
import uniffi.tezca_core.TitlanException

/**
 * 5a-2 red suite: pins the four-way pairing-failure vocabulary (P5-D2,
 * ratified 2026-08-05; pair-offer v3 freeze §5 seam) end to end at the
 * Kotlin dialog mapper — class correctness, four DISTINCT user strings, the
 * frozen expired copy VERBATIM, the negative pins (signature never surfaces
 * as expired; the structural family never as crypto), and the 4b-3 unified
 * "stale or malformed" dialog pinned DEAD in app sources.
 *
 * Plain-JVM on purpose (the CI "Android — lint, unit tests" job): the
 * generated [TitlanException] subclasses are plain data carriers,
 * constructible without loading the native library.
 */
class PairingFailureTest {

    // The frozen §5 copy (V3-D2): one surface for both expiry details.
    private val frozenExpiredCopy =
        "offer expired or not yet valid — check both devices' clocks, then re-mint"

    private fun expired(detail: FfiOfferExpiryDetail) =
        TitlanException.OfferExpired(1_755_000_000UL, 3600U, 1_755_010_000UL, detail)

    @Test
    fun classificationIsFourWayCorrect() {
        assertEquals(
            "relay transport failures are NETWORK_UNREACHABLE",
            PairingFailureClass.NETWORK_UNREACHABLE,
            PairingFailure.classify(TitlanException.Network("relay unreachable")),
        )
        assertEquals(
            "OfferExpired(Expired) is EXPIRED",
            PairingFailureClass.EXPIRED,
            PairingFailure.classify(expired(FfiOfferExpiryDetail.EXPIRED)),
        )
        assertEquals(
            "OfferExpired(NotYetValid) is EXPIRED",
            PairingFailureClass.EXPIRED,
            PairingFailure.classify(expired(FfiOfferExpiryDetail.NOT_YET_VALID)),
        )
        assertEquals(
            "a consumed/lapsed pairing inbox (stale offer) is EXPIRED",
            PairingFailureClass.EXPIRED,
            PairingFailure.classify(TitlanException.PairingUnavailable()),
        )
        assertEquals(
            "structural decode failures are MALFORMED",
            PairingFailureClass.MALFORMED,
            PairingFailure.classify(TitlanException.Malformed("trailing bytes")),
        )
        assertEquals(
            "offer_sig failure is CRYPTO",
            PairingFailureClass.CRYPTO,
            PairingFailure.classify(TitlanException.OfferSignatureInvalid()),
        )
        assertEquals(
            "proof-of-scan failure is CRYPTO",
            PairingFailureClass.CRYPTO,
            PairingFailure.classify(TitlanException.ProofOfScanFailed()),
        )
        assertEquals(
            "libsignal processing failure is CRYPTO on the pairing path",
            PairingFailureClass.CRYPTO,
            PairingFailure.classify(TitlanException.Protocol("PQXDH failure")),
        )
        assertEquals(
            "core internal faults are INTERNAL",
            PairingFailureClass.INTERNAL,
            PairingFailure.classify(TitlanException.Other("storage error: disk full")),
        )
        assertEquals(
            "non-core throwables are INTERNAL",
            PairingFailureClass.INTERNAL,
            PairingFailure.classify(RuntimeException("boom")),
        )
    }

    @Test
    fun fourClassesProduceFourDistinctUserStrings() {
        val strings = listOf(
            PairingFailure.userMessage(PairingFailureClass.NETWORK_UNREACHABLE),
            PairingFailure.userMessage(PairingFailureClass.EXPIRED),
            PairingFailure.userMessage(PairingFailureClass.MALFORMED),
            PairingFailure.userMessage(PairingFailureClass.CRYPTO),
        )
        assertEquals(
            "the four classes must produce four DISTINCT user strings, got $strings",
            4,
            strings.toSet().size,
        )
    }

    @Test
    fun expiredStringIsTheFrozenCopyVerbatim() {
        assertEquals(
            "the expired surface must be the frozen §5 copy VERBATIM",
            frozenExpiredCopy,
            PairingFailure.userMessage(expired(FfiOfferExpiryDetail.EXPIRED)),
        )
        assertEquals(
            "NotYetValid shares the one frozen surface (V3-D2)",
            frozenExpiredCopy,
            PairingFailure.userMessage(expired(FfiOfferExpiryDetail.NOT_YET_VALID)),
        )
    }

    @Test
    fun signatureFailureNeverSurfacesAsExpired() {
        assertEquals(
            "signature failure is CRYPTO, never EXPIRED",
            PairingFailureClass.CRYPTO,
            PairingFailure.classify(TitlanException.OfferSignatureInvalid()),
        )
        assertNotEquals(
            "the crypto dialog must not read as the expired dialog",
            PairingFailure.userMessage(expired(FfiOfferExpiryDetail.EXPIRED)),
            PairingFailure.userMessage(TitlanException.OfferSignatureInvalid()),
        )
    }

    @Test
    fun unsupportedVersionNeverSurfacesAsCrypto() {
        // v1/v2 offer bytes cross the FFI as Malformed (the v3-only acceptor's
        // unsupported-version reject) — they must class MALFORMED, not CRYPTO.
        val cls = PairingFailure.classify(TitlanException.Malformed("unsupported version 2"))
        assertEquals(
            "unsupported-version (v1/v2 bytes) must class MALFORMED",
            PairingFailureClass.MALFORMED,
            cls,
        )
        assertNotEquals("never CRYPTO", PairingFailureClass.CRYPTO, cls)
        assertNotEquals(
            "the malformed dialog must not read as the crypto dialog",
            PairingFailure.userMessage(PairingFailureClass.CRYPTO),
            PairingFailure.userMessage(PairingFailureClass.MALFORMED),
        )
    }

    @Test
    fun legacyUnifiedCopyIsDeadInAppSources() {
        val srcMain = repoFile("titlan-android/app/src/main")
        val offenders = srcMain.walkTopDown()
            .filter { it.isFile && (it.extension == "kt" || it.extension == "xml") }
            .filter { it.readText(Charsets.UTF_8).contains("stale or malformed") }
            .map { it.relativeTo(srcMain).path }
            .toList()
        assertTrue(
            "the 4b-3 unified 'stale or malformed' copy must be dead in app " +
                "sources (the four-way vocabulary replaced it), found in: $offenders",
            offenders.isEmpty(),
        )
    }

    /** Resolves a repo path by walking up from the test working directory. */
    private fun repoFile(path: String): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, path)
            if (candidate.exists()) return candidate
            dir = dir.parentFile
        }
        error("$path not found above ${System.getProperty("user.dir")}")
    }
}
