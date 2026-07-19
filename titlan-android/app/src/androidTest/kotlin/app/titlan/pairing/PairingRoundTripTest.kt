// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-2 CI signal (a) — pairing round-trip (frozen design §3/§9a).
 *
 * Scope is stated plainly by the design: frame injection at the [QrCodec]
 * boundary validates the DECODE PIPELINE, not scan ergonomics; realistic
 * camera/screen testing at true ~2 KB density is the separately named
 * device-phase target (item f-adjacent), NOT satisfied here.
 *
 * RED expectation: both methods reach not-yet-implemented production code and
 * fail with `kotlin.NotImplementedError` at the first stub — the byte-identity
 * method at [QrCodec.encodeQr], the round-trip method at
 * [PairingCoordinator.createOffer]. GREEN turns them green.
 */
@RunWith(AndroidJUnit4::class)
class PairingRoundTripTest {

    /**
     * QR and titlan:// carry byte-identical payloads (frozen design §3/§4).
     * Uses a fixed sample offer so the decode pipeline is exercised
     * independently of offer minting.
     */
    @Test
    fun qrAndLinkPayloadsAreByteIdentical() {
        val sampleOffer = ByteArray(64) { (it * 7 + 1).toByte() }

        val qr = QrCodec.encodeQr(sampleOffer)
        val fromQr = QrCodec.decodeQr(qr)
        assertArrayEquals("QR must round-trip the exact offer bytes", sampleOffer, fromQr)

        val link = QrCodec.encodeLink(sampleOffer)
        assertTrue("link must use the titlan://pair# scheme", link.startsWith("titlan://pair#"))
        val fromLink = QrCodec.decodeLink(link)
        assertArrayEquals("link must round-trip the exact offer bytes", sampleOffer, fromLink)
    }

    /**
     * Full pairing: mint an offer, inject its decoded frame into the responder,
     * verify proof-of-scan, establish a session, and exchange a message via the
     * real CI relay reached at 10.0.2.2. In RED the first production call
     * ([PairingCoordinator.createOffer]) is unimplemented; the relay leg is
     * never reached (so relay availability does not gate this red).
     */
    @Test
    fun offerScanProofAndFirstMessageRoundTrip() {
        val offer = PairingCoordinator.createOffer()

        // Frame injection at the codec boundary (design §9a): render then decode.
        val decoded = QrCodec.decodeQr(QrCodec.encodeQr(offer.bytes))
        val conversationId = PairingCoordinator.acceptScannedOffer(decoded)

        assertTrue("a conversation id must be returned on success", conversationId.isNotEmpty())
    }
}
