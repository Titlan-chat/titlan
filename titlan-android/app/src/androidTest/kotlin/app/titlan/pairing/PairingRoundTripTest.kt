// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.BuildConfig
import app.titlan.core.CoreClientFactory
import java.io.File
import java.security.SecureRandom
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
 *
 * F1 (maintainer-ratified 2026-07-21): the responder half of the round trip is
 * a SECOND core client on a scratch DB — a real second device. One identity
 * cannot pair with itself (peer address == local address in the session
 * layer), so the red commit's single-AppCore shape was undrivable. Production
 * API only ([CoreClientFactory.open] + beginPairingFromOffer); the asserted
 * property is unchanged.
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

        // The scanning side is a real second device: a scratch core client
        // (F1). The app-side offerer path — proof-of-scan verification and the
        // inbox handoff — still runs in production code behind
        // [PairingCoordinator.createOffer].
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val peerDb = File(context.cacheDir, "pairing-peer-scratch.db").also { it.delete() }
        val peerKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val conversationId =
            CoreClientFactory.open(peerDb.path, peerKey, BuildConfig.RELAY_URL).use { peer ->
                peer.initializeIdentity()
                peer.beginPairingFromOffer(decoded)
            }

        assertTrue("a conversation id must be returned on success", conversationId.isNotEmpty())
    }
}
