// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

/**
 * Byte-identical QR / `titlan://` codec for the pairing offer (frozen design
 * §3/§4). PRODUCTION HOME, stubbed in the 4b-2 RED commit.
 *
 * One payload spec, two encodings: [encodeQr]/[decodeQr] and
 * [encodeLink]/[decodeLink] MUST round-trip the SAME `offer_bytes`
 * (`proto/pairing.md` §Offer payload). The `titlan://pair#<base64url>`
 * fragment is decoded locally and never leaves the device (§4).
 *
 * The instrumented [app.titlan.pairing] round-trip test injects a decoded
 * frame at this boundary rather than through the camera — decode-pipeline
 * validation, not scan ergonomics (frozen design §9a). Real CameraX capture +
 * ZXing decode/generate (design §5) is GREEN machinery and pulls the ZXing +
 * CameraX dependencies (deferred from the RED commit — see the red report
 * flags); this stub keeps the RED build dependency-free.
 */
object QrCodec {

    /** Renders `offerBytes` to QR module data for display. */
    fun encodeQr(offerBytes: ByteArray): QrMatrix =
        TODO("4b-2 green: ZXing QRCodeWriter over offer_bytes")

    /** Decodes QR module data (or an injected test frame) back to offer bytes. */
    fun decodeQr(frame: QrMatrix): ByteArray =
        TODO("4b-2 green: ZXing decode; must equal the encoded offer_bytes")

    /** Encodes `offerBytes` as `titlan://pair#<base64url-nopad>`. */
    fun encodeLink(offerBytes: ByteArray): String =
        TODO("4b-2 green: titlan://pair# + base64url(nopad) of offer_bytes")

    /** Decodes a `titlan://pair#…` link's fragment back to offer bytes. */
    fun decodeLink(link: String): ByteArray =
        TODO("4b-2 green: parse scheme, base64url-decode the fragment")
}

/**
 * Opaque QR module data (a square bit matrix). Concrete representation is a
 * green detail; declared so the codec surface and its test compile in RED.
 */
class QrMatrix(val modules: ByteArray)
