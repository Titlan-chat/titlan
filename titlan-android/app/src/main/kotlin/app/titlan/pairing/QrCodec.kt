// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import android.util.Base64
import com.google.zxing.BarcodeFormat
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.BinaryBitmap
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Byte-identical QR / `titlan://` codec for the pairing offer (frozen design
 * §3/§4), on real ZXing. One payload spec, two encodings: [encodeQr]/[decodeQr]
 * and [encodeLink]/[decodeLink] round-trip the SAME `offer_bytes`
 * (`proto/pairing.md` §Offer payload). The `titlan://pair#<base64url>` fragment
 * is decoded locally and never leaves the device (§4).
 *
 * Both encodings carry the offer bytes as base64url(nopad) — a URL-safe,
 * QR-alphanumeric-friendly transport that is identical across QR and link, so
 * the two paths are provably the same payload. The QR path renders through
 * ZXing's `QRCodeWriter` and decodes back through `QRCodeReader` over the
 * rendered module matrix (design §9a injects the decoded frame at this
 * boundary rather than through the camera).
 */
object QrCodec {

    /** Renders `offerBytes` to QR module data for display. */
    fun encodeQr(offerBytes: ByteArray): QrMatrix {
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
            EncodeHintType.CHARACTER_SET to "ISO-8859-1",
            EncodeHintType.MARGIN to QUIET_ZONE,
        )
        // width/height = 1 asks QRCodeWriter for the natural 1px-per-module
        // matrix (plus the quiet-zone margin), so decode sees exact modules.
        val matrix = QRCodeWriter().encode(b64(offerBytes), BarcodeFormat.QR_CODE, 1, 1, hints)
        return QrMatrix(serialize(matrix))
    }

    /** Decodes QR module data (or an injected test frame) back to offer bytes. */
    fun decodeQr(frame: QrMatrix): ByteArray {
        val matrix = deserialize(frame.modules)
        val bitmap = BinaryBitmap(HybridBinarizer(BitMatrixLuminanceSource(matrix)))
        val hints = mapOf(
            DecodeHintType.PURE_BARCODE to true,
            DecodeHintType.TRY_HARDER to true,
        )
        val text = QRCodeReader().decode(bitmap, hints).text
        return unb64(text)
    }

    /** Encodes `offerBytes` as `titlan://pair#<base64url-nopad>`. */
    fun encodeLink(offerBytes: ByteArray): String = "$LINK_PREFIX${b64(offerBytes)}"

    /** Decodes a `titlan://pair#…` link's fragment back to offer bytes. */
    fun decodeLink(link: String): ByteArray {
        require(link.startsWith(LINK_PREFIX)) { "not a titlan://pair# link" }
        return unb64(link.substring(LINK_PREFIX.length))
    }

    private const val LINK_PREFIX = "titlan://pair#"
    private const val QUIET_ZONE = 4
    private const val B64_FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, B64_FLAGS)
    private fun unb64(s: String): ByteArray = Base64.decode(s, B64_FLAGS)

    /** `[w:int-be][h:int-be]` then `w*h` bytes, 1 = dark module, 0 = light. */
    private fun serialize(m: BitMatrix): ByteArray {
        val out = ByteArray(8 + m.width * m.height)
        writeIntBe(out, 0, m.width)
        writeIntBe(out, 4, m.height)
        var i = 8
        for (y in 0 until m.height) {
            for (x in 0 until m.width) {
                out[i++] = if (m.get(x, y)) 1 else 0
            }
        }
        return out
    }

    private fun deserialize(bytes: ByteArray): BitMatrix {
        val w = readIntBe(bytes, 0)
        val h = readIntBe(bytes, 4)
        val m = BitMatrix(w, h)
        var i = 8
        for (y in 0 until h) {
            for (x in 0 until w) {
                if (bytes[i++].toInt() != 0) m.set(x, y)
            }
        }
        return m
    }

    private fun writeIntBe(a: ByteArray, off: Int, v: Int) {
        a[off] = (v ushr 24).toByte()
        a[off + 1] = (v ushr 16).toByte()
        a[off + 2] = (v ushr 8).toByte()
        a[off + 3] = v.toByte()
    }

    private fun readIntBe(a: ByteArray, off: Int): Int =
        (a[off].toInt() and 0xFF shl 24) or
            (a[off + 1].toInt() and 0xFF shl 16) or
            (a[off + 2].toInt() and 0xFF shl 8) or
            (a[off + 3].toInt() and 0xFF)
}

/**
 * A ZXing [LuminanceSource] backed by a rendered [BitMatrix]: a dark module is
 * luminance 0, a light module 255. Lets [QrCodec.decodeQr] run the real ZXing
 * decode pipeline over the rendered matrix without a camera frame.
 */
private class BitMatrixLuminanceSource(matrix: BitMatrix) :
    LuminanceSource(matrix.width, matrix.height) {

    private val lum = ByteArray(width * height).also { buf ->
        for (y in 0 until height) {
            for (x in 0 until width) {
                buf[y * width + x] = if (matrix.get(x, y)) 0 else 255.toByte()
            }
        }
    }

    override fun getRow(y: Int, row: ByteArray?): ByteArray {
        val out = if (row == null || row.size < width) ByteArray(width) else row
        System.arraycopy(lum, y * width, out, 0, width)
        return out
    }

    override fun getMatrix(): ByteArray = lum
}

/**
 * Opaque QR module data (a rendered bit matrix). Concrete representation is a
 * codec detail; declared so the codec surface and its test compile.
 */
class QrMatrix(val modules: ByteArray)
