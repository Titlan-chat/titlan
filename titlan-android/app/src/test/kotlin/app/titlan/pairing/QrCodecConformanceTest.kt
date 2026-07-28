// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * QR-codec conformance vector (the QrCodec dual-sourcing ledger item, landed
 * as a permanent guard; maintainer-ratified receipt 4b2-WO-codec-fixture-tests).
 * The committed pairing-offer link in `proto/fixtures/` must decode to exactly
 * the pinned offer bytes on BOTH stacks — here (plain-JVM Kotlin) and in the
 * Rust core suite (`tezca-core/src/pairing.rs`,
 * `committed_conformance_vector_link_round_trips_and_parses`) — so the link
 * wire encoding cannot drift on either side without a red build. Expectations
 * are single-sourced in `pairing-offer-v2.expected.txt`, shared by both tests.
 *
 * `android.util.Base64` is not executable off-device (plain-JVM unit suite, no
 * Robolectric), so this test applies the established byte-exact replication of
 * [QrCodec.decodeLink]'s transformation: strip the `titlan://pair#` prefix,
 * then RFC 4648 url-safe base64 decode with no padding
 * (`java.util.Base64.getUrlDecoder()`), matching the app's
 * `URL_SAFE or NO_PADDING or NO_WRAP` flags per the clean-input equivalence
 * analysis in `~/4b2-codec-conform.md` (for input in `[A-Za-z0-9-_]` with no
 * whitespace and no padding, android's decode IS the RFC 4648 url-safe
 * decode). Device-empirical equivalence evidence on file
 * (`device-evidence/pairing/first-pair-20260728-probes.txt`, 2026-07-27/28):
 * the 4b-2 stage-0/stage-1 probes agreed on real hardware across three scan
 * events of a live offer — link sha256 `a385ad0f…`/2677 chars decoded to
 * `34c5937f…`/1997 bytes identically all three times, stage-1 == stage-2 at
 * the FFI entry, and the pairing ESTABLISHED, which verifies libsignal
 * signatures over the decoded bundle — i.e. the on-device
 * `android.util.Base64` output was byte-exact end-to-end.
 */
class QrCodecConformanceTest {

    @Test
    fun committedVectorDecodesToPinnedBytes() {
        val link = fixture("pairing-offer-v2.link.txt").readText(Charsets.UTF_8)
        val expected = fixture("pairing-offer-v2.expected.txt").readLines()
            .mapNotNull { line -> line.split('=', limit = 2).takeIf { it.size == 2 } }
            .associate { (key, value) -> key to value }

        assertTrue("committed link carries the titlan://pair# prefix", link.startsWith(LINK_PREFIX))

        // Byte-exact replication of QrCodec.decodeLink (see class KDoc).
        val bytes = java.util.Base64.getUrlDecoder().decode(link.substring(LINK_PREFIX.length))

        assertEquals("pinned decoded-bytes length", expected.getValue("decoded_len"), bytes.size.toString())
        val sha256 = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        assertEquals("pinned decoded-bytes sha256", expected.getValue("decoded_sha256"), sha256)
    }

    /** Resolves a repo fixture by walking up from the test working directory. */
    private fun fixture(name: String): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, "proto/fixtures/$name")
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        error("proto/fixtures/$name not found above ${System.getProperty("user.dir")}")
    }

    private companion object {
        const val LINK_PREFIX = "titlan://pair#"
    }
}
