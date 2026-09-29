// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 5e-1 red suite (freeze CU-D6): the chat body decoding rule and the composer
 * cap (finding F-H), plain-JVM — pure functions, no Android runtime.
 *
 * RED expectation: every method reaches not-yet-implemented production code
 * and fails with `kotlin.NotImplementedError` at the first stub —
 * [ChatBody.decode], [ChatBody.admit], [ChatBody.utf8Length] or
 * [ChatLimits.MAX_CHAT_UTF8_BYTES]. GREEN turns them green.
 */
class ChatBodyDecodingTest {

    @Test
    fun chatV1Utf8DecodesToText() {
        val text = "hello, Titlan — ¿qué tal? 🙂"
        val decoded = ChatBody.decode(
            ChatBody.CHAT_PAYLOAD_TYPE,
            ChatBody.CHAT_TYPE_VERSION,
            text.toByteArray(Charsets.UTF_8),
        )
        assertEquals("chat/1 UTF-8 must decode to its text", DecodedBody.Text(text), decoded)
    }

    @Test
    fun malformedUtf8IsUndecodable() {
        val body = byteArrayOf(0x68, 0x69, 0xFF.toByte(), 0xFE.toByte(), 0x21)
        assertEquals(
            "malformed UTF-8 in a chat/1 frame must render as the undecodable placeholder",
            DecodedBody.Undecodable,
            ChatBody.decode(ChatBody.CHAT_PAYLOAD_TYPE, ChatBody.CHAT_TYPE_VERSION, body),
        )
    }

    @Test
    fun otherTypesAndVersionsAreUnsupportedAndNeverDecoded() {
        val looksLikeText = "looks like text".toByteArray(Charsets.UTF_8)
        assertEquals(
            "chat/2 must be unsupported (only chat/1 is rendered)",
            DecodedBody.Unsupported,
            ChatBody.decode(ChatBody.CHAT_PAYLOAD_TYPE, 2, looksLikeText),
        )
        assertEquals(
            "posture/1 must be unsupported",
            DecodedBody.Unsupported,
            ChatBody.decode(0x02, 1, looksLikeText),
        )
        assertEquals(
            "policy/1 must be unsupported",
            DecodedBody.Unsupported,
            ChatBody.decode(0x03, 1, looksLikeText),
        )
        assertEquals(
            "alert/1 must be unsupported",
            DecodedBody.Unsupported,
            ChatBody.decode(0x04, 1, looksLikeText),
        )
    }

    @Test
    fun capIsTheSpecMaximumPayload() {
        val spec = repoFile("proto/envelope.md").readText(Charsets.UTF_8)
        val stated = Regex("""Maximum payload under the default profile: \*\*(\d+) bytes\*\*""").find(spec)
        assertTrue(
            "proto/envelope.md must state the default profile's maximum payload",
            stated != null,
        )
        assertEquals(
            "MAX_CHAT_UTF8_BYTES must equal the maximum payload proto/envelope.md states",
            stated!!.groupValues[1].toInt(),
            ChatLimits.MAX_CHAT_UTF8_BYTES,
        )
        assertEquals(
            "the cap is 8186 (512/2048/8192 buckets, 6-byte inner header)",
            8186,
            ChatLimits.MAX_CHAT_UTF8_BYTES,
        )
    }

    @Test
    fun admitTrimsBlanksAndEnforcesTheCap() {
        assertEquals("blank input is rejected", SendCheck.Blank, ChatBody.admit("   \n\t "))
        assertEquals("input is trimmed", SendCheck.Ok("hi"), ChatBody.admit("  hi \n"))
        val atCap = "a".repeat(8186)
        assertEquals("8186 UTF-8 bytes are admitted", SendCheck.Ok(atCap), ChatBody.admit(atCap))
        val overCap = "a".repeat(8187)
        assertEquals(
            "8187 UTF-8 bytes are rejected as too long",
            SendCheck.TooLong(8187),
            ChatBody.admit(overCap),
        )
        val multibyte = "é".repeat(4094) // 2 bytes each: 8188 bytes, 4094 characters
        assertEquals("utf8Length counts bytes, not characters", 8188, ChatBody.utf8Length(multibyte))
        assertEquals(
            "the cap counts UTF-8 bytes, not characters",
            SendCheck.TooLong(8188),
            ChatBody.admit(multibyte),
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
