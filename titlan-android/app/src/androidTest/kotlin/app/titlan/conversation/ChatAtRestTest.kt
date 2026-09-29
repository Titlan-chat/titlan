// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.BuildConfig
import app.titlan.core.AppCore
import app.titlan.core.CoreClientFactory
import app.titlan.sync.SyncController
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 5e-1 acceptance (INV-1 at rest; freeze CU-D10): after a chat message was
 * sent through the store and one received from a scratch peer, no file under
 * any app-accessible storage root contains either text in raw, hex or Base64
 * form — the SQLCipher stores are opaque, and any accidental preference,
 * saved-state or cache file would show here (the Inv1AtRestTest walk).
 *
 * RED expectation: fails with `kotlin.NotImplementedError` at the stub
 * [ConversationStore.refreshConversations]. GREEN runs the real path.
 */
@RunWith(AndroidJUnit4::class)
class ChatAtRestTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun tearDown() {
        SyncController.stop(context)
    }

    private fun freshKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Test
    fun chatTextNeverAtRest() = runBlocking {
        val app = AppCore.get()
        if (!app.isInitialized()) app.initializeIdentity()
        val sent = "titlan chat at-rest sent 5e1 p3w9"
        val received = "titlan chat at-rest received 5e1 z6c4"
        val peerDb = File(context.cacheDir, "chat-at-rest-peer.db").also { it.delete() }
        CoreClientFactory.open(peerDb.path, freshKey(), BuildConfig.RELAY_URL).use { peer ->
            peer.initializeIdentity()
            val peerConv = peer.beginPairingFromOffer(app.exportPairingOffer())

            // RED stops here: the store is unimplemented.
            val key = ConversationStore.refreshConversations().first()
            app.startSync(ConversationStore.events)
            assertEquals("the sent canary must be queued", SendOutcome.Queued, ConversationStore.send(key, sent))
            peer.sendChat(peerConv, received)
            assertTrue(
                "the received canary must arrive within 30 s",
                await(30_000) {
                    ConversationStore.messages(key).value.any { it.body == DecodedBody.Text(received) }
                },
            )
        }

        for (text in listOf(sent, received)) {
            val bytes = text.toByteArray(Charsets.UTF_8)
            val hex = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
            val b64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
            for (root in listOfNotNull(context.filesDir, context.cacheDir)) {
                root.walkTopDown().filter { it.isFile }.forEach { f ->
                    val content = f.readBytes()
                    assertFalse(
                        "chat text found at rest in ${f.path} (INV-1)",
                        containsSubsequence(content, bytes),
                    )
                    val asLatin1 = String(content, Charsets.ISO_8859_1)
                    assertFalse(
                        "hex-encoded chat text found at rest in ${f.path} (INV-1)",
                        asLatin1.contains(hex, ignoreCase = true),
                    )
                    assertFalse(
                        "Base64-encoded chat text found at rest in ${f.path} (INV-1)",
                        asLatin1.contains(b64),
                    )
                }
            }
        }
    }

    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
