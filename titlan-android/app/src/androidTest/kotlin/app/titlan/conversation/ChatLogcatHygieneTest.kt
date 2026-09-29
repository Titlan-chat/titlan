// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import android.util.Base64
import android.util.Log
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
 * 5e-1 acceptance (INV-1, log surface; freeze CU-D10): chat text never
 * reaches logcat in any common encoding — a canary sent through the store and
 * a canary received from a scratch peer, all buffers, with the 4b-1
 * positive-control canary so absence cannot be vacuous.
 *
 * RED expectation: fails with `kotlin.NotImplementedError` at the stub
 * [ConversationStore.refreshConversations]. GREEN runs the real path.
 */
@RunWith(AndroidJUnit4::class)
class ChatLogcatHygieneTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @After
    fun tearDown() {
        SyncController.stop(context)
    }

    private fun freshKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Test
    fun chatTextNeverAppearsInLogcat() = runBlocking {
        shell("logcat -b all -c")
        val canary = "TITLAN_CHAT_LOGCAT_CANARY_5e1a9f"
        Log.w("ChatLogcatHygieneTest", canary)

        val app = AppCore.get()
        if (!app.isInitialized()) app.initializeIdentity()
        val sent = "titlan chat hygiene sent 5e1 x7q2"
        val received = "titlan chat hygiene received 5e1 k4m8"
        val peerDb = File(context.cacheDir, "chat-logcat-peer.db").also { it.delete() }
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

        val log = shell("logcat -b all -d")
        assertTrue(
            "positive control failed: the logcat scanner did not see the deliberate canary — " +
                "absence results below would be meaningless",
            log.contains(canary),
        )
        for (text in listOf(sent, received)) {
            val bytes = text.toByteArray(Charsets.UTF_8)
            val hex = bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
            for (encoding in listOf(text, hex, hex.uppercase(), Base64.encodeToString(bytes, Base64.NO_WRAP))) {
                assertFalse(
                    "chat text leaked to logcat (INV-1), encoding: ${encoding.take(12)}…",
                    log.contains(encoding),
                )
            }
        }
    }

    private fun shell(cmd: String): String =
        instrumentation.uiAutomation.executeShellCommand(cmd).use { pfd ->
            java.io.FileInputStream(pfd.fileDescriptor).readBytes().toString(Charsets.UTF_8)
        }
}
