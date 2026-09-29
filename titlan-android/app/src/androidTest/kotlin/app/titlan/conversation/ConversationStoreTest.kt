// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.BuildConfig
import app.titlan.core.AppCore
import app.titlan.core.CoreClientFactory
import app.titlan.sync.ConnectionState
import app.titlan.sync.SyncController
import app.titlan.sync.SyncEvents
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 5e-1 red suite (freeze CU-D3/CU-D6): the UI sink and store, driven only
 * through production API against the live CI relay at 10.0.2.2 — the app's
 * process-wide core pairs with a scratch peer (F1 two-client shape: one
 * identity cannot pair with itself), then messages flow both ways through
 * [ConversationStore].
 *
 * RED expectation: both methods reach not-yet-implemented production code
 * and fail with `kotlin.NotImplementedError` at the first stub,
 * [ConversationStore.refreshConversations]. GREEN turns them green.
 */
@RunWith(AndroidJUnit4::class)
class ConversationStoreTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /** Joined core stop (4b2-WO-stop-sync) so the next test starts clean. */
    @After
    fun tearDown() {
        SyncController.stop(context)
    }

    private class RecordingPeerEvents : SyncEvents {
        override fun onMessageArrived(conversationId: ByteArray, messageId: ByteArray) = Unit
        override fun onConnectionState(
            conversationId: ByteArray,
            relayEndpoint: String,
            state: ConnectionState,
        ) = Unit
        override fun onConversationNeedsRepair(conversationId: ByteArray) = Unit
        override fun onPermanentSendFailure(conversationId: ByteArray, messageId: ByteArray) = Unit
        override fun onStorageError(detail: String) = Unit
    }

    private fun freshKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun scratchDb(name: String): File =
        File(context.cacheDir, "conversation-store-$name.db").also { it.delete() }

    @Test
    fun incomingChatAppearsInStoreAndOutgoingReachesPeer() = runBlocking {
        val app = AppCore.get()
        if (!app.isInitialized()) app.initializeIdentity()
        CoreClientFactory.open(scratchDb("peer").path, freshKey(), BuildConfig.RELAY_URL).use { peer ->
            peer.initializeIdentity()
            val peerConv = peer.beginPairingFromOffer(app.exportPairingOffer())

            // RED stops here: the store is unimplemented.
            val key = ConversationStore.refreshConversations().first()

            // Peer → app: the UI sink is registered BEFORE the peer sends.
            app.startSync(ConversationStore.events)
            val inbound = "titlan store canary in 5e1"
            peer.sendChat(peerConv, inbound)
            assertTrue(
                "a peer's chat must appear as an incoming text message in the store within 30 s",
                await(30_000) {
                    ConversationStore.messages(key).value.any {
                        it.incoming && it.body == DecodedBody.Text(inbound)
                    }
                },
            )

            // App → peer through the store's send path.
            peer.startSync(RecordingPeerEvents())
            val outbound = "titlan store canary out 5e1"
            assertEquals("a valid text must be queued", SendOutcome.Queued, ConversationStore.send(key, outbound))
            assertTrue(
                "the sent message must appear outgoing in the store immediately after send",
                ConversationStore.messages(key).value.any {
                    !it.incoming && it.body == DecodedBody.Text(outbound)
                },
            )
            assertTrue(
                "the store's send must reach the peer's store within 30 s",
                await(30_000) {
                    peer.messages(peerConv).any {
                        it.incoming && String(it.body, Charsets.UTF_8) == outbound
                    }
                },
            )
            assertEquals(
                "a blank text is rejected, not queued",
                SendOutcome.Rejected(SendCheck.Blank),
                ConversationStore.send(key, "   "),
            )
            peer.stopSync()
        }
    }

    @Test
    fun eventForAnUnknownKeyRefreshesTheConversationList() = runBlocking {
        val app = AppCore.get()
        if (!app.isInitialized()) app.initializeIdentity()

        // RED stops here: the store is unimplemented.
        val before = ConversationStore.refreshConversations().toSet()

        // A new pairing creates an app-side conversation the store has not listed.
        CoreClientFactory.open(scratchDb("peer-unknown").path, freshKey(), BuildConfig.RELAY_URL).use { peer ->
            peer.initializeIdentity()
            peer.beginPairingFromOffer(app.exportPairingOffer())
        }
        val newest = app.listConversations()
            .map { ConversationKey.of(it) }
            .first { it !in before }

        // The engine's first event for that conversation (CU-D3 refresh rule).
        ConversationStore.events.onConnectionState(newest.bytes, "", ConnectionState.CONNECTING)
        assertTrue(
            "an event naming a key not in the list must refresh the conversation list within 10 s",
            await(10_000) { ConversationStore.conversations.value.contains(newest) },
        )
        assertEquals(
            "the connection state must be recorded for that key",
            ConnectionState.CONNECTING,
            ConversationStore.connection.value[newest],
        )
    }
}

/** Polls [cond] every 50 ms until true or [timeoutMs] elapses. */
internal fun await(timeoutMs: Long, cond: () -> Boolean): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        if (cond()) return true
        Thread.sleep(50)
    }
    return cond()
}
