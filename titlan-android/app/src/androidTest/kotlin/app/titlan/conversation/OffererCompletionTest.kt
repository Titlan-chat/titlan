// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.BuildConfig
import app.titlan.core.AppCore
import app.titlan.core.CoreClientFactory
import app.titlan.pairing.PairingCoordinator
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 5e-1 red suite (freeze CU-D4): the offerer completion signal. The app's
 * process-wide core mints an offer through the production
 * [PairingCoordinator]; a scratch peer accepts it over the live CI relay;
 * [OfferWatcher] must report the new conversation — and must report nothing
 * for an offer nobody accepts.
 *
 * RED expectation: both methods fail with `kotlin.NotImplementedError` at
 * the first stub, [ConversationStore.refreshConversations]. GREEN turns them
 * green.
 */
@RunWith(AndroidJUnit4::class)
class OffererCompletionTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun freshKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Test
    fun watcherReportsTheNewConversationAfterAPeerPairs() = runBlocking {
        val app = AppCore.get()
        if (!app.isInitialized()) app.initializeIdentity()
        val offer = PairingCoordinator.createOffer()

        // RED stops here: the store is unimplemented.
        val before = ConversationStore.refreshConversations().toSet()
        val watched = async(Dispatchers.Default) {
            OfferWatcher.awaitNewConversation(
                before = before,
                deadlineEpochMillis = System.currentTimeMillis() + 60_000,
                pollMillis = 500,
            )
        }

        val peerDb = File(context.cacheDir, "offerer-completion-peer.db").also { it.delete() }
        CoreClientFactory.open(peerDb.path, freshKey(), BuildConfig.RELAY_URL).use { peer ->
            peer.initializeIdentity()
            peer.beginPairingFromOffer(offer.bytes)
        }

        val key = withTimeoutOrNull(10_000) { watched.await() }
        assertNotNull("the watcher must report the paired conversation within 10 s of the peer's pairing", key)
        assertTrue("the reported key must not be in the pre-mint set", key!! !in before)
        assertTrue(
            "the reported key must be a conversation core lists",
            app.listConversations().any { ConversationKey.of(it) == key },
        )
    }

    @Test
    fun watcherReportsNothingForAnOfferNobodyAccepts() = runBlocking {
        val app = AppCore.get()
        if (!app.isInitialized()) app.initializeIdentity()

        // RED stops here: the store is unimplemented.
        val before = ConversationStore.refreshConversations().toSet()
        PairingCoordinator.createOffer() // minted, never scanned
        val key = OfferWatcher.awaitNewConversation(
            before = before,
            deadlineEpochMillis = System.currentTimeMillis() + 3_000,
            pollMillis = 500,
        )
        assertNull("an offer nobody accepted must not produce a key", key)
    }
}
