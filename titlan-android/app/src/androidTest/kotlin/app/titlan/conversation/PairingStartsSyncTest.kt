// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

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
 * 5e-1 red suite (freeze CU-D5/CU-D8): what both roles do once a pairing
 * completes — [PairingCompletion.complete] refreshes the store, starts
 * receive-sync with the UI sink through the one canonical entry
 * ([SyncController.start]), and returns the key the screen navigates to.
 *
 * RED expectation: fails with `kotlin.NotImplementedError` at the stub
 * [PairingCompletion.complete]. GREEN turns it green.
 */
@RunWith(AndroidJUnit4::class)
class PairingStartsSyncTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /** LaunchSyncTest teardown discipline: joined stop, then the S2 double-stop. */
    @After
    fun tearDown() {
        SyncController.stop(context)
        assertFalse("stop must leave sync not running", SyncController.isRunning(context))
        SyncController.stop(context)
    }

    private fun freshKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Test
    fun completionStartsSyncWithTheUiSinkAndReturnsTheKey() = runBlocking {
        val app = AppCore.get()
        if (!app.isInitialized()) app.initializeIdentity()
        val offer = app.exportPairingOffer()
        val peerDb = File(context.cacheDir, "pairing-completion-peer.db").also { it.delete() }
        CoreClientFactory.open(peerDb.path, freshKey(), BuildConfig.RELAY_URL).use { peer ->
            peer.initializeIdentity()
            peer.beginPairingFromOffer(offer)
        }
        val conversationId = app.listConversations().first()

        SyncController.stop(context)
        assertFalse("precondition: sync must be stopped before completion", SyncController.isRunning(context))

        // RED stops here: completion is unimplemented.
        val key = PairingCompletion.complete(context, conversationId)

        assertEquals("the key is the hex of the paired conversation id", ConversationKey.of(conversationId), key)
        assertTrue("pairing completion must start receive-sync", SyncController.isRunning(context))
        assertTrue(
            "the store must list the paired conversation after completion",
            ConversationStore.conversations.value.contains(key),
        )
    }
}
