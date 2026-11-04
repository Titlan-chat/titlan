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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.tezca_core.TitlanException

/**
 * 1.1 red suite (gate L-D3/L-D4/L-D8): a conversation label set through
 * [ConversationStore] reaches core, shows on the list row, and is read back
 * by core from the encrypted store on a fresh open of the same database —
 * the persistence the §0 restart step then proves on a device. Driven only
 * through production API; the app's process-wide core pairs with a scratch
 * peer (the F1 two-client shape), and the re-open proof uses scratch
 * databases only (the AppCore contract: `filesDir/titlan.db` is never
 * reopened by a test).
 *
 * RED expectation: [labelShowsOnTheRowAndClears] fails with
 * `kotlin.NotImplementedError` at the stub [ConversationStore.setLabel];
 * [labelSurvivesAFreshOpenOfTheStore] and [coreRejectsALabelOverTheRule]
 * fail at their first core label call with the `InternalException` uniffi
 * raises for core's `todo!()` stub. GREEN turns all three green.
 */
@RunWith(AndroidJUnit4::class)
class ConversationLabelTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun tearDown() {
        SyncController.stop(context)
    }

    private fun freshKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun scratchDb(name: String): File =
        File(context.cacheDir, "conversation-label-$name.db").also { it.delete() }

    @Test
    fun labelShowsOnTheRowAndClears() = runBlocking {
        val app = AppCore.get()
        if (!app.isInitialized()) app.initializeIdentity()
        val before = ConversationStore.refreshConversations().toSet()
        CoreClientFactory.open(scratchDb("peer").path, freshKey(), BuildConfig.RELAY_URL).use { peer ->
            peer.initializeIdentity()
            peer.beginPairingFromOffer(app.exportPairingOffer())
        }
        val key = ConversationStore.refreshConversations().first { it !in before }

        // RED stops here: the label write is unimplemented.
        assertTrue("a valid label must be stored", ConversationStore.setLabel(key, "  Alice at work  "))
        val row = ConversationStore.rows.value.first { it.key == key }
        assertEquals("the row shows the trimmed label", "Alice at work", row.label)
        assertEquals(
            "core reads the label back through the summaries",
            "Alice at work",
            app.listConversationSummaries().first { ConversationKey.of(it.id) == key }.label,
        )

        assertTrue("clearing must succeed", ConversationStore.setLabel(key, null))
        assertNull(
            "a cleared label reads null (the row falls back to the hex form)",
            ConversationStore.rows.value.first { it.key == key }.label,
        )
    }

    @Test
    fun labelSurvivesAFreshOpenOfTheStore() {
        val path = scratchDb("persist").path
        val key = freshKey()
        val conversation = CoreClientFactory.open(path, key, BuildConfig.RELAY_URL).use { a ->
            a.initializeIdentity()
            CoreClientFactory.open(scratchDb("persist-peer").path, freshKey(), BuildConfig.RELAY_URL).use { b ->
                b.initializeIdentity()
                b.beginPairingFromOffer(a.exportPairingOffer())
            }
            assertTrue("the offerer lists the paired conversation", await(10_000) { a.listConversations().size == 1 })
            val conv = a.listConversations().single()
            // RED stops here: core's label write is unimplemented.
            a.setConversationLabel(conv, "Persisted name")
            conv
        }
        CoreClientFactory.open(path, key, BuildConfig.RELAY_URL).use { reopened ->
            val summary = reopened.listConversationSummaries().single()
            assertTrue(summary.id.contentEquals(conversation))
            assertEquals("the label is read from the encrypted store on disk", "Persisted name", summary.label)
            assertTrue("last activity is at least the creation time", summary.lastActivityAt >= summary.createdAt)
        }
    }

    @Test
    fun coreRejectsALabelOverTheRule() {
        CoreClientFactory.open(scratchDb("rule").path, freshKey(), BuildConfig.RELAY_URL).use { a ->
            a.initializeIdentity()
            CoreClientFactory.open(scratchDb("rule-peer").path, freshKey(), BuildConfig.RELAY_URL).use { b ->
                b.initializeIdentity()
                b.beginPairingFromOffer(a.exportPairingOffer())
            }
            assertTrue("the offerer lists the paired conversation", await(10_000) { a.listConversations().size == 1 })
            val conversation = a.listConversations().single()
            // RED stops here: core's label write is unimplemented.
            a.setConversationLabel(conversation, "kept")
            for (bad in listOf("   ", "x".repeat(LabelRules.MAX_SCALARS + 1), "line\nbreak")) {
                try {
                    a.setConversationLabel(conversation, bad)
                    fail("core must reject the label ${bad.take(8)}…")
                } catch (_: TitlanException) {
                    // expected: never truncated, never repaired
                }
            }
            assertEquals(
                "a rejected label leaves the stored one untouched",
                "kept",
                a.listConversationSummaries().single().label,
            )
        }
    }
}
