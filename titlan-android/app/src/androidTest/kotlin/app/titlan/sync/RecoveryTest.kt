// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.BuildConfig
import app.titlan.core.CoreClient
import app.titlan.core.CoreClientFactory
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-2 CI signal (c) — §10.7 recovery EVENT SURFACING through the FFI
 * (frozen design §1/§8; F2 re-venue, maintainer-ratified 2026-07-21).
 *
 * Venue split (docs/acceptance-venues.md): §10.7 CONVERGENCE acceptance —
 * derived-mailbox recovery, generation windowing, rotation, exhaustion
 * mechanics — is graded against the Rust e2e suite
 * (`tezca-relay/tests/relay_client_e2e.rs`), which can restart a real relay
 * child process:
 *
 *   - v2_single_total_loss_recovers_via_derived_mailboxes
 *   - v2_two_consecutive_total_losses_each_recover
 *   - v2_peer_unreachable_exhausts_recovery_and_needs_repair
 *   - v2_message_queued_while_relay_down_delivers_after_recovery
 *
 * No emulator test can restart the runner-host relay (and no CI sidecar is
 * wanted), so THIS suite covers the Android layer's own §1 obligation: the
 * frozen event vocabulary genuinely crosses the FFI to Kotlin observers —
 * "reconnecting, wait" states and the "unrecoverable, act" signal
 * ([SyncEvents.onConversationNeedsRepair]) — driven ONLY through production
 * API: [CoreClientFactory.open] against live, dead, or amnesiac relays (the
 * last a plain HTTP test double, [FakeRelay], standing in for a relay that
 * lost its mailboxes — the same loss signal a restart produces).
 *
 * Each test pairs a scratch offerer with a scratch peer over the real CI
 * relay (F1 two-client shape: one identity cannot pair with itself), then
 * reopens the offerer's store pointed at the relay under test — the relay URL
 * is stored config at open time (INV-5), so this is the production reopen
 * path, not a hook.
 */
@RunWith(AndroidJUnit4::class)
class RecoveryTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private class RecordingEvents : SyncEvents {
        val states = CopyOnWriteArrayList<Pair<ByteArray, ConnectionState>>()
        val needsRepair = CopyOnWriteArrayList<ByteArray>()

        // Captured for failure-message diagnostics only (never asserted on):
        // the two existing frozen-§1 error events. Core currently emits
        // storage-error only from flush_pending; nothing new is added here.
        val storageErrors = CopyOnWriteArrayList<String>()
        val sendFailures = CopyOnWriteArrayList<Pair<ByteArray, ByteArray>>()

        override fun onMessageArrived(conversationId: ByteArray, messageId: ByteArray) = Unit

        override fun onConnectionState(
            conversationId: ByteArray,
            relayEndpoint: String,
            state: ConnectionState,
        ) {
            states += conversationId to state
        }

        override fun onConversationNeedsRepair(conversationId: ByteArray) {
            needsRepair += conversationId
        }

        override fun onPermanentSendFailure(conversationId: ByteArray, messageId: ByteArray) {
            sendFailures += conversationId to messageId
        }

        override fun onStorageError(detail: String) {
            storageErrors += detail
        }

        fun awaitState(want: ConnectionState, timeoutMs: Long): Boolean =
            await(timeoutMs) { states.any { it.second == want } }
    }

    private fun freshKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun scratchDb(name: String): File =
        File(context.cacheDir, "recovery-$name.db").also { it.delete() }

    /**
     * Pairs [offerer] with a throwaway scratch peer over the real CI relay and
     * returns the OFFERER-side conversation id (the id recovery events carry).
     */
    private fun pairWithScratchPeer(offerer: CoreClient, peerDb: File): ByteArray {
        val offer = offerer.exportPairingOffer()
        CoreClientFactory.open(peerDb.path, freshKey(), BuildConfig.RELAY_URL).use { peer ->
            peer.initializeIdentity()
            peer.beginPairingFromOffer(offer)
        }
        val conv = offerer.listConversations().firstOrNull()
        assertNotNull("offerer-side conversation must exist after pairing", conv)
        return conv!!
    }

    /**
     * Failure-message diagnostics (instrumentation only — pass/fail conditions
     * are untouched): what the core actually did to the relay double (every
     * request + accepted-connection count), the observed §1 state sequence,
     * and any captured storage-error / permanent-send-failure events. Run
     * 29800890689 failed with zero visibility; this makes the next failure
     * self-diagnosing.
     */
    private fun diag(claim: String, relay: FakeRelay, events: RecordingEvents): String =
        claim +
            " [FakeRelay bound=${relay.boundAddress}" +
            " accepts=${relay.accepts.get()}" +
            " requests=${relay.requestLog.toList()}" +
            " | states=${events.states.map { it.second }}" +
            " | storageErrors=${events.storageErrors.toList()}" +
            " | permanentSendFailures=${events.sendFailures.size}]"

    /**
     * (was singleTotalLossRecoversViaDerivedMailboxes; convergence graded by
     * Rust `v2_single_total_loss_recovers_via_derived_mailboxes`.) The §1
     * state vocabulary surfaces for a real paired conversation on the live CI
     * relay: CONNECTING then ONLINE, carrying the conversation id.
     */
    @Test
    fun connectionStatesSurfaceThroughFfiOnLiveRelay() {
        val events = RecordingEvents()
        CoreClientFactory.open(scratchDb("live-a").path, freshKey(), BuildConfig.RELAY_URL)
            .use { a ->
                a.initializeIdentity()
                // Observers in place BEFORE pairing spawns the listener, so no
                // transition can be missed.
                a.startSync(events)
                val conv = pairWithScratchPeer(a, scratchDb("live-peer"))
                assertTrue(
                    "CONNECTING must surface through the FFI",
                    events.awaitState(ConnectionState.CONNECTING, 20_000),
                )
                assertTrue(
                    "ONLINE must surface through the FFI",
                    events.awaitState(ConnectionState.ONLINE, 20_000),
                )
                assertTrue(
                    "state events must carry the conversation id",
                    events.states.any { it.first.contentEquals(conv) },
                )
            }
    }

    /**
     * (was doubleRestartDesyncConverges; convergence graded by Rust
     * `v2_two_consecutive_total_losses_each_recover`.) A dead relay surfaces
     * the "reconnecting, wait" side of §1 — OFFLINE then BACKOFF — through
     * the FFI.
     */
    @Test
    fun deadRelaySurfacesOfflineAndBackoffThroughFfi() {
        val aDb = scratchDb("dead-a")
        val aKey = freshKey()
        CoreClientFactory.open(aDb.path, aKey, BuildConfig.RELAY_URL).use { a ->
            a.initializeIdentity()
            pairWithScratchPeer(a, scratchDb("dead-peer"))
        }
        val events = RecordingEvents()
        // Reopen the SAME store pointed at a dead port (production open path).
        CoreClientFactory.open(aDb.path, aKey, "ws://127.0.0.1:9").use { a ->
            a.startSync(events)
            assertTrue(
                "OFFLINE must surface through the FFI",
                events.awaitState(ConnectionState.OFFLINE, 20_000),
            )
            assertTrue(
                "BACKOFF must surface through the FFI",
                events.awaitState(ConnectionState.BACKOFF, 20_000),
            )
        }
    }

    /**
     * (was forcedOffsetBeyondWindowNeedsRepair; exhaustion mechanics graded by
     * Rust `v2_peer_unreachable_exhausts_recovery_and_needs_repair`.) The
     * "unrecoverable, act" signal genuinely crosses the FFI: an amnesiac relay
     * 404s every subscribe (the real §10.7 loss signal) while the peer never
     * answers a recovery-hello, so core's ratified 3-probe-cycle exhaustion
     * fires and [SyncEvents.onConversationNeedsRepair] must reach Kotlin with
     * the conversation id.
     */
    @Test
    fun needsRepairSurfacesThroughFfiOnRecoveryExhaustion() {
        val aDb = scratchDb("repair-a")
        val aKey = freshKey()
        var conv: ByteArray? = null
        CoreClientFactory.open(aDb.path, aKey, BuildConfig.RELAY_URL).use { a ->
            a.initializeIdentity()
            conv = pairWithScratchPeer(a, scratchDb("repair-peer"))
        }
        FakeRelay(putStatus = 201).use { amnesiac ->
            val events = RecordingEvents()
            CoreClientFactory.open(aDb.path, aKey, amnesiac.url).use { a ->
                a.startSync(events)
                val surfaced = await(30_000) { events.needsRepair.isNotEmpty() }
                assertTrue(
                    diag("needs-repair must surface through the FFI on exhaustion", amnesiac, events),
                    surfaced,
                )
                assertTrue(
                    diag("needs-repair must carry the conversation id", amnesiac, events),
                    events.needsRepair.any { it.contentEquals(conv!!) },
                )
            }
        }
    }

    /**
     * (was pacing429sDoNotCountTowardExhaustion — the negative preserved at
     * the event layer.) While the relay 429-paces recovery, exhaustion must
     * NOT fire: after ≥4 observed paced attempts, no needs-repair has crossed
     * the FFI (ratified §8: relay 429s are pacing, never counted).
     */
    @Test
    fun pacing429sDoNotSurfaceNeedsRepairThroughFfi() {
        val aDb = scratchDb("pacing-a")
        val aKey = freshKey()
        CoreClientFactory.open(aDb.path, aKey, BuildConfig.RELAY_URL).use { a ->
            a.initializeIdentity()
            pairWithScratchPeer(a, scratchDb("pacing-peer"))
        }
        FakeRelay(putStatus = 429).use { pacing ->
            val events = RecordingEvents()
            CoreClientFactory.open(aDb.path, aKey, pacing.url).use { a ->
                a.startSync(events)
                val observed = await(30_000) { pacing.putRequests.get() >= 4 }
                assertTrue(
                    diag("positive control: ≥4 paced recovery attempts must be observed", pacing, events),
                    observed,
                )
                assertTrue(
                    diag("positive control: sync must be live (CONNECTING seen)", pacing, events),
                    events.states.any { it.second == ConnectionState.CONNECTING },
                )
                assertTrue(
                    diag("429 pacing must never surface needs-repair (frozen §8)", pacing, events),
                    events.needsRepair.isEmpty(),
                )
            }
        }
    }
}

/** Polls [cond] every 50 ms until true or [timeoutMs] elapses. */
private fun await(timeoutMs: Long, cond: () -> Boolean): Boolean {
    val deadline = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < deadline) {
        if (cond()) return true
        Thread.sleep(50)
    }
    return cond()
}
