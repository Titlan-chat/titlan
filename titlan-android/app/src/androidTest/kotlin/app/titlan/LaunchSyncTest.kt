// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.core.AppCore
import app.titlan.core.CoreClient
import app.titlan.core.CoreClientFactory
import app.titlan.sync.FakeRelay
import app.titlan.sync.SyncController
import java.io.File
import java.security.SecureRandom
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b2-WO-launch-sync — launch-time sync start (device-checklist finding).
 *
 * Property: with a paired conversation durably persisted in the app store,
 * cold-starting [MainActivity] must start [SyncService] (receive-sync), so a
 * process death no longer leaves the app permanently non-syncing. Sync start is
 * currently reachable only via [SyncController.start] (no launch wiring), so a
 * cold launch composes PairingScreen and never starts sync.
 *
 * Two graded facts (flag ruling, Option B — see ~/4b2-launch-sync-flag.md):
 *
 *  - Assertion 7 (the RED→GREEN signal): after a cold [MainActivity] launch with
 *    a paired conversation present, [SyncController.isRunning] is true. This is
 *    the recorded RED failure signature — in RED, launch never starts sync, so
 *    this assertion fails (after all setup succeeds).
 *  - Assertion 8 (GREEN-side strengthening): the launch-started sync engages the
 *    relay. The device-global receive subscribe targets `my_relay`
 *    (BuildConfig.RELAY_URL, the live CI relay in the emulator lane), so it is
 *    not observable on a controllable relay; instead a pre-queued outbound
 *    message is flushed on connect to the per-conversation relay override
 *    (`convo.relay_url`, INV-5) pointed at an in-process [FakeRelay], observed as
 *    a deposit. This assertion is reached ONLY in GREEN (assertion 7 throws
 *    first in RED); its reachability is demonstrated by the GREEN run, not RED.
 *
 * Seeding is the [RecoveryTest]-style scratch-peer pairing over the live CI
 * relay (one identity cannot pair with itself); production API only.
 */
@RunWith(AndroidJUnit4::class)
class LaunchSyncTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /** Leave the shared process clean for the next test in the suite. */
    @After
    fun tearDown() {
        SyncController.stop(context)
    }

    private fun freshKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    /**
     * Pairs the process-wide app [offerer] with a throwaway scratch peer over
     * the live CI relay and returns the offerer-side conversation id (the
     * [RecoveryTest.pairWithScratchPeer] shape — a real second device, since one
     * identity cannot pair with itself).
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

    @Test
    fun coldLaunchWithPairedConversationStartsSyncAndSubscribes() {
        val core = AppCore.get()
        if (!core.isInitialized()) core.initializeIdentity()
        val conv = pairWithScratchPeer(
            core,
            File(context.cacheDir, "launch-sync-peer.db").also { it.delete() },
        )

        // Keep one outbound message pending so the launch-started sync has
        // something to flush on connect: point the conversation at an
        // unreachable relay first, so sendChat's immediate best-effort flush
        // cannot deliver (the message stays pending), then redirect deposits to
        // the observable relay double. Nothing has reached the FakeRelay yet.
        core.setConversationRelay(conv, "ws://127.0.0.1:1")
        core.sendChat(conv, "launch-sync probe")

        FakeRelay(putStatus = 201).use { relay ->
            core.setConversationRelay(conv, relay.url)

            // Launch-specific precondition: sync must be stopped, so "running
            // after launch" cannot be vacuously satisfied by a prior test in
            // this shared process.
            SyncController.stop(context)
            assertFalse(
                "precondition: sync must be stopped before launch",
                SyncController.isRunning(context),
            )

            ActivityScenario.launch(MainActivity::class.java).use {
                // Assertion 7 — RED→GREEN signal / recorded RED failure
                // signature: a cold launch with a paired conversation present
                // must start SyncService.
                assertTrue(
                    "cold launch with a paired conversation must start SyncService",
                    await(20_000) { SyncController.isRunning(context) },
                )
                // Assertion 8 — GREEN-side strengthening (reached only in
                // GREEN): the launch-started sync connects to my_relay and
                // flushes the pending message to the per-conversation relay
                // override, observed as a deposit on the FakeRelay.
                assertTrue(
                    diag("launch-started sync must reach the relay (deposit observed)", relay),
                    await(20_000) { relay.accepts.get() > 0 },
                )
            }
        }
    }

    private fun diag(claim: String, relay: FakeRelay): String =
        claim +
            " [FakeRelay bound=${relay.boundAddress}" +
            " accepts=${relay.accepts.get()}" +
            " requests=${relay.requestLog.toList()}]"
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
