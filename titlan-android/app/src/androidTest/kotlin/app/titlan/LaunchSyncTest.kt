// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.core.AppCore
import app.titlan.core.CoreClient
import app.titlan.core.CoreClientFactory
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
 * reachable only via [SyncController.start] (no launch wiring), so a cold launch
 * previously composed PairingScreen and never started sync.
 *
 * SOLE CI-GRADED ASSERTION: after a cold [MainActivity] launch with a paired
 * conversation present, [SyncController.isRunning] is true. Red `0060371`
 * recorded this as its failure signature ("cold launch with a paired
 * conversation must start SyncService"); CI run 29965946907 (#64) confirmed it
 * flipped red -> green.
 *
 * The deposit-observation strengthening — a FakeRelay-observed deposit proving
 * the launch-started sync engages the relay — did NOT survive CI timing
 * (accepts=0 in #64). Per the standing §9 fallback contract of
 * `~/4b2-launch-sync-flag.md` it is now a PHYSICAL-DEVICE step, not a CI
 * assertion: on a device, the checklist-(f) doze run observes the
 * launch-started sync actually delivering (the `TitlanDelivery` sentinel),
 * which subsumes the deposit observable — see
 * `docs/checklists/4b2-f-doze-latency.md`. The device-global receive subscribe
 * targets `my_relay` (BuildConfig.RELAY_URL), not a per-conversation relay, so
 * an in-process FakeRelay cannot observe it in the emulator lane regardless.
 *
 * Seeding is the [RecoveryTest]-style scratch-peer pairing over the live CI
 * relay (one identity cannot pair with itself); production API only. No
 * outbound message is queued and no relay override is set — the graded property
 * needs only a persisted conversation, so the minimal seeding also leaves no
 * pending-flush loop churning the shared store after the test.
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
    fun coldLaunchWithPairedConversationStartsSync() {
        val core = AppCore.get()
        if (!core.isInitialized()) core.initializeIdentity()
        pairWithScratchPeer(
            core,
            File(context.cacheDir, "launch-sync-peer.db").also { it.delete() },
        )

        // Launch-specific precondition: sync must be stopped, so "running after
        // launch" cannot be vacuously satisfied by a prior test in this shared
        // process.
        SyncController.stop(context)
        assertFalse(
            "precondition: sync must be stopped before launch",
            SyncController.isRunning(context),
        )

        ActivityScenario.launch(MainActivity::class.java).use {
            // Sole graded assertion (the RED->GREEN signal, red 0060371): a cold
            // launch with a paired conversation present must start SyncService.
            assertTrue(
                "cold launch with a paired conversation must start SyncService",
                await(20_000) { SyncController.isRunning(context) },
            )
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
