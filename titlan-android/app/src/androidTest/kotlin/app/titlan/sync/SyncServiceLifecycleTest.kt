// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-2 CI signal (b) — FGS lifecycle (frozen design §1/§7/§9b).
 *
 * The receive-sync service starts (gated per §2), posts the fixed §7
 * persistent notification, survives backgrounding, and an airplane-mode round
 * trip queues and delivers on reconnect. Driven through [SyncController] (not a
 * raw `startForegroundService`) so the failure lands at production logic, not
 * at a foreground-start-timeout crash.
 *
 * RED expectation: both methods fail with `kotlin.NotImplementedError` at
 * [SyncController.start] — the sync engine shell is unimplemented.
 */
@RunWith(AndroidJUnit4::class)
class SyncServiceLifecycleTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    /** Collects callbacks; unused in RED (start throws before any fire). */
    private class RecordingEvents : SyncEvents {
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

    @Test
    fun startPostsPersistentNotificationAndSurvivesBackground() {
        SyncController.start(context, RecordingEvents())

        // GREEN: assert the §7 notification is posted (fixed text, IMPORTANCE_MIN,
        // VISIBILITY_SECRET) and still present after the app is backgrounded.
        assertTrue("sync must be running after start", SyncController.isRunning(context))
    }

    @Test
    fun airplaneModeQueuesAndDeliversOnReconnect() {
        SyncController.start(context, RecordingEvents())

        // GREEN: toggle airplane mode via shell, send while offline (queued),
        // restore connectivity, and assert delivery + durable persistence with
        // the app backgrounded. Notification absence is NOT a failure (§7).
        assertTrue("sync must be running after start", SyncController.isRunning(context))
    }
}
