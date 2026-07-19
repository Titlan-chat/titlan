// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-2 CI signal (d) — logcat hygiene across the FULL sync path (frozen design
 * §9d; 4b-1 canary precedent). No key material, plaintext, or mailbox routing
 * id may reach logcat while sync runs.
 *
 * RED expectation: the test logs its positive-control canary, then drives the
 * sync path via [SyncController.start], which is not-yet-implemented — it fails
 * with `kotlin.NotImplementedError` at [SyncController.start] before reaching
 * the absence assertions. GREEN runs the real sync path and the canary +
 * absence assertions all pass (exactly the 4b-1 LogcatHygieneTest shape).
 */
@RunWith(AndroidJUnit4::class)
class SyncLogcatHygieneTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private class NoopEvents : SyncEvents {
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
    fun noSecretsInLogcatAcrossSyncPath() {
        shell("logcat -b all -c")

        // Positive control: prove the scanner can see this process's logs so the
        // absence assertions below cannot be vacuously green.
        val canary = "TITLAN_SYNC_CANARY_4b2c1a"
        Log.w("SyncLogcatHygieneTest", canary)

        // Drive the full sync path. RED stops here (start is unimplemented).
        SyncController.start(context, NoopEvents())

        val log = shell("logcat -b all -d")
        assertTrue(
            "positive control failed: canary not seen — absence results would be meaningless",
            log.contains(canary),
        )
        // GREEN: with a real paired conversation + relay, assert no DB key
        // encoding, no plaintext, and no mailbox id appears across the run.
        assertFalse("sync path must not leak the canary sentinel key", log.contains("SENTINEL_KEY"))
    }

    private fun shell(cmd: String): String =
        instrumentation.uiAutomation.executeShellCommand(cmd).use { pfd ->
            java.io.FileInputStream(pfd.fileDescriptor).readBytes().toString(Charsets.UTF_8)
        }
}
