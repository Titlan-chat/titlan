// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import app.titlan.pairing.PairingCoordinator
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-2 CI signal (c) — §10.7 recovery via derived mailboxes (frozen design §8/
 * §9c). Four scenarios drive the recovery machinery against the real CI relay
 * (built + run on the runner host, reached at 10.0.2.2):
 *
 *  1. single total-loss  — relay restart mid-conversation; both clients
 *     recover via derived mailboxes; messages flow.
 *  2. double-restart desync — A at n+1, B at n; windowing converges.
 *  3. forced offset ≥ W  — exhaustion asserts `conversation-needs-repair`.
 *  4. 429-pacing negative — relay 429s NEVER count toward the 3-cycle
 *     exhaustion; the client paces with backoff.
 *
 * Each scenario first needs an established conversation, so each reaches
 * not-yet-implemented production code at [PairingCoordinator.createOffer] in
 * RED and fails with `kotlin.NotImplementedError`. The recovery assertions
 * (and the relay leg) become live in GREEN.
 */
@RunWith(AndroidJUnit4::class)
class RecoveryTest {

    private fun establishConversation(): ByteArray {
        val offer = PairingCoordinator.createOffer()
        return PairingCoordinator.acceptScannedOffer(offer.bytes)
    }

    @Test
    fun singleTotalLossRecoversViaDerivedMailboxes() {
        val conversationId = establishConversation()
        // GREEN: send, restart the relay (total routing loss), assert both sides
        // recreate derived inboxes, converge, and messages resume flowing.
        assertTrue(conversationId.isNotEmpty())
    }

    @Test
    fun doubleRestartDesyncConverges() {
        val conversationId = establishConversation()
        // GREEN: drive A to generation n+1 while B is at n; assert the ±W window
        // converges both onto max(g) and rotation retires the derived mailboxes.
        assertTrue(conversationId.isNotEmpty())
    }

    @Test
    fun forcedOffsetBeyondWindowNeedsRepair() {
        val conversationId = establishConversation()
        // GREEN: force a relative generation offset ≥ W (=4); assert the
        // conversation-needs-repair event fires (CoreError::ConversationNeedsRepair).
        assertTrue(conversationId.isNotEmpty())
    }

    @Test
    fun pacing429sDoNotCountTowardExhaustion() {
        val conversationId = establishConversation()
        // GREEN (negative assertion): drive the relay to 429 during recovery;
        // assert the 3-cycle exhaustion counter does NOT advance and the client
        // paces with backoff instead of surfacing needs-repair.
        assertTrue(conversationId.isNotEmpty())
    }
}
