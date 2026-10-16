// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * 5e-2 red suite (gate E-5, finding F-J): no core failure escapes a store
 * coroutine or a UI coroutine; it becomes the storage-error state, which is
 * shown, never logged (INV-1).
 *
 * The failure is real and needs no seam in production code: on the JVM,
 * `TitlanApp.onCreate` never runs, so `AppCore` is never initialised and both
 * `AppCore.get()` and `AppCore.hasPairedConversation()` throw at the core
 * boundary.
 *
 * RED expectation: all six tests fail at their first call or assertion — the
 * store and [OfferWatcher] calls throw `IllegalArgumentException`,
 * [ConversationStore.probePaired] throws `NotImplementedError` at its stub, and
 * the coroutine [ConversationStore.onMessageArrived] launches reaches the
 * default uncaught-exception handler. GREEN turns them green.
 */
class CoreFailureTest {

    private val key = ConversationKey("00112233445566778899aabbccddeeff")
    private val uncaught = AtomicReference<Throwable?>(null)
    private var previousHandler: Thread.UncaughtExceptionHandler? = null

    @Before
    fun captureUncaught() {
        previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, e -> uncaught.compareAndSet(null, e) }
    }

    @After
    fun restoreUncaught() {
        Thread.setDefaultUncaughtExceptionHandler(previousHandler)
    }

    @Test
    fun refreshConversationsKeepsTheListOnCoreFailure() = runBlocking {
        val before = ConversationStore.conversations.value
        val keys = ConversationStore.refreshConversations()
        assertEquals(before, keys)
        assertEquals(before, ConversationStore.conversations.value)
        assertTrue("a core failure must raise the storage-error state", ConversationStore.storageError.value)
    }

    @Test
    fun refreshMessagesKeepsTheMessagesOnCoreFailure() = runBlocking {
        val before = ConversationStore.messages(key).value
        val list = ConversationStore.refreshMessages(key)
        assertEquals(before, list)
        assertEquals(before, ConversationStore.messages(key).value)
        assertTrue("a core failure must raise the storage-error state", ConversationStore.storageError.value)
    }

    @Test
    fun sendReportsFailedOnCoreFailure() = runBlocking {
        val outcome = ConversationStore.send(key, "core failure canary")
        assertEquals(SendOutcome.Failed, outcome)
        assertTrue("a core failure must raise the storage-error state", ConversationStore.storageError.value)
    }

    @Test
    fun probePairedIsNullOnCoreFailure() = runBlocking {
        assertNull(ConversationStore.probePaired())
        assertTrue("a core failure must raise the storage-error state", ConversationStore.storageError.value)
    }

    @Test
    fun messageArrivedNeverReachesTheUncaughtHandler() {
        ConversationStore.onMessageArrived(key.bytes, ByteArray(16))
        val deadline = System.currentTimeMillis() + 2_000L
        while (uncaught.get() == null && System.currentTimeMillis() < deadline) Thread.sleep(50L)
        assertNull("a store coroutine must not throw into the uncaught handler", uncaught.get())
        assertTrue("a core failure must raise the storage-error state", ConversationStore.storageError.value)
    }

    @Test
    fun offerWatcherTreatsAFailedPollAsNothingYet() = runBlocking {
        val result = OfferWatcher.awaitNewConversation(
            before = emptySet(),
            deadlineEpochMillis = System.currentTimeMillis() + 500L,
            pollMillis = 50L,
        )
        assertNull(result)
    }
}
