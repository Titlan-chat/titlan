// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import android.content.Context
import android.content.Intent
import android.os.Looper
import android.os.UserManager
import app.titlan.core.AppCore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * App-facing entry point to receive-sync (frozen design §1). The sync engine
 * itself lives in tezca-core over UniFFI (A3); this controller and
 * [SyncService] are the thin Kotlin shell that owns process lifetime, the
 * persistent notification, and connectivity signals fed into core. No protocol
 * logic lives in Kotlin.
 */
object SyncController {

    private val running = AtomicBoolean(false)

    @Volatile
    private var pendingEvents: SyncEvents? = null

    /**
     * Finding F-N: the most recent start's foreground obligation. Counted
     * down by [SyncService] on the main thread the moment `startForeground()`
     * has been called — or the start has been declined (`stopSelf` inside
     * `onStartCommand`, which clears the obligation the same way). [stop]
     * waits on it before `stopService`: Android P+ crashes the process when a
     * service started with `startForegroundService` is stopped while still
     * "waiting for start foreground" (`ForegroundServiceDidNotStartInTimeException`),
     * and nothing else orders a caller's `stopService` after the service's
     * own main-thread `onStartCommand`. A sticky revival has no latch.
     */
    @Volatile
    private var foregroundSettled: CountDownLatch? = null

    /** Upper bound on the wait in [stop]: the platform's own foreground-start budget. */
    private const val FOREGROUND_SETTLE_TIMEOUT_MS = 10_000L

    /**
     * Starts receive-sync: launches the foreground [SyncService] (gated on
     * [UserManager.isUserUnlocked] per frozen design §2 — CE storage is
     * unreadable while the device is locked, so sync must not start), then
     * subscribes every conversation in core, delivering to [events].
     *
     * Idempotent: core rehydrates entirely from SQLCipher, so a second start is
     * cheap and no in-memory state is load-bearing across restarts.
     */
    fun start(context: Context, events: SyncEvents) {
        val userManager = context.getSystemService(UserManager::class.java)
        if (userManager != null && !userManager.isUserUnlocked) {
            // Device-locked (CE storage sealed): do not start. The caller retries
            // on ACTION_USER_UNLOCKED (wired at the app layer, 4b-3).
            return
        }
        pendingEvents = events
        foregroundSettled = CountDownLatch(1)
        context.startForegroundService(Intent(context, SyncService::class.java))
        running.set(true)
    }

    /**
     * Launch-time start (4b2-WO-launch-sync): starts receive-sync with no UI
     * observer, resuming with the inert [DefaultSyncEvents] sink. Since 5e-1
     * MainActivity starts sync with the UI sink
     * ([app.titlan.conversation.ConversationStore]); this form remains for the
     * no-observer case, the same as a START_STICKY
     * revival (C2-D1) and safe for the same reason: core acks the relay only
     * after durable persist (frozen §1), so delivery never depends on an
     * attached observer. This is the SAME entry as the canonical [start] —
     * identical §2 gate, identical foreground-service intent — not a parallel
     * start mechanism.
     */
    fun start(context: Context) = start(context, DefaultSyncEvents)

    /**
     * Invoked by [SyncService] once it is in the foreground: begins the core
     * sync engine wired to the [SyncEvents] captured by [start]. Kept off the
     * Intent because [SyncEvents] is a live callback, not Parcelable.
     *
     * C2-D1: on a START_STICKY revival this is a FRESH process — no [start]
     * ran, so [pendingEvents] is null — yet the §7 notification is already up
     * and must not claim sync that is not running. Sync therefore RESUMES with
     * [DefaultSyncEvents]: core start is idempotent and rehydrates wholly from
     * SQLCipher, and core acks the relay only after durable persist (frozen
     * §1), so delivery stays correct with no live observer. UI observers
     * replace the sink whenever [start] next runs (core callback registration
     * is engine-global and replaced on each start).
     */
    internal fun onServiceForegrounded() {
        synchronized(this) {
            // F-N: a stop that landed between startForeground() and this
            // thread reaching the core must win — otherwise the core engine
            // would start with no service above it. Both paths take this
            // lock, so the order is decided here, once.
            if (!running.get()) return
            AppCore.get().startSync(pendingEvents ?: DefaultSyncEvents)
            running.set(true)
        }
    }

    /**
     * [SyncService] → here, on the main thread, once the latest start's
     * foreground obligation is settled either way (F-N). No latch (a sticky
     * revival, or a start declined before `startForegroundService`): no-op.
     */
    internal fun onForegroundSettled() {
        foregroundSettled?.countDown()
    }

    /**
     * Stops all sync tasks and tears the foreground service down. Waits for
     * the latest start's foreground obligation to settle first (F-N): the
     * service's `onStartCommand` runs on the main thread, so the wait is
     * skipped there (it would deadlock) — no production caller stops from
     * the main thread.
     */
    fun stop(context: Context) {
        awaitForegroundSettled()
        synchronized(this) {
            running.set(false)
            AppCore.get().stopSync()
            context.stopService(Intent(context, SyncService::class.java))
            pendingEvents = null
        }
    }

    private fun awaitForegroundSettled() {
        val latch = foregroundSettled ?: return
        if (Looper.myLooper() != Looper.getMainLooper()) {
            latch.await(FOREGROUND_SETTLE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        }
        foregroundSettled = null
    }

    /** True while the foreground [SyncService] is running. */
    fun isRunning(context: Context): Boolean = running.get()
}

/**
 * Sink for sync resumed WITHOUT a UI observer (START_STICKY revival in a
 * fresh process — C2-D1). Deliberately inert, and that is safe by frozen §1:
 * core acks the relay only after durable persist, so no message depends on an
 * observer being attached; the UI reads the store when it next opens, and its
 * live observers replace this sink via [SyncController.start]. This is a
 * delivery-continuity sink, not a UI decision — since 5e-1 the UI sink is
 * [app.titlan.conversation.ConversationStore], registered at Activity
 * creation and at every pairing completion.
 */
private object DefaultSyncEvents : SyncEvents {
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
