// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import android.content.Context
import android.content.Intent
import android.os.UserManager
import app.titlan.core.AppCore
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
        context.startForegroundService(Intent(context, SyncService::class.java))
        running.set(true)
    }

    /**
     * Invoked by [SyncService] once it is in the foreground: begins the core
     * sync engine wired to the [SyncEvents] captured by [start]. Kept off the
     * Intent because [SyncEvents] is a live callback, not Parcelable.
     */
    internal fun onServiceForegrounded() {
        pendingEvents?.let { AppCore.get().startSync(it) }
    }

    /** Stops all sync tasks and tears the foreground service down. */
    fun stop(context: Context) {
        AppCore.get().stopSync()
        context.stopService(Intent(context, SyncService::class.java))
        running.set(false)
        pendingEvents = null
    }

    /** True while the foreground [SyncService] is running. */
    fun isRunning(context: Context): Boolean = running.get()
}
