// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import android.content.Context

/**
 * App-facing entry point to receive-sync (frozen design §1). PRODUCTION HOME,
 * stubbed in the 4b-2 RED commit.
 *
 * The sync engine itself lives in tezca-core over UniFFI (A3); this controller
 * and [SyncService] are the thin Kotlin shell that owns process lifetime, the
 * persistent notification, and connectivity signals fed into core. No protocol
 * logic lives in Kotlin.
 *
 * The 4b-2 GREEN commit implements [start]/[stop] to launch [SyncService] as a
 * foreground service and wire the core [SyncEvents] callbacks. Today every
 * entry point is `TODO()` — the instrumented acceptance tests reach these and
 * fail at not-yet-implemented production code (4b-1 precedent).
 */
object SyncController {

    /**
     * Starts receive-sync: launches the foreground [SyncService] (gated on
     * [android.os.UserManager.isUserUnlocked] per frozen design §2) and
     * subscribes every conversation, delivering to [events].
     *
     * Idempotent and cheap once implemented (frozen design §1: the engine
     * rehydrates entirely from SQLCipher; no in-memory state is load-bearing
     * across restarts).
     */
    fun start(context: Context, events: SyncEvents): Unit =
        TODO("4b-2 green: gate on isUserUnlocked, start SyncService, wire core SyncEngine callbacks")

    /** Stops all sync tasks and tears the foreground service down. */
    fun stop(context: Context): Unit =
        TODO("4b-2 green: stop SyncService and core sync tasks")

    /** True while the foreground [SyncService] is running. */
    fun isRunning(context: Context): Boolean =
        TODO("4b-2 green: reflect SyncService running state")
}
