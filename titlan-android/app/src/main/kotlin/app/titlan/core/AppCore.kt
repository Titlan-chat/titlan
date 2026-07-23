// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.core

import android.content.Context
import app.titlan.BuildConfig
import app.titlan.crypto.DbKeyManager
import java.io.File

/**
 * Process-wide holder for the single opened [CoreClient] (one identity/DB per
 * device, A3). [init] captures the application context in
 * [app.titlan.TitlanApp.onCreate]; [get] lazily opens the encrypted store on
 * first use with the DB key from [DbKeyManager] and the build's default relay
 * ([BuildConfig.RELAY_URL]; INV-5: per-conversation relay still overrides). The
 * app never opens the core anywhere else — [app.titlan.pairing.PairingCoordinator]
 * and [app.titlan.sync.SyncController] both route through here so there is
 * exactly one engine per process.
 */
object AppCore {

    @Volatile
    private var appContext: Context? = null

    /**
     * The single process-wide opened core, cached for the process lifetime and
     * never re-opened (see [get]).
     *
     * CONTRACT: the backing SQLCipher file (`filesDir/`[DB_FILE]) must NEVER be
     * deleted or replaced while the process is alive. Unlinking it out from
     * under this open connection makes the next WRITE through it fail
     * `SQLITE_READONLY_DBMOVED` ("attempt to write a readonly database"), while
     * READS still return stale data from the open inode — so the fault can hide
     * behind reads until a write hits it (CI #64/#65 read-masked it as "Query
     * returned no rows"; the per-offer-prekey INSERT surfaced it in #66; see
     * `~/4b2-readonly-invest.md`). Instrumented tests that need a fresh store
     * MUST use their own DB paths and leave `filesDir/`[DB_FILE] alone.
     */
    @Volatile
    private var client: CoreClient? = null

    /** Captures the application context. Called once from `TitlanApp.onCreate`. */
    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /** The opened core, creating it (and the device identity) on first call. */
    fun get(): CoreClient {
        client?.let { return it }
        val ctx = requireNotNull(appContext) {
            "AppCore.init must run first (TitlanApp.onCreate)"
        }
        return synchronized(this) {
            client ?: open(ctx).also { client = it }
        }
    }

    /**
     * True iff the encrypted store already exists on disk AND holds at least one
     * conversation. A fresh install (no [DB_FILE]) returns false WITHOUT opening
     * or creating anything — identity stays lazily minted at first pairing, so a
     * never-paired app is untouched (4b2-WO-launch-sync: zero conversations =
     * current behavior). When the file exists this opens SQLCipher via [get]
     * (already initialized — no new identity) and reads [CoreClient.listConversations];
     * heavy, so call off the main thread. The existence probe uses exactly the
     * path [get] would open.
     */
    fun hasPairedConversation(): Boolean {
        val ctx = requireNotNull(appContext) {
            "AppCore.init must run first (TitlanApp.onCreate)"
        }
        if (!File(ctx.filesDir, DB_FILE).exists()) return false
        return get().listConversations().isNotEmpty()
    }

    private fun open(appContext: Context): CoreClient {
        val key = DbKeyManager(appContext).getOrCreateDbKey()
        try {
            val dbPath = File(appContext.filesDir, DB_FILE).path
            val core = CoreClientFactory.open(dbPath, key, BuildConfig.RELAY_URL)
            if (!core.isInitialized()) core.initializeIdentity()
            return core
        } finally {
            // Zeroize our copy of the raw key; core keeps its own (INV-1).
            key.fill(0)
        }
    }

    private const val DB_FILE = "titlan.db"
}
