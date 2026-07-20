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
