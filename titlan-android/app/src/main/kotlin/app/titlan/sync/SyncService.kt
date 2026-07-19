// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * The always-on receive-sync foreground service (frozen design §1, §7).
 * PRODUCTION HOME, stubbed in the 4b-2 RED commit.
 *
 * Thin shell only: process lifetime + the persistent notification + feeding
 * connectivity signals into the tezca-core sync engine. No protocol logic
 * (A3). The 4b-2 GREEN commit implements [onStartCommand] to call
 * `startForeground` with the fixed [NOTIFICATION_TEXT] notification and start
 * the core engine via [SyncController].
 *
 * foregroundServiceType is declared in the manifest; the remoteMessaging vs
 * specialUse decision is the frozen design §6 red-phase verification (a–d),
 * recorded in the design doc. Until ratified the manifest declares
 * `specialUse` with the required PROPERTY justification.
 */
class SyncService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int =
        TODO("4b-2 green: startForeground with the §7 notification; start core sync engine")

    companion object {
        /** Notification channel id for the persistent FGS notification. */
        const val CHANNEL_ID = "titlan_sync"

        /**
         * Fixed FGS notification text (frozen design §7): zero metadata, zero
         * dynamic state, VISIBILITY_SECRET, lowest platform-honored importance.
         */
        const val NOTIFICATION_TEXT = "Titlan sync active"
    }
}
