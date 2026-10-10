// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.UserManager
import app.titlan.R

/**
 * The always-on receive-sync foreground service (frozen design §1, §7). Thin
 * shell only: process lifetime + the persistent notification + starting the
 * tezca-core sync engine via [SyncController]. No protocol logic (A3).
 *
 * The notification is deliberately content-free (frozen design §7): fixed text
 * (`R.string.sync_notification_title`), zero metadata, zero dynamic state, `VISIBILITY_SECRET`
 * (hidden on the lock screen), and the lowest platform-honored importance
 * (`IMPORTANCE_MIN`, no sound/peek). `foregroundServiceType` is declared in the
 * manifest as `specialUse` (frozen design §6 default until remoteMessaging is
 * ratified).
 */
class SyncService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Frozen §2 at EVERY entry point (C2-D2): a sticky revival reaches
        // here without passing SyncController.start's gate. With the device
        // locked, CE storage is sealed — decline cleanly per §2: stop before
        // going foreground (no notification; stopping within onStartCommand
        // also clears the startForeground obligation, so no crash) and return
        // NOT_STICKY (no revival spin against sealed storage). Nothing is
        // logged (INV-1). The app layer retries on ACTION_USER_UNLOCKED (4b-3).
        // Either way the start's foreground obligation is settled here, and
        // SyncController.stop waits for exactly that before stopService (F-N).
        val userManager = getSystemService(UserManager::class.java)
        if (userManager != null && !userManager.isUserUnlocked) {
            stopSelf(startId)
            SyncController.onForegroundSettled()
            return START_NOT_STICKY
        }
        ensureChannel()
        startForeground(
            NOTIFICATION_ID,
            buildNotification(),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
        )
        SyncController.onForegroundSettled()
        // Now in the foreground: start the core sync engine (frozen §1) — off
        // the main thread, because the first start opens SQLCipher and may
        // generate the device identity (Kyber keygen), well past ANR budget.
        // Racing starts are safe: AppCore.get is synchronized and core start
        // is idempotent (rehydrates from SQLCipher).
        Thread({ SyncController.onServiceForegrounded() }, "titlan-sync-start").start()
        // Rehydrates from SQLCipher on restart; STICKY so the OS revives it.
        return START_STICKY
    }

    private fun ensureChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.sync_notification_title),
            NotificationManager.IMPORTANCE_MIN,
        ).apply {
            setShowBadge(false)
            lockscreenVisibility = Notification.VISIBILITY_SECRET
            enableLights(false)
            enableVibration(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.sync_notification_title))
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setOngoing(true)
            .setShowWhen(false)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()

    companion object {
        /** Notification channel id for the persistent FGS notification. */
        const val CHANNEL_ID = "titlan_sync"

        /** Fixed FGS notification id. */
        private const val NOTIFICATION_ID = 1

        // The fixed FGS notification text (frozen design §7: zero metadata,
        // zero dynamic state, VISIBILITY_SECRET, lowest platform-honored
        // importance) is R.string.sync_notification_title, whose value is the
        // former literal, unchanged (5e-1, CU-D9; check-invariants family 20e).
    }
}
