// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.view.WindowManager

/**
 * Application entry point. Central FLAG_SECURE enforcement
 * (maintainer-confirmed: always-on for MVP, no toggle, no debug exemption):
 * every activity gets FLAG_SECURE in onActivityPreCreated — before the
 * window is first drawn — so activities added later (4b-3) cannot opt out
 * by omission. Suppresses screenshots and recents thumbnails (INV-1's
 * screen surface).
 */
class TitlanApp : Application() {

    override fun onCreate() {
        super.onCreate()
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityPreCreated(
                activity: Activity,
                savedInstanceState: Bundle?,
            ) {
                activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }

            override fun onActivityCreated(a: Activity, s: Bundle?) = Unit
            override fun onActivityStarted(a: Activity) = Unit
            override fun onActivityResumed(a: Activity) = Unit
            override fun onActivityPaused(a: Activity) = Unit
            override fun onActivityStopped(a: Activity) = Unit
            override fun onActivitySaveInstanceState(a: Activity, s: Bundle) = Unit
            override fun onActivityDestroyed(a: Activity) = Unit
        })
    }
}
