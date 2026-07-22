// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.system.Os
import android.view.WindowManager
import app.titlan.core.AppCore

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
        // Debug-only TLS pin bridge (device checklist f, maintainer-ratified
        // FLAG-A option a): must run BEFORE any core touch — the engine's
        // HTTP client captures the env at first open. Statically pinned
        // (shape, single-sourcing, and gate-before-core-init line order)
        // by scripts/check-invariants.sh §8. Dead branch in release
        // (DEBUG = false; the release .so carries no anchor code either).
        if (BuildConfig.DEBUG) exportDebugRelayPin()
        // Capture the app context for the single process-wide core (A3). Opening
        // is still lazy — first pairing/sync call opens the encrypted store.
        AppCore.init(this)
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

    /**
     * Exports the VM relay TLS pin from the [DEBUG_RELAY_PIN_PROP] system
     * property (set via `adb shell setprop`) into `TEZCA_TEST_RELAY_PIN`,
     * the exact env contract the feature-gated test anchor reads and the
     * one [TitlanTestRunner] fills for the instrumented suites. Read via
     * `getprop` — no hidden-API reflection, no added dependency. Unset or
     * blank is a silent no-op; the value is key-shaped hex and is NEVER
     * logged (INV-1). A genuine Os.setenv failure is deliberately left
     * loud rather than masked as a TLS mystery (debug builds only).
     */
    private fun exportDebugRelayPin() {
        val pin = runCatching {
            val proc = Runtime.getRuntime().exec(arrayOf("getprop", DEBUG_RELAY_PIN_PROP))
            val out = proc.inputStream.bufferedReader().use { it.readText() }
            proc.waitFor()
            out
        }.getOrNull()?.trim()
        if (!pin.isNullOrEmpty()) Os.setenv("TEZCA_TEST_RELAY_PIN", pin, true)
    }

    companion object {
        /** Debug-only system property carrying the VM relay TLS pin (hex). */
        private const val DEBUG_RELAY_PIN_PROP = "debug.titlan.relay-pin"
    }
}
