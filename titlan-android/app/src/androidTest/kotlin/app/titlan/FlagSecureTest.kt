// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-1 acceptance (maintainer-confirmed): FLAG_SECURE is always-on for MVP —
 * every activity window, no toggle, no debug exemption. Suppresses
 * screenshots and recents thumbnails (INV-1's screen surface).
 *
 * Green plan (4b-1): a TitlanApp [android.app.Application] registers
 * ActivityLifecycleCallbacks that set FLAG_SECURE in onActivityPreCreated
 * for EVERY activity — central enforcement, so activities added in 4b-3
 * cannot opt out by omission. This test asserts the resulting window state.
 */
@RunWith(AndroidJUnit4::class)
class FlagSecureTest {

    @Test
    fun mainActivityWindowIsSecure() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val flags = activity.window.attributes.flags
                assertTrue(
                    "FLAG_SECURE must be set on every activity window (always-on, no toggle)",
                    flags and WindowManager.LayoutParams.FLAG_SECURE != 0,
                )
            }
        }
    }
}
