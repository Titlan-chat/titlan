// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import android.content.pm.ApplicationInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-1 acceptance (maintainer-confirmed backup posture): backup fully
 * disabled — the wrapped DB key cannot leave the device's Keystore, so any
 * extracted copy of app data is a pure leak surface.
 *
 * Reads the MERGED manifest via the installed package's [ApplicationInfo]
 * (post-manifest-merger, what the OS actually enforces) — deliberately NOT
 * the source XML, which the merger or a library manifest could override.
 * The dataExtractionRules *content* (cloud-backup AND device-transfer both
 * excluded) is not runtime-readable; the green commit adds an aapt2
 * xmltree check of the built APK to CI for that half.
 */
@RunWith(AndroidJUnit4::class)
class BackupDisabledTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun mergedManifestDisablesBackup() {
        val appInfo = context.applicationInfo
        assertEquals(
            "allowBackup must be false in the MERGED manifest",
            0,
            appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP,
        )
        assertNull(
            "no backup agent may be injected by any manifest source",
            appInfo.backupAgentName,
        )
    }
}
