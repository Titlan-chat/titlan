// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-2 positive control (frozen design §1/§6/§7): the receive-sync foreground
 * service is declared in the MERGED manifest with a foregroundServiceType and
 * the sync permissions are requested.
 *
 * Reads what the OS actually enforces (post-manifest-merger [PackageManager]),
 * NOT the source XML. This is genuinely reachable in the RED commit — the
 * manifest declaration lands with the red — so it is PREDICTED TO PASS, the
 * way BackupDisabledTest passed in the 4b-1 red (it proves the instrumented
 * harness runs and the declaration is real, so the failing suites below are
 * failing on logic, not a broken harness).
 */
@RunWith(AndroidJUnit4::class)
class SyncManifestTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun syncServiceDeclaredWithSpecialUseForegroundType() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_SERVICES.toLong()),
        )
        val service = info.services?.firstOrNull { it.name.endsWith(".sync.SyncService") }
        assertNotNull("SyncService must be declared in the merged manifest", service)
        assertEquals(
            "SyncService must not be exported",
            false,
            service!!.exported,
        )
        assertTrue(
            "SyncService must declare a specialUse foregroundServiceType " +
                "(frozen design §6 default until remoteMessaging is ratified)",
            service.foregroundServiceType and
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE != 0,
        )
    }

    @Test
    fun syncPermissionsRequested() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()),
        )
        val requested = info.requestedPermissions?.toSet() ?: emptySet()
        for (perm in listOf(
            "android.permission.INTERNET",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
            "android.permission.POST_NOTIFICATIONS",
        )) {
            assertTrue("missing requested permission: $perm", perm in requested)
        }
    }
}
