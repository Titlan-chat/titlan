// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 5d-3 (finding F-C, v0.1.0-rc.1 §8): the release TLS trust path depends on
 * rustls-platform-verifier's Kotlin component being packaged in the app. The
 * debug suites cannot exercise the handshake itself (they run under the CI
 * test anchor), so this pins the packaging; release-checklist §0 proves the
 * handshake on a device.
 */
@RunWith(AndroidJUnit4::class)
class PlatformTrustTest {

    @Test
    fun verifierComponentIsPackaged() {
        // Throws ClassNotFoundException when the component is absent (rc.1).
        Class.forName("org.rustls.platformverifier.CertificateVerifier")
    }

    @Test
    fun nativeInitSucceedsAndIsIdempotent() {
        val context = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()
        org.junit.Assert.assertTrue(app.titlan.core.PlatformTrust.nativeInit(context))
        org.junit.Assert.assertTrue(app.titlan.core.PlatformTrust.nativeInit(context))
    }
}
