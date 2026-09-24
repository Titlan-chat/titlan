// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.core

import android.content.Context

/**
 * Release TLS trust bootstrap (5d-3, PV-D2). rustls-platform-verifier's
 * Android backend must be handed the application [Context] once, before any
 * relay connection; otherwise every connection carrying no per-conversation
 * pin — the production default — fails inside the TLS handshake (finding
 * F-C, v0.1.0-rc.1). The Kotlin half of the verifier
 * (`org.rustls.platformverifier`) ships as an AAR pinned to the locked
 * support crate (PV-D1a); the Rust half is the JNI export
 * `Java_app_titlan_core_PlatformTrust_nativeInit` in tezca-core.
 * Idempotent; logs nothing (INV-1).
 */
object PlatformTrust {
    init {
        System.loadLibrary("tezca_core")
    }

    /** True once the verifier holds the app context; false is fatal at startup. */
    @JvmStatic
    external fun nativeInit(context: Context): Boolean
}
