// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import android.os.Bundle
import android.system.Os
import androidx.test.runner.AndroidJUnitRunner

/**
 * Instrumented-suite runner: exports the CI relay pin
 * (`-Pandroid.testInstrumentationRunnerArguments.tezcaRelayPin=<hex sha256 of
 * the relay's leaf cert DER>`, see ci.yml) as `TEZCA_TEST_RELAY_PIN` in the
 * app process BEFORE the Application (and therefore the core) is created.
 *
 * The debug .so's feature-gated trust anchor (tezca-core ws/pin.rs) reads
 * exactly this variable; release .so builds contain no anchor code, so this
 * runner — test-harness only, never packaged in the app APK — is the sole
 * bridge. Locally, running without the argument simply leaves the anchor
 * dormant (relay-touching suites then need a --plain-http ws:// relay or fail
 * at connect, never silently trust anything).
 */
class TitlanTestRunner : AndroidJUnitRunner() {
    override fun onCreate(arguments: Bundle?) {
        arguments?.getString("tezcaRelayPin")?.takeIf { it.isNotBlank() }?.let { pin ->
            Os.setenv("TEZCA_TEST_RELAY_PIN", pin.trim(), true)
        }
        super.onCreate(arguments)
    }
}
