// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import app.titlan.pairing.PairingScreen

/**
 * 4b-2 minimal functional UI: the pairing screen (frozen design scope note —
 * machinery + minimal functional UI; polished Compose surfaces are 4b-3).
 * Everything here stays UI-only — protocol and crypto live in tezca-core
 * behind UniFFI bindings (A3).
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    PairingScreen()
                }
            }
        }
    }
}
