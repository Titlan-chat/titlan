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
import app.titlan.core.AppCore
import app.titlan.pairing.PairingScreen
import app.titlan.sync.SyncController

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
        // Launch-time receive-sync (4b2-WO-launch-sync, device checklist f): if
        // the store already holds a paired conversation, start SyncService so a
        // process death no longer leaves the app permanently non-syncing. UI
        // stays PairingScreen (navigation/polish is 4b-3). Off the main thread —
        // the store-existence check opens SQLCipher when a store is present, well
        // past ANR budget (mirrors SyncService's own off-main core touch). The
        // application context + the AppCore/SyncController singletons retain no
        // Activity reference. This never runs pre-unlock at BFU: MainActivity is
        // not directBootAware, so it is unresolvable until first unlock — the
        // SyncService §2 isUserUnlocked gate stays the sole unlock gate, and
        // SyncController.start here is the same entry as the pairing path.
        val appContext = applicationContext
        Thread({
            if (AppCore.hasPairedConversation()) SyncController.start(appContext)
        }, "titlan-launch-sync").start()
    }
}
