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
import app.titlan.conversation.ConversationStore
import app.titlan.core.AppCore
import app.titlan.sync.SyncController

/**
 * The single Activity (5e-1, freeze CU-D2): it hosts [TitlanRoot], which
 * decides the start destination from the store and navigates between the
 * conversation list, the chat screen and the pairing screen in Compose state.
 * One Activity keeps the central FLAG_SECURE enforcement's coverage (TM-C5).
 * Everything here stays UI-only — protocol and crypto live in tezca-core
 * behind UniFFI bindings (A3).
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    TitlanRoot()
                }
            }
        }
        // Launch-time receive-sync (4b2-WO-launch-sync, device checklist f; 5e-1
        // CU-D8): if the store already holds a paired conversation, start
        // SyncService with the UI sink (ConversationStore.events), so a process
        // death no longer leaves the app non-syncing and the screens observe
        // what arrives. Off the main thread — the store-existence check opens
        // SQLCipher when a store is present, well past ANR budget (mirrors
        // SyncService's own off-main core touch). The application context + the
        // AppCore/SyncController/ConversationStore singletons retain no Activity
        // reference. This never runs pre-unlock at BFU: MainActivity is not
        // directBootAware, so it is unresolvable until first unlock — the
        // SyncService §2 isUserUnlocked gate stays the sole unlock gate, and
        // SyncController.start here is the same entry as the pairing path.
        val appContext = applicationContext
        Thread({
            if (AppCore.hasPairedConversation()) SyncController.start(appContext, ConversationStore.events)
        }, "titlan-launch-sync").start()
    }
}
