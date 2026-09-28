// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import android.content.Context

/**
 * What both roles do once a pairing has completed (5e-1, CU-D5/CU-D8):
 * refresh the store's conversation list, start receive-sync with the UI sink
 * ([ConversationStore.events]) through the one canonical entry
 * (SyncController.start), and hand back the key the screen navigates to.
 * Never called from a sync callback (CU-D3 callback rule).
 */
object PairingCompletion {
    suspend fun complete(context: Context, conversationId: ByteArray): ConversationKey = TODO()
}
