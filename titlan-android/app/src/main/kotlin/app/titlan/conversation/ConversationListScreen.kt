// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.titlan.R
import app.titlan.sync.ConnectionState

/**
 * The conversation list (5e-1, freeze CU-D7): rows in the store's order (most
 * recent first), each labelled with the first 8 hex characters of its key and
 * carrying its connection chip. No last-message preview. Everything shown is
 * read from [ConversationStore] (CU-D3).
 */
@Composable
fun ConversationListScreen(onOpen: (ConversationKey) -> Unit, onPair: () -> Unit) {
    val keys by ConversationStore.conversations.collectAsState()
    val connection by ConversationStore.connection.collectAsState()
    val needsRepair by ConversationStore.needsRepair.collectAsState()

    Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).padding(16.dp)) {
        Text(stringResource(R.string.conversations_title), style = MaterialTheme.typography.titleMedium)
        Button(onClick = onPair) { Text(stringResource(R.string.conversations_pair_device)) }
        LazyColumn {
            items(keys, key = { it.hex }) { key ->
                Column {
                    Row(
                        Modifier.fillMaxWidth().clickable { onOpen(key) }.padding(vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(stringResource(R.string.conversations_row_label, key.shortHex))
                        ConnectionChip(connection[key])
                    }
                    if (needsRepair.contains(key)) {
                        Text(
                            stringResource(R.string.chat_needs_repair),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
    }
}

/**
 * The connection chip shared by the list and the chat header (CU-D6): the
 * five [ConnectionState] values map to five resources, and nothing is shown
 * until the first event for that conversation.
 */
@Composable
fun ConnectionChip(state: ConnectionState?) {
    val label = when (state) {
        null -> return
        ConnectionState.CONNECTING -> R.string.chat_state_connecting
        ConnectionState.ONLINE -> R.string.chat_state_online
        ConnectionState.OFFLINE -> R.string.chat_state_offline
        ConnectionState.BACKOFF -> R.string.chat_state_backoff
        ConnectionState.RECOVERING -> R.string.chat_state_recovering
    }
    Text(stringResource(label), style = MaterialTheme.typography.labelMedium)
}
