// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.titlan.R
import app.titlan.sync.ConnectionState

/**
 * The conversation list (5e-1, freeze CU-D7; 1.1, L-D4/L-D5): rows in the
 * store's order — most recent activity first — each showing its label when
 * set (with the first 8 hex characters of its key as a subtitle, the one
 * stable identity until safety numbers arrive at P7) or the hex form alone,
 * its last-activity time, and its connection chip. No last-message preview.
 * A long-press opens the label dialog. Everything shown is read from
 * [ConversationStore] (CU-D3).
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun ConversationListScreen(onOpen: (ConversationKey) -> Unit, onPair: () -> Unit) {
    val rows by ConversationStore.rows.collectAsState()
    val connection by ConversationStore.connection.collectAsState()
    val needsRepair by ConversationStore.needsRepair.collectAsState()
    val storageError by ConversationStore.storageError.collectAsState()
    // INV-1: which row is being renamed is a key, never label text; memory only.
    var editing by remember { mutableStateOf<ConversationRow?>(null) }

    Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).padding(16.dp)) {
        Text(stringResource(R.string.conversations_title), style = MaterialTheme.typography.titleMedium)
        // 5e-2 (finding F-J): a failed store read lands here, so the banner shows here too.
        if (storageError) Text(stringResource(R.string.chat_storage_error))
        Button(onClick = onPair) { Text(stringResource(R.string.conversations_pair_device)) }
        LazyColumn {
            items(rows, key = { it.key.hex }) { row ->
                val key = row.key
                Column {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .combinedClickable(
                                onLongClickLabel = stringResource(R.string.label_rename_action),
                                onLongClick = { editing = row },
                                onClick = { onOpen(key) },
                            )
                            .padding(vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(conversationTitle(row, key))
                            if (row.label != null) {
                                Text(
                                    stringResource(R.string.conversations_row_label, key.shortHex),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            ConnectionChip(connection[key])
                            Text(
                                MessageTime.formatNow(row.lastActivityEpochSeconds),
                                style = MaterialTheme.typography.labelSmall,
                            )
                        }
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

    editing?.let { row ->
        LabelDialog(key = row.key, current = row.label, onDismiss = { editing = null })
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
