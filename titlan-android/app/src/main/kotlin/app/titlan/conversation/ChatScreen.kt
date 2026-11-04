// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.titlan.R
import kotlinx.coroutines.launch

/**
 * The chat screen (5e-1, freeze CU-D6; 1.1, L-D2/L-D5): header with the
 * conversation title — its label, else the hex form; tapping it opens the
 * label dialog — and connection chip; messages in store order, outgoing right
 * and incoming left, text only, each with one local time (this device's
 * clock on its own side; none for a pre-1.1 message); composer with a text
 * field and Send. No delivery ticks until P6. Everything shown is read from
 * [ConversationStore] (CU-D3).
 *
 * INV-1: the draft lives in memory only and is never part of saved instance
 * state; a stored body is rendered through its decoded form, never from raw
 * bytes; the storage-error detail is never shown.
 */
@Composable
fun ChatScreen(key: ConversationKey, onBack: () -> Unit, onPairAgain: () -> Unit) {
    val messageFlow = remember(key) { ConversationStore.messages(key) }
    val messages by messageFlow.collectAsState()
    val rows by ConversationStore.rows.collectAsState()
    val connection by ConversationStore.connection.collectAsState()
    val needsRepair by ConversationStore.needsRepair.collectAsState()
    val notDelivered by ConversationStore.notDelivered.collectAsState()
    val storageError by ConversationStore.storageError.collectAsState()

    LaunchedEffect(key) { ConversationStore.refreshMessages(key) }

    var draft by remember { mutableStateOf("") }
    var renaming by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    val row = rows.firstOrNull { it.key == key }

    Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onBack) { Text(stringResource(R.string.nav_back)) }
            Text(
                conversationTitle(row, key),
                modifier = Modifier
                    .weight(1f)
                    .clickable(onClickLabel = stringResource(R.string.label_rename_action)) { renaming = true },
            )
            ConnectionChip(connection[key])
        }
        if (renaming) {
            LabelDialog(key = key, current = row?.label, onDismiss = { renaming = false })
        }

        if (storageError) {
            Text(
                stringResource(R.string.chat_storage_error),
                modifier = Modifier.padding(horizontal = 12.dp),
            )
        }

        if (needsRepair.contains(key)) {
            Column(Modifier.padding(horizontal = 12.dp)) {
                Text(stringResource(R.string.chat_needs_repair))
                Button(onClick = onPairAgain) { Text(stringResource(R.string.chat_pair_again)) }
            }
        }

        if (messages.isEmpty()) {
            // CU-D5 evidence continuity: the empty state is the text the
            // device checklists read after pairing, in either role.
            Box(
                Modifier.weight(1f).fillMaxWidth().padding(horizontal = 24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(stringResource(R.string.chat_empty_paired))
            }
        } else {
            LazyColumn(modifier = Modifier.weight(1f).fillMaxWidth(), state = listState) {
                items(messages, key = { it.id }) { message ->
                    MessageRow(message, notDelivered.contains(message.id))
                }
            }
            LaunchedEffect(messages.size) {
                if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1)
            }
        }

        // CU-D6 send rule (finding F-H mitigation): Send is disabled on a blank
        // draft and on one over the cap, so core is never handed a frame it
        // would persist and then fail to encode.
        val check = ChatBody.admit(draft)
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text(stringResource(R.string.chat_compose_hint)) },
            )
            Button(
                enabled = check is SendCheck.Ok,
                onClick = {
                    val text = draft
                    draft = ""
                    scope.launch {
                        // Rejected or Failed (5e-2, F-J): nothing was queued, so the text comes back.
                        if (ConversationStore.send(key, text) !is SendOutcome.Queued) draft = text
                    }
                },
            ) { Text(stringResource(R.string.chat_send)) }
        }
        if (check is SendCheck.TooLong) {
            Text(
                stringResource(R.string.chat_too_long),
                modifier = Modifier.padding(horizontal = 12.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

/**
 * One message (CU-D6; 1.1 L-D2): a `chat/1` body as its text, any other body
 * as one of the two fixed placeholders — the raw bytes are never rendered —
 * and, below it, the one local time ([MessageTime]; absent for a pre-1.1 row).
 */
@Composable
private fun MessageRow(message: UiMessage, notDelivered: Boolean) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = if (message.incoming) Arrangement.Start else Arrangement.End,
    ) {
        val color = if (message.incoming) {
            MaterialTheme.colorScheme.surfaceVariant
        } else {
            MaterialTheme.colorScheme.primaryContainer
        }
        Column(Modifier.background(color, MaterialTheme.shapes.medium).padding(8.dp)) {
            Text(
                when (val body = message.body) {
                    is DecodedBody.Text -> body.text
                    DecodedBody.Unsupported -> stringResource(R.string.chat_message_unsupported)
                    DecodedBody.Undecodable -> stringResource(R.string.chat_message_undecodable)
                },
            )
            message.epochSeconds?.let { at ->
                Text(MessageTime.formatNow(at), style = MaterialTheme.typography.labelSmall)
            }
            if (notDelivered) {
                Text(
                    stringResource(R.string.chat_message_not_delivered),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
