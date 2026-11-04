// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.titlan.R
import kotlinx.coroutines.launch

/**
 * The conversation-label dialog (1.1, L-D5), opened from the chat header and
 * from a list-row long-press: one single-line field prefilled with the
 * current label, a live `used/cap` counter, Save / Clear / Cancel. The rule
 * is applied here first ([LabelRules], mirroring core), so core is handed
 * either a valid trimmed label or `null`; a core rejection or failure keeps
 * the dialog open and raises the storage-error banner (the E-5 guard in
 * [ConversationStore.setLabel]).
 *
 * INV-1: a label is a contact name — the draft lives in memory only, never in
 * saved instance state (scripts/check-invariants.sh 23f), and is never logged.
 */
@Composable
fun LabelDialog(key: ConversationKey, current: String?, onDismiss: () -> Unit) {
    var draft by remember { mutableStateOf(current ?: "") }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val check = LabelRules.check(draft)

    fun commit(label: String?) {
        busy = true
        scope.launch {
            val written = ConversationStore.setLabel(key, label)
            busy = false
            if (written) onDismiss()
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.label_dialog_title)) },
        text = {
            Column {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    enabled = !busy,
                    isError = check is LabelCheck.TooLong || check is LabelCheck.Invalid,
                    label = { Text(stringResource(R.string.label_dialog_hint)) },
                    supportingText = {
                        Text(
                            when (check) {
                                is LabelCheck.TooLong -> stringResource(R.string.label_too_long, LabelRules.MAX_SCALARS)
                                LabelCheck.Invalid -> stringResource(R.string.label_invalid)
                                else -> stringResource(
                                    R.string.label_counter,
                                    LabelRules.scalarCount(draft.trim()),
                                    LabelRules.MAX_SCALARS,
                                )
                            },
                        )
                    },
                )
                Text(
                    stringResource(R.string.label_dialog_note),
                    modifier = Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && (check is LabelCheck.Ok || check is LabelCheck.Clear),
                onClick = { commit((check as? LabelCheck.Ok)?.label) },
            ) { Text(stringResource(R.string.label_save)) }
        },
        dismissButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(enabled = !busy && current != null, onClick = { commit(null) }) {
                    Text(stringResource(R.string.label_clear))
                }
                TextButton(enabled = !busy, onClick = onDismiss) {
                    Text(stringResource(R.string.label_cancel))
                }
            }
        },
    )
}

/** The title a conversation shows (1.1, L-D4/L-D5): its label, else the hex form. */
@Composable
fun conversationTitle(row: ConversationRow?, key: ConversationKey): String =
    row?.label ?: stringResource(R.string.conversations_row_label, key.shortHex)
