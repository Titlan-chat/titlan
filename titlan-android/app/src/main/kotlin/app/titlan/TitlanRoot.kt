// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.titlan.conversation.ChatScreen
import app.titlan.conversation.ConversationKey
import app.titlan.conversation.ConversationListScreen
import app.titlan.conversation.ConversationStore
import app.titlan.core.AppCore
import app.titlan.pairing.PairingScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The three destinations of the single Activity (5e-1, freeze CU-D2). */
sealed interface Screen {
    data object Conversations : Screen
    data class Chat(val key: ConversationKey) : Screen
    data object Pairing : Screen
}

// The saved navigation tags. A chat tag carries a conversation key's hex and
// nothing else (CU-D2: no message text, draft or offer bytes is ever saved).
private const val TAG_CONVERSATIONS = "conversations"
private const val TAG_PAIRING = "pairing"
private const val TAG_CHAT_PREFIX = "chat:"

private fun screenOf(tag: String?): Screen? = when {
    tag == null -> null
    tag == TAG_CONVERSATIONS -> Screen.Conversations
    tag == TAG_PAIRING -> Screen.Pairing
    tag.startsWith(TAG_CHAT_PREFIX) -> Screen.Chat(ConversationKey(tag.removePrefix(TAG_CHAT_PREFIX)))
    else -> Screen.Conversations
}

/**
 * State-driven navigation (5e-1, freeze CU-D2). The start destination is
 * decided from the store: the conversation list when a paired conversation
 * exists, else pairing. Back leaves a chat for the list, and leaves pairing
 * for the list only when a conversation exists (otherwise the Activity
 * finishes).
 *
 * Both root-level reads are gated by [AppCore.hasPairedConversation], the
 * existence probe that opens nothing on a never-paired install — identity
 * stays lazily minted at first pairing (4b2-WO-launch-sync).
 */
@Composable
fun TitlanRoot() {
    var tag by rememberSaveable { mutableStateOf<String?>(null) }
    val screen by rememberUpdatedState(screenOf(tag))
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        val paired = withContext(Dispatchers.IO) { AppCore.hasPairedConversation() }
        if (paired) ConversationStore.refreshConversations()
        if (tag == null) tag = if (paired) TAG_CONVERSATIONS else TAG_PAIRING
    }

    // CU-D3 refresh trigger: Activity ON_START re-reads the list and the open
    // conversation, so what arrived while the UI was stopped is shown.
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) {
                scope.launch {
                    if (withContext(Dispatchers.IO) { AppCore.hasPairedConversation() }) {
                        ConversationStore.refreshAll((screen as? Screen.Chat)?.key)
                    }
                }
            }
        }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer) }
    }

    when (val current = screen) {
        null -> Box(Modifier.fillMaxSize())

        Screen.Conversations -> ConversationListScreen(
            onOpen = { key -> tag = TAG_CHAT_PREFIX + key.hex },
            onPair = { tag = TAG_PAIRING },
        )

        is Screen.Chat -> {
            BackHandler { tag = TAG_CONVERSATIONS }
            ChatScreen(
                current.key,
                onBack = { tag = TAG_CONVERSATIONS },
                onPairAgain = { tag = TAG_PAIRING },
            )
        }

        Screen.Pairing -> {
            val conversations by ConversationStore.conversations.collectAsState()
            BackHandler(enabled = conversations.isNotEmpty()) { tag = TAG_CONVERSATIONS }
            PairingScreen(onPaired = { key -> tag = TAG_CHAT_PREFIX + key.hex })
        }
    }
}
