// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

/**
 * Composer limits (5e-1, CU-D6; finding F-H). The single site of the chat
 * cap: the largest payload the default padding profile admits, stated by
 * `proto/envelope.md` ("Maximum payload under the default profile: 8186
 * bytes") and pinned there by ChatBodyDecodingTest and
 * scripts/check-invariants.sh family 20c. Core persists an outgoing frame
 * before it checks the size, and an oversized frame blocks every later
 * message in that conversation — so the UI never hands core one.
 */
object ChatLimits {
    const val MAX_CHAT_UTF8_BYTES = 8186
}
