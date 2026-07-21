<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# 4b-2 acceptance venues (maintainer-ratified 2026-07-21)

## §10.7 recovery: where convergence is graded

Derived-mailbox recovery convergence — generation windowing, rotation,
exhaustion mechanics under REAL relay state loss — requires killing and
restarting a relay process mid-conversation. The Android instrumented suite
cannot do that: the CI relay runs on the runner host, an emulator test cannot
restart it, and a CI restart-sidecar was considered and rejected. The venues
are therefore split:

**Convergence acceptance — Rust e2e suite**
(`tezca-relay/tests/relay_client_e2e.rs`, real relay child processes,
restarted mid-test):

- `v2_single_total_loss_recovers_via_derived_mailboxes`
- `v2_two_consecutive_total_losses_each_recover`
- `v2_peer_unreachable_exhausts_recovery_and_needs_repair`
- `v2_message_queued_while_relay_down_delivers_after_recovery`

**FFI event surfacing — Android instrumented suite**
(`app/src/androidTest/.../sync/RecoveryTest.kt`): the frozen §1 event
vocabulary genuinely crosses the FFI to Kotlin observers — connection-state
transitions on live and dead relays, and `onConversationNeedsRepair` on
recovery exhaustion — driven only through production API
(`CoreClientFactory.open` against live, dead, or amnesiac relays; the
amnesiac relay is a plain in-process HTTP test double that answers the same
404 loss signal a restarted relay produces).

The plaintext of the split: Rust proves the recovery machine converges;
Android proves the app can SEE what the machine reports. Neither venue
duplicates the other.

## Ledgered follow-ups

- **Pairing-offer cancel (relay-side DELETE).** The pairing screen's dismiss
  action does not (and must not claim to) cancel an outstanding offer: local
  invalidation of the offer's single-use state requires a core FFI cancel
  method, which is new FFI surface and is deliberately NOT added here
  (flagged 2026-07-21). Until that lands, a dismissed offer remains
  single-use and lapses at its 1 h TTL; the UI states this honestly. The
  follow-up is: core cancel method (stop the pairing listener, forget the
  secret) + relay-side `DELETE /v1/mailboxes/{pairing_inbox}`.
