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

- **INV-5 gap on the receive path (4b-3 / Phase 5 invariant-audit item,
  recorded 2026-07-21).** `set_conversation_relay` repoints the SEND side
  only (`conversations.relay_url`, consumed by `flush_pending` and the
  recovery deposit legs). The subscribe/receive endpoint is the
  engine-global `my_relay` — the `open()` parameter — at
  `relay_client/mod.rs:816`, so per-conversation relay selection is not yet
  honored on the receive path: a conversation "moved" to another relay
  still receives on the device's default relay. No behavior change was made
  when this was found (evidence: `~/4b2-relay-selection-evidence.md`); the
  Phase 5 invariant audit should decide whether INV-5's "every conversation
  may override" extends to the receive leg and, if so, how the listener
  learns a per-conversation endpoint.
- **Pairing-offer cancel (relay-side DELETE).** The pairing screen's dismiss
  action does not (and must not claim to) cancel an outstanding offer: local
  invalidation of the offer's single-use state requires a core FFI cancel
  method, which is new FFI surface and is deliberately NOT added here
  (flagged 2026-07-21). Until that lands, a dismissed offer remains
  single-use and lapses at its 1 h TTL; the UI states this honestly. The
  follow-up is: core cancel method (stop the pairing listener, forget the
  secret) + relay-side `DELETE /v1/mailboxes/{pairing_inbox}`. Related, by
  design: pairing/offer listeners are not cancelled by `stop_sync` — they
  end on pairing completion, proof-of-scan burn, inbox retirement, or offer
  TTL (4b2-WO-stop-sync).
- **Pairing-accept error mapping (4b-3, recorded 2026-07-28).** The accept
  path maps every failure — including the `Network` variant — onto the one
  "stale or malformed" dialog string, so an unreachable relay reads as a bad
  offer. Split the mapping so network-layer failures surface as reachability
  problems. Evidence: `4b2-WO-ffi-bisect` and the 2026-07-27/28 device
  sessions.
  **RESOLVED — landed in 5a-2 (PR #40, 2026-08-20); annotated here in 5a-3.**
  The four-way pairing-failure vocabulary (P5-D2) retired the unified dialog;
  network-layer failures now surface as reachability problems, distinct from
  stale/malformed offers (`app/src/main/.../pairing/PairingFailure.kt`).
- **Offer TTL vs harness wait fuse (design gate, recorded 2026-07-28).** The
  deposit harness's `DEFAULT_WAIT_SECS` is a 600 s wait fuse from mint; the
  frozen design gives offers a 1 h TTL. Reconcile which value governs, and
  where.
  **RESOLVED — landed in 5a-1 (PR #37, 2026-08-17); annotated here in 5a-3.**
  One governing value: the offer's own embedded `issued_at + ttl_s`
  (pair-offer v3 — Horizon freeze §H7, v3 freeze V3-D2/§6). The harness fuse
  now READS the embedded `ttl_s` through `peek_offer_validity`
  (`DEFAULT_WAIT_SECS` retired; pinned by
  `tezca-core/src/pairing_v3_acceptance.rs` `r9_harness_fuse_equals_embedded_ttl`);
  the UI countdown reads the same value (`OFFER_TTL_MS` deleted;
  `PairingCoordinator.createOffer`); the acceptor enforces the window
  (`OfferExpired`, evaluated before any network I/O); the relay's 14 d TTL
  remains a storage bound only. Spec: `proto/pairing.md` §Single-sourced
  constants. The 600 s references in `docs/checklists/4b2-pairing-device.md`
  §2 describe the pre-v3 harness and stand as dated phase records.
- **Link-paste field usability (4b-3, recorded 2026-07-28).** The §5 paste
  field is reachable only via the camera-permission-denied trigger; with a
  ~2.6 KB link pasted its accept button sits off-screen; the screen does not
  scroll; keyevent 66 / 61+66 do not submit.
- **Blank post-pairing screen (4b-3, recorded 2026-07-28).** Pairing success
  renders only a status line; there is no conversation-list navigation.
- **Swallowed peek failure (4b-3, recorded 2026-07-28).**
  `PairingScreen.kt:357-358` wraps `peekOfferRelay` in
  `runCatching{}.getOrNull()` — the first core touch on the scan path, with
  every failure silently swallowed. Surface or log-gate the failure.
- **Bounded network-I/O timeouts (Phase 5 hardening, recorded 2026-07-28).**
  No timeouts are configured on relay HTTP/WS operations, so a joined
  `stop_sync` landing during a control frame's shielded network leg waits on
  OS TCP behavior (`4b2-WO-stop-sync` FLAG-3). Add bounded network-I/O
  timeouts across the relay client.
