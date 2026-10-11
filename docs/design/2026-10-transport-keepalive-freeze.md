<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Transport Keepalive (5e-1b) Design Freeze — ratified 2026-10-07

Status: **FROZEN.** Maintainer ratification 2026-10-07, one verdict of record:
"package as recommended" (ratifies every recommendation of the reviewer's
working document r1, `p5-5e1b-transport-keepalive-gate.md`, sha256
`43bcdebcfb4979c9d9884190e1b57ad0fe470bde5bf919c4774a862394c17892`). This
document is the decision record for unit `5e-1b transport keepalive`, the
core fix for finding F-L that ruling R-E (2026-10-07, ledger item 40) made a
precondition of `v0.1.0`. Deviations require a governed amendment.
Amendment A1 (ratified 2026-10-07 by option, verdict of record "lets go
with option A"): finding F-M, discovered during the unit's order drafting,
adds KA-D11 (per-conversation flush serialization), red test R-9 and
invariant sub-check 21i; the file set of KA-D10 is unchanged.
Hash-chained predecessor: `docs/design/2026-09-conversation-ui-freeze.md`,
whole-file sha256
`ca0d85c95b5d67f8184505954744a1b8016c37e462c3c6bdee7a5132583472f8`.
Base of the findings: titlan `main` `6f27c1b837878455859764379b7c4a2676efd46a`
(5e-1 merged). Every `file:line` below is at that commit.

## The finding (F-L)

A conversation's receive subscription was a WebSocket that nothing exercised
unless a message flowed: the client only answered pings
(`tezca-core/src/relay_client/ws.rs:89`) and otherwise waited without a
deadline; the listener left that wait only on a frame, a transport error or
cancellation (`relay_client/mod.rs:945-950`); pending sends were flushed at
send and on (re)connect, never on a timer (`:429`, `:941`); the relay HTTP
client carried no timeout (`ws.rs:146-149`) and `send_chat` blocked the
calling thread on it (`client.rs:322`). On a silently dropped path the chip
stayed `Online` and messages waited on the relay until something forced a
reconnect. Observed on the release-checklist §0 run of 2026-09-30 and
2026-10-07 (record `5e1-section0-record.md`, sha256 `564869cd…da39`): idle
death within 3–10 minutes on the emulator's path, with no network event on
the dead side.

## The second finding (F-M, amendment A1)

`Engine::flush_pending` (`relay_client/mod.rs:433-469`) reads every
`pending` row, encrypts each and deposits it, and marks a row `sent` only
after its deposit returns; nothing stops two callers from running it for the
same conversation at once. The callers overlap in production: the inline
flush of `send_chat` (`:429`) against a second `send_chat` — the chat
screen launches every Send tap on its own IO coroutine
(`titlan-android/.../ChatScreen.kt:129`, `ConversationStore.kt:108`) — or
against the listener's connect-time flush (`:941`), and, once KA-D3 lands,
against the keepalive tick's flush. The second caller reads the first row
while its deposit is still in flight, encrypts it again under the next
ratchet counter and deposits it again; the receiver's ratchet accepts both
(they are distinct ciphertexts), it has no frame-level message identity to
deduplicate on, and persists two rows. On the base commit the pre-existing
e2e test `unimplemented_payload_type_is_acked_and_discarded_on_live_inbox`
fails this way at ≈3 % (1/30 isolated; 10/40 with a diagnostic print in the
flush: in every failure the same message id is deposited twice from two
runtime threads). On a phone it is a message shown twice to the peer after
a quick second send on a slow link.

## KA-D0 — Unit identity (FROZEN)

Unit `5e-1b transport keepalive`; branch `p5-5e1b-transport-keepalive`; base
`6f27c1b`; sits between 5e-1 and the `5e-2 v0.1.0 release` gate. Version
identity unchanged (`versionName 0.1.0-rc.2`); the bump belongs to 5e-2.

## KA-D1 — Client-side keepalive; relay binary unchanged (FROZEN)

The client sends a WebSocket Ping after `KEEPALIVE_INTERVAL_S` of silence on a
subscription and expects a Pong within `KEEPALIVE_GRACE_S`; a missed Pong is a
transport error from `Subscription::next`, which the listener turns into its
existing reconnect (`Offline` → `Backoff` → `Connecting` → `Online` + pending
flush). All three subscription consumers run it: the conversation listener,
the pairing-handoff wait, and the pairing listener. The relay source is
untouched; its RFC 6455 auto-Pong is a design assumption pinned by
`tezca-relay/tests/relay_lifecycle.rs :: ws_ping_is_answered_with_pong`. The
published relay `4e91ee9d7e7efd58c320238996a9bdcb82a7c440400852897dc0021a6646ae1e`
stays byte-identical across this unit. Relay-side pinging and dead-subscriber
reaping are a named successor (titlan-ops).

## KA-D2 — Parameters (FROZEN): 55 s interval, 10 s grace

`KEEPALIVE_INTERVAL_S = 55`, `KEEPALIVE_GRACE_S = 10`, single-sourced in
`tezca-core/src/config.rs` beside the offer-validity constants and consumed
only through `KeepaliveTiming`. A dead socket is detected within 65 s of the
last traffic; the first reconnect attempt follows 1 s later. The pairing
handoff's 10 s inline wait is below the interval and unchanged (F-K stays with
PD-D2).

## KA-D3 — Periodic pending flush while connected (FROZEN)

`Subscription::next` yields `Event::Idle` when a keepalive round trip
completes; on `Idle` the conversation listener runs `flush_pending` (a no-op
with nothing pending) and continues. A deposit that failed while the socket
lived is therefore retried within one interval without a reconnect. At most
one deposit attempt per conversation per interval — far under the relay's
`60 deposit/min/source`.

## KA-D4 — Bounded relay HTTP (FROZEN): 10 s connect, 30 s request

`HTTP_CONNECT_TIMEOUT_S = 10`, `HTTP_REQUEST_TIMEOUT_S = 30` in `config.rs`,
applied on the single `reqwest::Client::builder()` site (`ws.rs`
`build_http_client`), which keeps `use_preconfigured_tls` (family 18b). Every
relay HTTP call inherits them: `send_chat`'s inline deposit is bounded (the
message stays `pending`, retried by KA-D3 or reconnect — the documented
contract is unchanged) and every pairing HTTP step surfaces a NETWORK-class
failure within the request timeout instead of hanging.

## KA-D5 — Chip semantics unchanged (FROZEN)

`Online` keeps meaning "subscribed"; a keepalive failure produces the existing
`Offline` → `Backoff { secs }` → `Connecting` → `Online` sequence that the
5e-1 `ConnectionChip` already renders. No `FfiConnectionState` change, no
string, no Kotlin: the unit is zero-UI and zero-FFI.

## KA-D6 — Red set (FROZEN, with two gate corrections)

- R-1 `ws::tests::keepalive_pings_after_interval_of_silence`
- R-2 `ws::tests::keepalive_missing_pong_is_a_transport_error`
- R-3 `ws::tests::keepalive_resets_on_traffic`
- R-4 `relay_client_e2e::silent_socket_is_detected_and_resubscribed`
- R-5 `relay_lifecycle::ws_ping_is_answered_with_pong` (green on the base by
  design — it pins an existing relay behaviour)
- R-6 `relay_client_e2e::pending_send_flushes_on_keepalive_tick_without_reconnect`
- R-7 `ws::tests::http_client_times_out_on_a_silent_server`
- R-8 check-invariants family 21
- R-9 `relay_client_e2e::two_quick_sends_deposit_each_message_once` (A1):
  two sends 200 ms apart while the harness proxy holds every deposit for
  800 ms; each message must reach the peer exactly once and no reconnect
  may occur. Fails on the base at its assertion (`first` delivered twice).

Gate corrections recorded at order drafting (reviewer, 2026-10-07): **GC-1** the
`ws.rs` unit tests run in real time with short injected timing, not under
tokio's paused clock — the workspace `tokio` carries no `test-util` feature and
adding one is a manifest change outside the unit's containment. **GC-2** the
e2e tests inject timing through `TitlanClient::open_with_timing`, compiled
only under the dev-scope `test-relay-anchor` feature (the shipped library
carries exactly the production constants); the fault is injected by a
byte-level TCP proxy in the test harness that can silence existing WebSocket
connections without closing them, or answer deposit POSTs with `503` itself.
**GC-3** the keepalive tick's `flush_pending` is raced against the sync
generation's cancel signal exactly like the connect-time flush, so the
listener's cancellation discipline (every pure wait raced; only
handle→persist→ack unraced) holds on the new path.

## KA-D7 — Invariant family 21 "Transport keepalive (5e-1b, F-L)" (FROZEN)

21a one keepalive Ping site, constants single-sourced in `config.rs`; 21b the
one reqwest builder applies `.connect_timeout(` and `.timeout(`; 21c the
listener retries pending sends on `Event::Idle`; 21d the checklist carries the
idle-socket block in §0 and §8; 21e this freeze is on the tree, Apache-2.0,
hash-chained; 21f the pinning tests exist (R-4, R-6, R-9); 21g the timing
seam is gated by `#[cfg(feature = "test-relay-anchor")]`. Containment (21h)
is the order's gate against the base commit. 21i (A1): exactly one
`flush_pending`, and it acquires the per-conversation flush guard before
reading pending rows.

## KA-D8 — Device acceptance (FROZEN): "Idle-socket round trip (F-L)"

Release checklist §0 and §8: after the message exchange, both devices left in
the conversation, screens on, untouched for 15 minutes; then the literal
`titlan message idle` from the physical device must appear on the emulator
within 60 s, with no network toggle. The unit's acceptance is §0 on the merged
head, all blocks (the 5e-1 precedent, CU-D12 form), before 5e-2 opens.

## KA-D9 — Documents (FROZEN)

`proto/relay-api.md` (keepalive paragraph under the subscribe endpoint;
normative for third-party clients; no wire-format change); `docs/threat-model.md`
(F-L mitigation under TM-C7; the constant-rate presence signal under TM-R2);
`docs/release-checklist.md` (KA-D8 blocks; §0 Direction B wording corrected
per reviewer defect #36); this freeze. `docs/user-notes.md` unchanged.

## KA-D10 — Containment (FROZEN)

Changed: `tezca-core/src/relay_client/{ws.rs,mod.rs}`, `tezca-core/src/config.rs`,
`tezca-core/src/client.rs`; `tezca-relay/tests/{common/mod.rs,relay_client_e2e.rs,relay_lifecycle.rs}`;
`scripts/check-invariants.sh`; the four documents above. Byte-identical to the
base: `tezca-relay/src/`, `proto/*.md` outside the one paragraph,
`titlan-android/`, `uniffi-bindgen/`, `Cargo.toml` (all), `Cargo.lock`,
`titlan-android/gradle.lockfile`. No new dependency: Ping/Pong are
`tungstenite::Message` variants already in use; timers are `tokio::time`;
reqwest's timeouts are builder methods on the locked version.

## KA-D11 — Per-conversation flush serialization (FROZEN, amendment A1)

`flush_pending` holds a per-conversation guard (`Engine::flush_locks`, a
`tokio::sync::Mutex<()>` per conversation, fetched under the engine's `std`
mutex) across its read-pending → encrypt → deposit → mark span. Overlapping
callers wait their turn and then find the row already `sent`; the ordering
of a conversation's sends is unchanged (rows are flushed by `rowid`). Every
flush path is covered without being named: the inline send, the
connect-time flush, the keepalive tick, `mailbox-update/1`, and the
recovery paths. No Kotlin, no FFI, no wire change. Residual, named for a
successor: a deposit the relay accepted whose `202` was lost on the wire is
still retried as a fresh ciphertext — eliminating that needs a frame-level
message identity (a `chat/2` or envelope decision for the Tezca spine), not
a client lock.

## Successors named here

`5e-2 v0.1.0 release` (after this unit's §0 passes); relay-side keepalive and
subscriber reaping (titlan-ops); PD-D2 (F-I, F-K, the F3 offer-cancel FFI);
F-J and the 5e-1 UI riders; the INV-5 receive-path unit; RC-D1(b) UniFFI
single-sourcing; frame-level message identity for receiver-side
deduplication (the F-M residual, a spine decision).
