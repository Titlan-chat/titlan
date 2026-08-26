<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan Recovery — Derived-Mailbox Recovery Protocol (§10.7)

**Status: FROZEN — Titlan wire protocol spec 1.0 (Phase 5, unit 5a-3).**
This document specifies, **as implemented**, how two paired parties
re-establish routing after **total** mailbox loss (typically a restart of the
shared relay, which is RAM-only — `relay-api.md` INV-3) **without
re-pairing**. It is the procedural companion to `proto/inner-frame.md`, which
remains the authority for the frame layouts (`recovery-hello`,
`mailbox-update/2`, `mailbox-update/3`) and the derivation formulas; this
document restates the formulas only where needed to follow the protocol.
Ratification history: frozen 4b-2 design §8, maintainer resolutions of
2026-07-19 (work order §10.7: HMAC-PRF derivation; dual-contribution root),
rotation ordering and hello-answers-hello ratified 2026-07-19.

Placement note: this protocol is specified in its own file (rather than inside
`pairing.md`) because it runs on established sessions, long after pairing;
pairing only seeds it (§Recovery root).

## 1. Roles and the recovery root

- Roles are fixed at pairing and persisted: the party that displayed the offer
  is the **offerer** (A); the party that scanned it is the **responder** (B).
  The role is a deterministic tiebreak used by §4.
- **Recovery root (dual contribution).** Each party contributes 32 bytes from
  its OS CSPRNG at pairing — the responder's `recovery_root_contribution` in
  `pair-ack/2`, the offerer's in the pairing `inbox-handoff`
  (`mailbox-update/2`). **Neither contribution is ever in the offer or QR.**
  Both parties compute the identical root:

  ```
  root = HMAC-SHA256(key = A_contribution, msg = B_contribution)   # A = offerer, B = responder
  ```

  All MAC bytes come from libsignal's `signal-crypto` `CryptographicMac`
  (`"HmacSha256"`) — INV-6.
- A conversation **without** a root (one paired before the v2/v3 offer flow, or
  one whose `mailbox-update/2` never landed) cannot run this protocol; see §6.

Reference: `tezca-core/src/recovery.rs` (`Role`, `derive_root`),
`tezca-core/src/pairing.rs` (`hmac_sha256`, `RECOVERY_CONTRIB_LEN`),
`tezca-core/src/relay_client/mod.rs` (`handle_pair_ack_v2` — offerer mints
`a_contrib`, computes `derive_root(a, b)`; `await_inbox_handoff_v2` — responder
computes `derive_root(a, b)` from the received contribution;
`begin_pairing_from_offer` — responder mints `b_contrib`). Tests:
`recovery.rs` `root_is_symmetric_across_parties_but_order_sensitive`;
`tezca-relay/tests/relay_client_e2e.rs` `pair_v2_offer_proof_and_exchange`.

## 2. Derived mailbox IDs (HMAC-PRF)

For a party whose pairing role is `role` and a generation `g` (u32), the id of
the derived mailbox **owned by that party** is:

```
mailbox_id = base64url_nopad(
    HMAC-SHA256(root, "titlan-recovery-mailbox-v1" ‖ role_label ‖ g_u32_be)
)                                                               # 43 chars
role_label ∈ { "offerer", "responder" }   # the mailbox OWNER's role
```

Properties: 256-bit, unguessable, opaque to the relay; role- and
generation-separated, so the two directions and successive generations never
collide. HMAC is used as a PRF because libsignal exposes no public HKDF; for a
uniformly random `root`, HKDF-Expand ≡ HMAC-PRF, so a single HMAC is an
equivalent KDF with every byte inside libsignal (INV-6). The label's `-v1`
suffix is the versioning hook: any future derivation (e.g. device-bearing)
bumps the label and produces disjoint ids by construction (Horizon §H2.3).

Derived ids are **created at the client's chosen id** with
`PUT /v1/mailboxes/{id}` (`relay-api.md`), which is idempotent and leaks no
existence information; deposit and subscribe never create.

Reference: `tezca-core/src/recovery.rs` (`MAILBOX_LABEL`, `Role::label`,
`derive_mailbox_id`, `base64url_nopad`); test
`mailbox_ids_are_43_chars_and_role_generation_separated`;
`tezca-core/src/relay_client/http.rs` (`put_mailbox`);
`tezca-relay/tests/put_mailbox.rs`.

## 3. Generations, the window, and the probe

Each party keeps two persisted counters per conversation: its **own
generation** `own_g` and the **last generation reported by the peer** `peer_g`
(both 0 at pairing).

**Constants (spec 1.0):**

| name | value | meaning |
|---|---|---|
| `W` (`RECOVERY_WINDOW`) | 4 | generation-convergence window |
| `RECOVERY_PROBE_CYCLES` | 3 | completed probe cycles without verified contact before exhaustion |
| `recovery-hello` version | 1 | `inner-frame.md` |
| `recovery-hello` nonce | 16 bytes | random; idempotency key together with the generation |

**Loss detection.** A subscribe to this party's current receive mailbox that
returns `404` is the loss signal (unknown/expired/deleted are
indistinguishable by design). The party then runs one recovery attempt.

**Recovery attempt (sender-side forward probe), at the new generation
`g = own_g + 1`:**

1. **Exhaustion check first** (§5). If exhausted ⇒ `conversation-needs-repair`;
   no probe runs.
2. **PUT-create and subscribe own derived inbox** at `g`
   (`derive(root, own_role, g)`); this becomes the party's receive mailbox. If
   the PUT or the local update fails, the attempt fails (no cycle counted;
   retried with backoff).
3. **Mint one `recovery-hello`** `{version 1, generation = g, nonce}` and
   encrypt it under the conversation's Double Ratchet.
4. **For each peer generation `k` in the window `[peer_g … peer_g + (W−1)]`:**
   PUT-create the peer's derived inbox at `k` (`derive(root, peer_role, k)`)
   and, if the PUT succeeded (`201`), deposit the same sealed hello into it.
   **Create-before-deposit is load-bearing** — deposit never creates. A relay
   `429` on any PUT or deposit is a **pacing** signal (the leg is skipped this
   attempt, and it does **not** count toward exhaustion).
5. **Point sends** at the peer's derived inbox at `g` and persist
   `(own_g, peer_g) = (g, peer_g)`.
6. The attempt **completed** (steps 2–5 ran) ⇒ one probe cycle is counted
   (§5); the party reports `Recovering` and resubscribes on its derived inbox.

Why the sender's window suffices: the receiver subscribes its own derived
inbox at its current generation only; the sender's forward window covers the
receiver's `own_g` whenever the relative offset is `≤ W−1`, which coincides
exactly with the recoverable range of §5. A receiver-side window is therefore
unnecessary and is not implemented (`inner-frame.md` §recovery-hello,
ratified 2026-07-19).

Reference: `tezca-core/src/recovery.rs` (`RECOVERY_WINDOW`,
`RECOVERY_PROBE_CYCLES`, `RECOVERY_HELLO_VERSION`, `RECOVERY_HELLO_NONCE_LEN`,
`encode_recovery_hello`, `GenerationState::outbound_window`);
`tezca-core/src/relay_client/mod.rs` (`conversation_listener` —
`Connected::NotFound` ⇒ `recover`; `recover_v2` — exhaustion check, `g =
own_gen + 1`, cycle counted only when the probe completed;
`enter_recovery_gen` — steps 2–5; `put_create` — `201` only). Tests:
`recovery.rs` `sender_forward_window_is_w_wide`,
`recovery_hello_round_trips_and_rejects_malformed`;
`tezca-relay/tests/relay_client_e2e.rs`
`v2_single_total_loss_recovers_via_derived_mailboxes`,
`v2_message_queued_while_relay_down_delivers_after_recovery`.

## 4. Convergence and the rotation finisher

**Verified receipt.** A `recovery-hello` counts only if it **decrypts under
the conversation's Double Ratchet**; an undecryptable deposit is not contact
and moves nothing (it is acked and discarded, `envelope.md` §Unknown and
unsupported types).

**Dedup.** The receiver dedups hellos by `(generation, nonce)`: a pair already
seen is acked but not reprocessed, so the idempotent probe landing in several
window generations is applied once. The reference implementation keeps a
bounded per-conversation ring of 512 pairs, oldest-evicted (in memory).

**On a verified, new hello reporting generation `r`:**

1. Reset the exhaustion cycle counter (§5) — verified contact.
2. Converge: `peer_g := max(peer_g, r)`; `own_g := max(own_g, r)`.
3. If `own_g` was **raised** ("behind the peer"): run steps 2–5 of §3 at the
   adopted generation — this re-enters recovery at `own_g` and, in doing so,
   **sends this party's hello** into the peer's window. This is how "hello
   answers hello" is realized: a party that adopts a generation always emits
   a hello at it, and a party that was not raised has, by construction,
   already sent its hello at its current generation when it entered it.
4. Else, if `r == own_g` **and this party is the offerer**: the two sides are
   converged — initiate the **rotation** below.
5. Else: flush pending sends (the peer's derived inbox is now known-live).

**Rotation (drain-then-switch; the OFFERER initiates, the responder never
does).** Rotation retires the derived inboxes in favor of fresh, long-lived,
relay-generated ones, without dropping in-flight chat:

1. The offerer mints a fresh relay-generated inbox `F_A`
   (`POST /v1/mailboxes`), deposits `mailbox-update/3{F_A}` into the
   **responder's derived inbox at the converged generation**, and **stays
   subscribed on its own derived inbox**, draining any chat the responder is
   still sending there.
2. The responder receives `/3{F_A}` on its derived inbox: routes its sends to
   `F_A`, mints `F_B`, deposits `/3{F_B}` into the **offerer's derived inbox**
   (not `F_A` — the offerer is not subscribed there yet), switches its receive
   to `F_B`, and deletes its own derived inbox (`DELETE /v1/mailboxes/{id}`;
   the relay idle TTL would otherwise reap it).
3. The offerer receives `/3{F_B}` on its derived inbox: routes its sends to
   `F_B`, switches its receive to `F_A`, and deletes its derived inbox.
   **Receipt of the second leg is the implicit ack.**

`mailbox-update/3` carries no recovery-root contribution (the root already
exists on both ends); it is structurally shorter than `/2`, and a `/3` frame
with trailing bytes is malformed (`inner-frame.md`).

Why this is safe: per-mailbox delivery is FIFO (`relay-api.md`), so the
offerer drains every chat the responder deposited into the offerer's derived
inbox **before** the `/3{F_B}` that triggers its switch. A late deposit into an
already-deleted derived inbox yields `404` → loss detection → a bounded fresh
recovery cycle (the derived ids remain re-derivable); chat keeps flowing over
the derived inboxes meanwhile.

Reference: `tezca-core/src/relay_client/mod.rs` (`handle_recovery_hello` —
dedup, reset, converge, re-enter on bump, offerer-initiates on `r == own_g`;
`mark_hello_seen` — 512-entry ring; `initiate_rotation` — `/3{F_A}` into the
responder's derived inbox, stay on derived; `handle_rotation` — responder leg
into the offerer's derived inbox, offerer leg switches and deletes);
`tezca-core/src/recovery.rs` (`GenerationState::converge`);
`tezca-core/src/pairing.rs` (`encode_mailbox_update_v3` /
`parse_mailbox_update_v3`). Tests: `recovery.rs`
`double_restart_desync_converges_to_max`;
`tezca-relay/tests/relay_client_e2e.rs`
`v2_two_consecutive_total_losses_each_recover`.

## 5. Exhaustion ⇒ `conversation-needs-repair`

Recovery is **bounded**. Either condition ends it with the
`conversation-needs-repair` signal (`ConnectionState::RePairRequired` plus the
needs-repair callback), after which re-pairing is the only path:

- **Window exhausted:** the relative generation offset `|own_g − peer_g| ≥ W`
  (= 4). A hello cannot land in a live window.
- **Cycles exhausted:** `RECOVERY_PROBE_CYCLES` (= 3) **completed** probe
  cycles with no verified peer contact. A cycle counts once per recovery
  attempt whose probe actually ran (§3 step 6) — never per deposit; relay
  `429`s within an attempt are pacing and add nothing; an attempt that failed
  at setup adds nothing. Any verified hello resets the counter.

Reference: `tezca-core/src/recovery.rs` (`GenerationState::is_exhausted`,
`ExhaustionTracker`); `tezca-core/src/relay_client/mod.rs` (`recover_v2` —
both checks; `conversation_listener` — `Recovery::NeedsRepair` ⇒
`RePairRequired` + `emit_needs_repair`). Tests: `recovery.rs`
`offset_at_or_beyond_window_is_exhausted`,
`cycle_exhaustion_counts_attempts_and_429_within_an_attempt_cannot_advance`;
`tezca-relay/tests/relay_client_e2e.rs`
`v2_peer_unreachable_exhausts_recovery_and_needs_repair`;
`titlan-android/app/src/androidTest/kotlin/app/titlan/sync/RecoveryTest.kt`
`needsRepairSurfacesThroughFfiOnRecoveryExhaustion`.

## 6. Conversations without a recovery root (`mailbox-update/1`)

A conversation with **no persisted root** (no role, or the pairing handoff
never landed) does not run §3–§5. On loss it performs the Phase-4a
**one-sided** recovery: create a fresh **random** relay-generated inbox,
announce it over the existing session with `mailbox-update/1`
(`pairing.md`), and, if that deposit itself returns `404` (the peer's inbox is
gone too — total loss), surface `RePairRequired`. Such conversations are
**re-pair-only on total loss, permanently** — derived-mailbox recovery is not
retrofitted onto them.

Reference: `tezca-core/src/relay_client/mod.rs` (`recover` — dispatch on root
presence; `recover_v1`; `handle_incoming` — `mailbox-update/1` adopts the
announced inbox); `tezca-core/src/pairing.rs` (`encode_mailbox_update` /
`parse_mailbox_update`).

## 7. Relay-side facts this protocol relies on

- `PUT /v1/mailboxes/{id}`: idempotent create-at-id, `201` whether created or
  existing, `400` on a malformed id shape, `429` pacing, `503` uniformly at
  the global cap (recovery-blocked-at-cap is accepted).
- `POST …/messages` and `GET …/ws` return `404` for an unknown id and **never
  create**.
- `DELETE /v1/mailboxes/{id}` is unconditional `204`.
- Per-mailbox delivery is FIFO replay-then-live; unacked messages redeliver
  on reconnect.
- The 14-day `--ttl-secs` default reaps idle mailboxes (including stranded
  derived inboxes); it is a storage bound, not a protocol timer.

Reference: `relay-api.md`; `tezca-relay/src/api.rs`;
`tezca-relay/tests/put_mailbox.rs`, `tezca-relay/tests/relay_lifecycle.rs`
`unacked_messages_are_redelivered_on_reconnect`, `tezca-relay/tests/limits.rs`
`ttl_expires_messages_and_mailboxes`.
