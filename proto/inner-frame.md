<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan Inner Frame — Message / Control Discrimination

**Status: NORMATIVE for Phase 4b-2** (frozen design 2026-07-18, §3/§8;
registry ratified 2026-07-19; maintainer-ratified B1/B2 + F1/F2 2026-07-19 —
dual-contribution recovery root, HMAC-PRF mailbox derivation, proof over
`bundle ‖ contribution`, inbox-handoff `/2` pairing vs `/3` rotation). This document specifies how a receiver tells a
**human message** from a **protocol-internal control frame** inside the sealed
payload, and defines the control frames 4b-2 uses: the pairing response
`pair-ack/2`, the rotation announcement `inbox-handoff`, and the recovery
probe `recovery-hello`. It is third-party implementable.

**The A8 outer envelope enum is UNTOUCHED.** Outer `kind` stays exactly
`0x01` session-setup / `0x02` ratchet (`proto/envelope.md` Layer 1). All
discrimination described here happens in **Layer 2 — the inner frame**, which
exists only as plaintext inside the libsignal encryption; the relay never sees
any of it (A6).

## Discrimination rule

The inner frame's `payload_type` byte (`proto/envelope.md` Layer 2, the
numbering authority) is the sole discriminator. No new header field is added —
the "message/control discrimination" is a **partition of the existing
registry**, stated normatively here so implementers do not have to infer it:

| payload_type range | class | receiver behavior |
|---|---|---|
| `0x01`–`0x04` (`chat`, `posture`, `policy`, `alert`) | **message** | delivered to the application layer (chat is surfaced; reserved Tezca types are ack-and-drop on an MVP chat client) |
| `0x05`+ (`pair-ack`, `mailbox-update`, and the 4b-2 control frames below) | **control** | consumed by the sync engine; **never** surfaced as a message and **never** counted as unread |

A control frame that fails to parse is a clean typed rejection (INV-4), never
a crash and never a message. A `message`-class frame is delivered even when
its specific type/version is unsupported (`RecognizedButUnsupported`) — that
is an application decision, not a protocol error. The two classes are handled
by different code paths and MUST NOT cross: a control frame decoded as a
message, or vice-versa, is a conformance failure.

## Control frame: `pair-ack/2` (pairing response + proof-of-scan)

`pair-ack/2` is the responder's (B's) FIRST sealed frame back to the offerer
(A) after a v2 offer scan (frozen design §3; `proto/pairing.md`). It proves
possession of the scanned offer and, in the SAME frame, announces B's own
routing inbox — so the return direction (B→A) needs no separate
`inbox-handoff` at pairing.

It rides the existing `pair-ack` payload_type `0x05` at **type_version
`0x02`** — no new registry byte. A v1 (`pair-ack/1`) receiver rejects `0x02`
cleanly (`RecognizedButUnsupported`) rather than mis-parsing.

| field | encoding |
|---|---|
| version | u8 = `0x02` |
| responder_bundle | B's pairing bundle (self-delimiting, `proto/pairing.md` §Pairing bundle) — identity key + signed / Kyber / one-time prekeys |
| relay_url | u16 len + UTF-8 (B's relay for this conversation) |
| inbox_id | 43 bytes ASCII (B's per-conversation inbox) |
| recovery_root_contribution | 32 bytes CSPRNG — B's contribution to the §8 recovery root (B2; never in the offer) |
| proof | 32 bytes = `HMAC-SHA256(pairing_secret, responder_bundle ‖ recovery_root_contribution)` via libsignal (INV-6) |

A verifies `proof` over the received `responder_bundle ‖
recovery_root_contribution` (F2 — the contribution IS in the MAC input, so an
off-path party cannot substitute a recovery-root contribution without failing
proof-of-scan), keyed by the `pairing_secret` A minted, in **constant time**.
Mismatch ⇒ `CoreError::ProofOfScanFailed` and A **invalidates** the offer
(`proto/pairing.md` §Proof-of-scan). On success A records B's
`relay_url`/`inbox_id` as the conversation's routing target, keeps B's
`recovery_root_contribution`, and retires the pairing mailbox; A's own
long-lived inbox and A's own contribution are handed to B by a subsequent
`inbox-handoff` (`mailbox-update/2`).

## Control frame: `inbox-handoff` (mailbox rotation)

`inbox-handoff` is a **pure rotation announcement**: it announces a fresh
**relay-generated, long-lived** inbox over an existing session and asks the
peer to route there, retiring a bridge mailbox in favor of a durable home. It
is used by the offerer (A) at pairing to hand A's long-lived inbox to B and
retire the pairing mailbox, and by both parties at §10.7 recovery convergence
to retire the derived mailboxes. The pairing RETURN direction (B→A) does NOT
use it — `pair-ack/2` folds B's inbox announcement into the proof-of-scan
frame.

It rides payload_type `0x06` (`mailbox-update`) with **two distinct
type_versions (F1)** that differ structurally, so the frame's role is explicit
and the parser rejects a length mismatch cleanly (`Malformed`) rather than
guessing:

- **`mailbox-update/2` — pairing handoff.** Carries A's recovery-root
  contribution (the offerer's half of the B2 dual-contribution root).

  | field | encoding |
  |---|---|
  | version | u8 = `0x02` |
  | relay_url | u16 len + UTF-8 |
  | inbox_id | 43 bytes ASCII (the new relay-generated inbox) |
  | recovery_root_contribution | 32 bytes CSPRNG — A's contribution |

- **`mailbox-update/3` — recovery-time rotation.** The recovery root already
  exists on both ends, so the contribution field is **structurally absent** (no
  all-zero sentinel — the frame is simply shorter, and a `/3` frame carrying
  trailing bytes is `Malformed`).

  | field | encoding |
  |---|---|
  | version | u8 = `0x03` |
  | relay_url | u16 len + UTF-8 |
  | inbox_id | 43 bytes ASCII (the new relay-generated inbox) |

A v1 (`mailbox-update/1`) receiver rejects `0x02`/`0x03` cleanly
(`RecognizedButUnsupported`). The receiver adopts the announced inbox as the
peer's routing target; on `/2` it also derives and stores the recovery root
(below).

### Rotation ordering (maintainer-ratified convergence + rotation ordering, 2026-07-19)

The rotation that finishes §10.7 recovery is **asymmetric and role-ordered** so
the two parties never rotate simultaneously into inboxes the other has already
left, and so no in-flight chat is dropped during the switch:

- The **OFFERER initiates** rotation; the responder NEVER does. The pairing role
  is persisted at pairing, so this is a deterministic tiebreak.
- `mailbox-update/3` is deposited into the peer's derived inbox **at the
  generation the peer REPORTED** (in its `recovery-hello`), never at `max(g)` —
  a generation outside the peer's receive window is unread. The offerer
  therefore initiates only once it holds a hello whose reported generation
  equals its own (converged).
- **Normative flow (drain-then-switch).**
  1. The offerer mints a fresh relay-generated inbox `F_A`, deposits `/3{F_A}`
     into the RESPONDER'S derived inbox, and **STAYS subscribed on its own
     derived inbox** — draining any in-flight chat the responder is still
     sending there.
  2. The responder receives `/3{F_A}`, routes its sends to `F_A`, mints `F_B`,
     and deposits `/3{F_B}` **into the OFFERER'S derived inbox** (NOT `F_A` —
     the offerer is not subscribed on `F_A` yet), then switches its receive to
     `F_B` and deletes its own derived inbox (or the relay idle TTL reaps it).
  3. The offerer receives `/3{F_B}` on its derived inbox, routes its sends to
     `F_B`, switches its receive to `F_A`, and deletes its derived inbox —
     **receipt of the second leg is the implicit ack**.
- **Why this is safe.** Per-mailbox delivery is FIFO, so the offerer drains
  every chat message the responder deposited into the offerer's derived inbox
  BEFORE the `/3{F_B}` that triggers the switch — no message is stranded. A
  late deposit into an already-deleted derived inbox simply yields `404` →
  loss detection → a bounded fresh recovery cycle (the derived IDs remain
  re-derivable), and messages keep flowing over the derived inboxes meanwhile.

## Derived recovery-mailbox IDs (B1/B2, maintainer-ratified 2026-07-19)

Both mailboxes of a conversation share a relay, so a relay restart is TOTAL
routing loss; the derived mailboxes let both parties re-establish routing
without re-pairing.

- **Root (B2 dual-contribution).** Each party contributes 32 CSPRNG bytes at
  pairing — the responder's `recovery_root_contribution` in `pair-ack/2`, the
  offerer's in `mailbox-update/2`. Neither is ever in the offer/QR. The root is

  ```
  root = HMAC-SHA256(A_contribution, B_contribution)          # A = offerer, B = responder
  ```

  Both parties compute the identical root; the offerer's contribution keys the
  HMAC and the responder's is the message.
- **Mailbox ID (B1 HMAC-PRF).**

  ```
  mailbox_id = base64url_nopad(
      HMAC-SHA256(root, "titlan-recovery-mailbox-v1" ‖ role_label ‖ generation_u32_be)
  )                                                            # 43 chars
  role_label ∈ { "offerer", "responder" }  = the mailbox OWNER's pairing role
  ```

  256-bit, unguessable, opaque to the relay; role- and generation-separated so
  the two directions and successive generations never collide.
- **Why HMAC-PRF, not literal HKDF.** libsignal exposes no public HKDF; it does
  expose HMAC-SHA256 (`signal-crypto` `CryptographicMac`). For a uniformly
  random `root`, HKDF-Expand ≡ HMAC-PRF, so a single HMAC is an equivalent KDF
  and keeps every byte inside libsignal (INV-6).
- **Why not a `pairing_secret`-derived root (2a, REJECTED).** The
  `pairing_secret` travels in the offer/QR; deriving the root from it would let
  a QR photographer compute the entire future recovery-mailbox sequence and
  PUT-squat those IDs — a permanent recovery-denial DoS. The dual-contribution
  root is never in the offer, so a photographer learns nothing about it.
- **Edge — total loss before the handoff lands.** If the relay dies after
  `pair-ack/2` but before `mailbox-update/2` is delivered, the two parties do
  not share a root yet (one side has only its own contribution). Recovery is
  impossible; the conversation falls back to the re-pair path
  (`conversation-needs-repair`). Accepted (frozen §8).

## Control frame: `recovery-hello`

`recovery-hello` is the idempotent probe a recovering sender deposits into a
peer's **derived** recovery mailboxes (frozen design §8). It carries just
enough for the peer to (a) confirm a verified in-band contact and (b) learn
the sender's current generation so both sides converge on `max(g_A, g_B)`.

| field | encoding |
|---|---|
| version | u8 = `0x01` |
| generation | u32 BE — the sender's current recovery generation `g` |
| nonce | 16 bytes — random; makes redeliveries idempotent-detectable so a redelivered hello is not reprocessed |

Rules:
- **Convergence mechanism (maintainer-ratified 2026-07-19).** The receiver MUST
  subscribe its OWN derived inbox at its current generation `own_g` and MAY also
  subscribe lower generations; the normative convergence mechanism is the
  SENDER's forward probe, which deposits the `recovery-hello` across peer
  generations `[peer_g … peer_g+(W−1)]` after PUT-CREATING those inboxes
  (create-before-deposit is load-bearing). Because the sender's window covers
  the receiver's `own_g` whenever the relative offset is `≤ W−1`, a
  current-generation-only receiver converges over EXACTLY the recoverable range
  — coinciding with the `≥ W` exhaustion bound below. A receiver-side window
  `[own_g−(W−1) … own_g]` would extend reach to a `2W−2` offset, but only into
  offsets already defined as exhausted (`≥ W`), so it adds no recoverable reach;
  the receiver-side window is therefore OPTIONAL.
- First **verified** `recovery-hello` receipt in either direction → both sides
  adopt `max(own_g, generation)`; once converged (a hello whose reported
  generation equals `own_g`) the OFFERER runs the role-ordered rotation
  (§inbox-handoff Rotation ordering), retiring the derived mailboxes.
- **Hello answers hello (maintainer-ratified 2026-07-19).** On a verified
  `recovery-hello`, a party that has NOT already sent one at its current
  generation replies with a hello into the sender's derived inbox **at the
  generation the received hello reported**; `(generation, nonce)` dedup
  terminates the exchange after one round. Rationale: bilateral convergence —
  without the reply only one side learns the other is present.
- A relative generation offset `≥ W` (W = 4, config) → the frame cannot land
  in a live window → `conversation-needs-repair` (`CoreError::ConversationNeedsRepair`).
- Relay `429`s while depositing are **pacing signals**, never failures: they
  do not count toward the 3-cycle exhaustion; the client paces with backoff.

### Verified receipt and replay dedup

- **"Verified"** := successful **ratchet decryption** of the frame (the sealed
  payload authenticates under the conversation's Double Ratchet). An
  undecryptable deposit is not a verified contact and does not advance
  convergence — only a verified `recovery-hello` moves generations.
- The receiver **dedups by `(generation, nonce)`**: a `recovery-hello` whose
  pair has already been seen is acknowledged but NOT reprocessed, so
  redeliveries (the idempotent probe hitting multiple window generations) are
  applied exactly once.
- Dedup **retention 14 days** (config, aligned to the relay message TTL —
  `relay-api.md` `--ttl-secs`; an entry older than one TTL is unreplayable, so
  it may be evicted safely), with a **512-entry per-conversation cap**,
  oldest-evicted (config).

### Registry status (MAINTAINER-RATIFIED 2026-07-19)

Byte assignment is a maintainer decision; the numbering authority is
`proto/envelope.md` (precedent: `0x05`/`0x06` maintainer-assigned 2026-07-15).
Ratified for 4b-2:

- `pair-ack/2` → **no new byte** — rides `pair-ack` `0x05` at type_version
  `0x02` (pairing response + proof-of-scan, above).
- `inbox-handoff` → **no new byte** — rides `mailbox-update` `0x06` at
  type_version `0x02` (rotation announcement, above).
- `recovery-hello` → **`0x07`** (RATIFIED). The `proto/envelope.md` registry
  row and the `PayloadType::RecoveryHello` variant in
  `tezca-core/src/envelope/inner.rs` land in the 4b-2 GREEN commit, per the
  standing convention that the RED commit ships only the ratified spec, not
  new registry code.
