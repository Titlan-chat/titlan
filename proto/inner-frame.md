<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan Inner Frame — Message / Control Discrimination

**Status: NORMATIVE for Phase 4b-2** (frozen design 2026-07-18, §3/§8;
registry ratified 2026-07-19). This document specifies how a receiver tells a
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
| proof | 32 bytes = `HMAC-SHA256(pairing_secret, responder_bundle)` via libsignal (INV-6) |

A verifies `proof` over the received `responder_bundle`, keyed by the
`pairing_secret` A minted, in **constant time**. Mismatch ⇒
`CoreError::ProofOfScanFailed` and A **invalidates** the offer
(`proto/pairing.md` §Proof-of-scan). On success A records B's
`relay_url`/`inbox_id` as the conversation's routing target and retires the
pairing mailbox; A's own long-lived inbox is handed to B by a subsequent
`inbox-handoff`.

## Control frame: `inbox-handoff` (mailbox rotation)

`inbox-handoff` is a **pure rotation announcement**: it announces a fresh
**relay-generated, long-lived** inbox over an existing session and asks the
peer to route there, retiring a bridge mailbox in favor of a durable home. It
is used by the offerer (A) at pairing to hand A's long-lived inbox to B and
retire the pairing mailbox, and by both parties at §10.7 recovery convergence
to retire the derived mailboxes. The pairing RETURN direction (B→A) does NOT
use it — `pair-ack/2` folds B's inbox announcement into the proof-of-scan
frame.

Encoding is **identical to `mailbox-update/1`** (`proto/pairing.md`
§Control messages) — relay + new inbox — carried as **`mailbox-update`
type_version `0x02`** on payload_type `0x06`. Reusing the existing registry
byte with a bumped type-version keeps the outer registry unchanged; a v1
receiver rejects `0x02` cleanly (`RecognizedButUnsupported`) rather than
mis-parsing.

| field | encoding |
|---|---|
| version | u8 = `0x02` |
| relay_url | u16 len + UTF-8 |
| inbox_id | 43 bytes ASCII (the new relay-generated inbox) |

The difference from `mailbox-update/1` is **semantic, not structural**: v1 was
one-sided recovery of a single lost direction; v2 is the rotation handoff that
retires a bridge mailbox (pairing or derived) in favor of a durable home. The
receiver adopts the announced inbox as the peer's routing target for the
conversation.

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
- `recovery-hello` is deposited into peer generations `[peer_g … peer_g+(W−1)]`
  after the sender PUT-CREATES those derived inboxes (the create-before-deposit
  order is load-bearing for the 2W bound; frozen design §8).
- First **verified** `recovery-hello` receipt in either direction → both sides
  adopt `max(own_g, generation)` and immediately run the rotation
  (`inbox-handoff`), retiring the derived mailboxes.
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
