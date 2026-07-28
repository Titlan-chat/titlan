<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Tezca Wire Envelope — Specification v1

**Status: NORMATIVE for envelope framing (Phase 2).** Session-setup payload
semantics and relay transport are specified separately (`proto/pairing.md`,
Phase 3 relay docs). All integers are big-endian.

## Design constraints (locked)

- **Versioned and typed** (A8, INV-4): unknown versions and unknown payload
  types are rejected cleanly — never a crash, never a guess.
- **Sealed metadata** (A6): the relay sees mailbox ID, timing, and the outer
  envelope only. Payload type and true length are inside the encryption.
- **Padded buckets** (A8): inner plaintext is padded to fixed bucket sizes
  BEFORE encryption, so padding is authenticated and observers see only
  bucket-clustered ciphertext sizes.
- **Transport-agnostic** (INV-5): relay addresses come from conversation
  configuration; nothing in the envelope names a relay.

## Layer 1 — outer envelope (visible to relay and wire)

| offset | size | field | rule |
|---|---|---|---|
| 0 | 4 | magic | `54 5A 43 41` (`"TZCA"`); mismatch ⇒ reject (malformed) |
| 4 | 1 | version | `0x01`; any other value ⇒ reject (unsupported version). v1 receivers accept exactly {1}. |
| 5 | 1 | kind | `0x01` session-setup (libsignal `PreKeySignalMessage`), `0x02` ratchet (`SignalMessage`); other ⇒ reject |
| 6 | 2 | reserved | `0x0000`; any other value ⇒ reject in v1 |
| 8 | … | ciphertext | libsignal message bytes, to end of blob; MUST be ≥ 1 byte |

Minimum well-formed envelope: 9 bytes. There is deliberately **no cleartext
length field and no cleartext payload-type field**.

## Layer 2 — inner frame (plaintext of the ratchet encryption)

| offset | size | field | rule |
|---|---|---|---|
| 0 | 1 | payload_type | registry below; unknown ⇒ reject (unknown type) |
| 1 | 1 | type_version | version of that payload type; `chat/1` = (`0x01`, `0x01`) |
| 2 | 4 | payload_len | u32; `6 + payload_len` MUST fit the frame |
| 6 | N | payload | |
| 6+N | P | padding | `0x00` bytes to exactly one configured bucket size |

Receiver rules (all violations are clean, typed rejections):
1. Total decrypted frame length MUST equal exactly one configured bucket.
2. `6 + payload_len` MUST be ≤ frame length.
3. Every byte after the payload MUST be `0x00`.

Sender rule: if `payload_len > largest_bucket − 6`, fail BEFORE any
cryptographic operation runs (`PayloadTooLarge`).

## Payload type registry (this document is the numbering authority)

| byte | name | status |
|---|---|---|
| `0x01` | `chat` | chat/1 implemented (MVP): payload is UTF-8 text |
| `0x02` | `posture` | **first-class reserved** — Tezca suite |
| `0x03` | `policy` | **first-class reserved** — Tezca suite |
| `0x04` | `alert` | **first-class reserved** — Tezca suite |
| `0x05` | `pair-ack` | pairing control: reply coordinates (`pair-ack/1` Phase 4a; `pair-ack/2` proof-of-scan Phase 4b-2) — see `pairing.md` / `inner-frame.md` |
| `0x06` | `mailbox-update` | pairing/recovery control: inbox recovery + rotation/handoff (`/1` Phase 4a; `/2` pairing handoff, `/3` recovery rotation, Phase 4b-2) — see `inner-frame.md` |
| `0x07` | `recovery-hello` | §10.7 recovery probe (Phase 4b-2, maintainer-assigned 2026-07-19) — see `inner-frame.md` |
| `0x08–0x7F` | — | unassigned; allocation requires an entry here |
| `0x80–0xFF` | — | private/experimental; never allocated by this registry |

`0x05` (`pair-ack`) and `0x06` (`mailbox-update`) were **assigned by the
maintainer on 2026-07-15** (this document is the numbering authority; byte
assignment is a maintainer decision).

**First-class reserved** means: the frame encodes, decodes, and round-trips
in every conforming implementation today. A client that recognizes a type but
does not implement it responds at the application layer (ack-and-drop /
"recognized but unsupported") — this is NOT a protocol error. Only bytes
outside the registry are protocol errors. Each type versions independently:
`posture/2` someday changes nothing about `chat/1`.

## Padding buckets (work order §10.2 — RESOLVED 2026-07-14)

- Default profile: **512 B / 2048 B / 8192 B**, applied to the inner frame.
  Maximum payload under the default profile: **8186 bytes**.
- Profiles are **per-conversation** configuration, like the relay address.
- Observable leak with 3 buckets: ≈ log₂3 ≈ 1.6 bits of coarse length per
  message. Conversations expected to carry mixed human+machine payload types
  SHOULD use a **single-bucket profile** so bucket size cannot proxy for
  payload type.

## Test vectors (NORMATIVE)

Conforming implementations MUST reproduce these byte-exact. The reference
test suite is `tezca-core/tests/envelope_spec.rs`.

### V1 — outer, ratchet kind

Envelope: kind `0x02`, ciphertext = 16 × `0xAA`:

```
545a434101020000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

### V2 — outer, session-setup kind

Envelope: kind `0x01`, ciphertext = `01 02 03`:

```
545a434101010000010203
```

### V3 — inner, chat/1 "hi titlan" (default profile)

9-byte payload ⇒ 512-byte frame: the 15 bytes below, then 497 × `00`.

```
0101000000096869207469746c616e
```

### V4 — inner, posture/1 with empty payload (default profile)

512-byte frame: the 6 bytes below, then 506 × `00`. (Demonstrates a reserved
platform type framing byte-exactly today.)

```
020100000000
```

### V5 — inner, alert/1 payload `DE AD` (default profile)

512-byte frame: the 8 bytes below, then 504 × `00`.

```
040100000002dead
```

### Negative vectors

| input | required rejection |
|---|---|
| outer, version byte `0x02` | unsupported version |
| outer, kind byte `0x03` | unknown kind |
| outer, reserved `0x0001` | reserved-must-be-zero |
| outer, 8 bytes (header only) | malformed (empty ciphertext) |
| inner, 513-byte frame (default profile) | invalid bucket |
| inner, `payload_len` = 507 in a 512-byte frame | malformed (length exceeds frame) |
| inner, valid frame with one padding byte `0x01` | invalid padding |
| inner, payload_type `0x4A` | unknown payload type |
| inner, chat/1 payload 8187 bytes (sender side) | payload too large (max 8186) |

## Open items (Phase 5 completes the spec)

- Version negotiation posture for v2+ (v1 policy: accept exactly {1})
- Relay-side maximum blob size (Phase 3, must admit an 8192-bucket frame
  plus ratchet overhead)
