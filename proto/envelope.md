<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Tezca Wire Envelope — Specification

**Status: DRAFT SKELETON (Phase 1).** The normative encoding is implemented
and finalized in Phase 2; Phase 5 completes this document to the point where
a third party can implement a compatible client.

## Design constraints (locked)

- **Versioned and typed from day one** (A8, INV-4): every wire message carries
  a protocol version and a payload type. Receivers reject unknown versions and
  unknown payload types cleanly — never crash, never guess.
- **Sealed sender** (A6): the relay learns recipient mailbox ID and timing
  only. Sender identity travels inside the encrypted envelope.
- **Padded ciphertext buckets** (A8): ciphertexts are padded to fixed-size
  buckets for traffic-analysis resistance.
- **Transport-agnostic**: the envelope is the unit deposited to and delivered
  by any relay; relay addresses come from conversation/team configuration
  (INV-5), never from the envelope or from constants outside the single
  default-config value.

## Envelope structure (shape, non-normative until Phase 2)

| Field | Description |
|-------|-------------|
| `version` | Protocol version. Unknown → reject cleanly (INV-4). |
| `payload_type` | Typed enum, see registry below. Unknown → reject cleanly. |
| `ciphertext` | Sealed-sender encrypted payload (libsignal), padded to a bucket size. |

## Payload type registry

| Type | Status |
|------|--------|
| `chat/1` | Implemented in MVP (Phase 2) |
| `posture/1` | Reserved — Tezca suite, not in MVP |
| `policy/1` | Reserved — Tezca suite, not in MVP |
| `alert/1` | Reserved — Tezca suite, not in MVP |

Reserved types exist so the envelope never needs a breaking change when the
platform grows machine payloads. The MVP implements `chat/1` only and rejects
everything else as unknown.

## Padding buckets

Proposed defaults: **512 B / 2 KiB / 8 KiB** (work order §6 Phase 2).
Implemented as configuration; final values require human approval before
release (work order §10.2) — do not treat the proposal as decided.

## Open items (tracked for Phase 2)

- Normative byte-level encoding of header and fields
- Version negotiation / downgrade-rejection rules
- Maximum envelope size and oversize handling
- Test vectors (including malformed, wrong-version, unknown-type,
  oversized, and replayed envelopes — work order §8 negative tests)
