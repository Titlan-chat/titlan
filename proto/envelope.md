<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Tezca Wire Envelope — Specification v1

**Status: FROZEN — Titlan wire protocol, spec 1.0 (Phase 5, unit 5a-3).**
This document is the root of the `/proto` tree, the payload-type **numbering
authority**, and the home of the versioning rules. Together with its
companions it is third-party implementable:

| document | scope |
|---|---|
| `proto/envelope.md` (this) | outer envelope, inner frame, payload-type registry, unknown-type handling, padding, versioning and relay coordination |
| `proto/pairing.md` | pairing bundle v1, pair-offer **v3** (v1/v2 retired), pairing control frames, QR/link threat model |
| `proto/inner-frame.md` | message/control discrimination and the control-frame layouts (`pair-ack/2`, `mailbox-update/2`,`/3`, `recovery-hello/1`) |
| `proto/recovery.md` | §10.7 derived-mailbox recovery protocol (recovery root, PRF, generation window, rotation) |
| `proto/relay-api.md` | relay HTTP/WebSocket API `/v1/` |

All integers are big-endian. MUST / SHOULD / MAY are normative. Every
normative statement in the `/proto` tree is backed by the reference
implementation (`tezca-core`, `tezca-relay`) and its committed tests; the
vectors a third party tests against are listed in §Conformance vectors. Design
rationale is in the ratified freezes `docs/design/2026-07-horizon-freeze.md`
(Horizon, §H1–§H8) and `docs/design/2026-08-pair-offer-v3-freeze.md` (pair-offer
v3); this document cites them by section and does not restate decisions.

## Frozen component versions (spec 1.0)

| component | version selector | frozen value | specified in |
|---|---|---|---|
| outer envelope | byte 4 `version` | `0x01` | this document, Layer 1 |
| inner frame | `payload_type` + `type_version` | registry below | this document, Layer 2 |
| pairing bundle | `format_version` | `0x01` | `pairing.md` |
| pairing offer | `offer_version` | `0x03` (`0x01` and `0x02` retired — rejected) | `pairing.md` |
| control frames | `type_version` per type | `pair-ack/2`; `mailbox-update/1`, `/2`, `/3`; `recovery-hello/1` | `inner-frame.md`, `pairing.md` |
| relay API | URL prefix | `/v1/` | `relay-api.md` |

**Compatibility promise (frozen).** The formats above change only by a
**version bump** (a new value of the relevant selector) or by a
**registry-controlled addition** (a new payload type, or a new `type_version`
of an existing type, entered in this document) — never by in-place
redefinition of a frozen value. A spec-1.0 receiver accepts exactly the frozen
values and rejects every other version cleanly: a typed rejection, never a
crash, never a guess. Every Titlan-defined struct is version-led so a future
version produces bytes a spec-1.0 receiver rejects by construction (Horizon
§H2.3). Relay coordination for an outer-version bump is in §Versioning and
relay coordination.

Reference: `tezca-core/src/envelope/mod.rs` (`VERSION`, `Envelope::parse`),
`tezca-core/src/pairing.rs` (`FORMAT_VERSION`, `OFFER_VERSION_V3`),
`tezca-core/src/recovery.rs` (`MAILBOX_LABEL` `…-v1`).

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
| 4 | 1 | version | `0x01`; any other value ⇒ reject (unsupported version). Spec-1.0 receivers accept exactly {1}. |
| 5 | 1 | kind | `0x01` session-setup (libsignal `PreKeySignalMessage`), `0x02` ratchet (`SignalMessage`); other ⇒ reject (unknown kind) |
| 6 | 2 | reserved | `0x0000`; any other value ⇒ reject (reserved-must-be-zero) |
| 8 | … | ciphertext | libsignal message bytes, to end of blob; MUST be ≥ 1 byte |

Minimum well-formed envelope: **9 bytes**. There is deliberately **no
cleartext length field and no cleartext payload-type field**.

Receiver rules, applied in this order — the first failing check names the
rejection class: (1) total length ≤ 8 ⇒ malformed; (2) magic; (3) version;
(4) kind; (5) reserved. The ciphertext is never inspected by the envelope
layer; it is handed to the ratchet whole.

Relay admission is a strict subset of these rules: a relay validates ONLY
bytes 0–4 (magic + version) and the 9-byte minimum, and reads nothing else
(`relay-api.md`; §Versioning and relay coordination).

Reference: `tezca-core/src/envelope/mod.rs` (`Envelope::encode`,
`Envelope::parse`, `EnvelopeKind::try_from`); tests
`tezca-core/tests/envelope_spec.rs` (`golden_outer_*`, `outer_negatives`,
`prop_outer_*`); `tezca-relay/src/wire.rs` (`deposit_admissible`).

## Layer 2 — inner frame (plaintext of the ratchet encryption)

| offset | size | field | rule |
|---|---|---|---|
| 0 | 1 | payload_type | registry below; unknown ⇒ reject (unknown type) |
| 1 | 1 | type_version | version of that payload type; `chat/1` = (`0x01`, `0x01`) |
| 2 | 4 | payload_len | u32; `6 + payload_len` MUST fit the frame |
| 6 | N | payload | |
| 6+N | P | padding | `0x00` bytes to exactly one configured bucket size |

Receiver rules, applied in this order (all violations are clean, typed
rejections):
1. Total decrypted frame length MUST equal exactly one configured bucket
   (invalid bucket).
2. `payload_type` MUST be a registry byte (unknown payload type).
3. `6 + payload_len` MUST be ≤ frame length (malformed).
4. Every byte after the payload MUST be `0x00` (invalid padding).

`type_version` is not validated by the frame parser; each payload type
interprets it (§Unknown and unsupported types).

Sender rules: if `payload_len > largest_bucket − 6`, fail BEFORE any
cryptographic operation runs (payload too large); otherwise pad to the
**smallest** bucket of the profile that holds `6 + payload_len`.

Reference: `tezca-core/src/envelope/inner.rs` (`INNER_HEADER_LEN`,
`InnerFrame::encode`, `InnerFrame::parse`); tests `envelope_spec.rs`
(`golden_inner_*`, `inner_negatives`, `bucket_boundaries`,
`oversize_fails_before_any_crypto`, `prop_inner_*`).

## Control-frame payload header

Every **control-class** payload (registry types `0x05`–`0x07`, and any future
control type) begins with a one-byte `version` field whose value equals the
frame's `type_version`; the remaining fields follow per the owning document
(`inner-frame.md`, `pairing.md`). A parser for a given `type_version` MUST
reject a leading `version` byte other than the one it implements (malformed)
and MUST reject trailing bytes after the last defined field (malformed).

Reference: `tezca-core/src/pairing.rs` (`encode_mailbox_update` /
`parse_mailbox_update`, `encode_pair_ack_v2` / `parse_pair_ack_v2`,
`encode_mailbox_update_v2` / `parse_mailbox_update_v2`,
`encode_mailbox_update_v3` / `parse_mailbox_update_v3`),
`tezca-core/src/recovery.rs` (`encode_recovery_hello` /
`parse_recovery_hello`); producers set `type_version` to the same constant the
payload's first byte carries (`tezca-core/src/relay_client/mod.rs`, every
`InnerFrame { payload_type: …, type_version: …, payload: … }` construction);
test `pairing.rs` `mailbox_update_v1_with_trailing_bytes_is_malformed`.

## Payload type registry (this document is the numbering authority)

| byte | name | class | status at spec 1.0 |
|---|---|---|---|
| `0x01` | `chat` | message | `chat/1` implemented: payload is UTF-8 text (non-UTF-8 ⇒ malformed at extraction) |
| `0x02` | `posture` | message | **first-class reserved** — Tezca suite; frames encode/decode/round-trip; no semantics in a chat client (ack-and-discard) |
| `0x03` | `policy` | message | **first-class reserved** — as `posture` |
| `0x04` | `alert` | message | **first-class reserved** — as `posture` |
| `0x05` | `pair-ack` | control | `pair-ack/2` implemented (pairing response + proof-of-scan; `inner-frame.md`, `pairing.md`). `pair-ack/1` **RETIRED** — never produced, not parsed (`pairing.md`) |
| `0x06` | `mailbox-update` | control | `/1` one-sided recovery for conversations without a recovery root; `/2` pairing inbox-handoff; `/3` recovery-time rotation — all implemented (`inner-frame.md`, `pairing.md`, `recovery.md`) |
| `0x07` | `recovery-hello` | control | `/1` implemented — §10.7 recovery probe (`inner-frame.md`, `recovery.md`) |
| `0x08` | `receipt` | — | **RESERVED** (Horizon §H1.1): name and numeric id only, at `type_version` 1; semantics unspecified until a later design freeze |
| `0x09` | `control` | — | **RESERVED** (Horizon §H1.1), same terms; a generic escape hatch, not a commitment to multiplexing (§H1.3) |
| `0x0A` | `attachment-pointer` | — | **RESERVED** (Horizon §H1.1), same terms; the designated carrier for `tezca-blob` pointers (§H5, informative — see §Future directions) |
| `0x0B–0x7F` | — | — | unassigned; allocation requires an entry here |
| `0x80–0xFF` | — | — | private/experimental; never allocated by this registry |

Assignment record: `0x05`/`0x06` maintainer-assigned 2026-07-15; `0x07`
2026-07-19; `0x08`–`0x0A` reserved by the Horizon freeze, ratified 2026-07-30.

**First-class reserved** means: the frame encodes, decodes, and round-trips in
every conforming implementation today; only the application semantics are
absent. Each type versions independently: `posture/2` someday changes nothing
about `chat/1`.

**Reserved (name and id only)** means: the byte is taken, the name is fixed,
nothing about the eventual v1 semantics is committed, and a spec-1.0
implementation emits no such frame (there is nothing defined to emit). A
receiver handles these bytes per §Unknown and unsupported types. The reference
implementation at spec 1.0 carries no enum rows for `0x08`–`0x0A` and
classifies them at frame parse as unknown; the receiver behavior is identical
either way.

**Classes.** `0x01`–`0x04` are **message** class (delivered to the application
layer); `0x05` and above are **control** class (consumed by the sync engine,
never surfaced as a message, never counted as unread). The partition is
normative in `inner-frame.md` §Discrimination rule.

### Registry policy (Horizon §H1.3)

- Payload-type ids are assigned **only in this document, by the maintainer**.
  A byte not entered here is unknown (§Unknown and unsupported types).
- **Per-function type assignment** is the preferred pattern (the `pair-ack` /
  `mailbox-update` / `recovery-hello` precedent); the generic `control`
  reservation is an escape hatch, not a commitment to multiplexing.
- A type evolves by a new `type_version`, entered here and laid out in the
  owning document; an existing (type, type_version) pair is never redefined.
- Reserving an id commits nothing about its eventual semantics (§H1.1).

Reference: `tezca-core/src/envelope/inner.rs` (`PayloadType`,
`PayloadType::try_from`); tests `envelope_spec.rs`
(`reserved_types_round_trip_as_first_class_frames`,
`chat_extraction_declines_machine_payloads_gracefully`,
`unknown_type_is_a_protocol_error_not_a_recognized_one`).

## Unknown and unsupported types — NORMATIVE receiver behavior (Horizon §H1.4)

Two conditions are distinguished at parse time but handled identically on a
live inbox:

- **Unknown:** the `payload_type` byte is not in the registry (at spec 1.0:
  `0x0B`–`0xFF`, and `0x08`–`0x0A` for an implementation without the reserved
  rows). The frame parser rejects it (unknown payload type).
- **Recognized but unsupported:** a registry type, or a `type_version` of one,
  that this implementation does not implement — e.g. `posture/1` on a chat
  client, `pair-ack/1`, or a `mailbox-update/2` arriving anywhere but the
  pairing handoff. This is an application-level decline, **not** a protocol
  error.

**Rule.** A client that fetches a frame it cannot use — whether it fails to
decrypt, is unknown, or is recognized but unsupported — MUST **ack and
discard** it: acknowledge it to the relay so it is not redelivered, persist
nothing, raise no user-visible error, enter no redelivery loop, and log
nothing that pairs the payload type with conversation identifiers. The
listener MUST survive and keep delivering subsequent frames. The
ack-after-persist guarantee applies only to **accepted chat messages**: a
`chat/1` frame is persisted before it is acked.

Reference: `tezca-core/src/relay_client/mod.rs` (`Engine::handle_incoming` —
undecryptable ⇒ drop; `chat` ⇒ persist then deliver; unmatched types ⇒ no
action — then `conversation_listener` acks every delivered frame after
`handle_incoming` returns); `tezca-core` contains no logging call on any
receive path (`scripts/check-invariants.sh` enforces the same for the relay).
Test: `tezca-relay/tests/relay_client_e2e.rs`
`unimplemented_payload_type_is_acked_and_discarded_on_live_inbox` (a
`posture/1` frame under a live session is acked — a fresh subscriber sees no
replay — not persisted, and the listener goes on to deliver chat);
`delivered_message_is_durably_persisted` (ack-after-persist for chat).

## Padding buckets and profiles (work order §10.2 — RESOLVED 2026-07-14)

- A **padding profile** is the ordered set of permitted inner-frame bucket
  sizes. Every bucket MUST be ≥ 6 bytes (the inner header); a profile MUST
  contain at least one bucket.
- **Default profile: 512 B / 2048 B / 8192 B**, applied to the inner frame.
  Maximum payload under the default profile: **8186 bytes**.
- The profile is a **per-conversation protocol parameter**: both peers of a
  conversation MUST use the same profile, because the receiver validates frame
  length against its own profile (Layer 2 rule 1). At spec 1.0 the **default
  profile is the only deployed profile**: the reference implementation applies
  it to every conversation and exposes no per-conversation override (a
  single-bucket constructor exists but is not wired to configuration).
- Observable leak with 3 buckets: ≈ log₂3 ≈ 1.6 bits of coarse length per
  message. Conversations expected to carry mixed human+machine payload types
  SHOULD use a **single-bucket profile** so bucket size cannot proxy for
  payload type (informative guidance for future profiles).

Reference: `tezca-core/src/config.rs` (`PaddingProfile::default_profile`,
`PaddingProfile::single`, `PaddingProfile::new`, `max_payload`);
`tezca-core/src/relay_client/mod.rs` (`Engine::new` —
`PaddingProfile::default_profile()` for the engine); tests `envelope_spec.rs`
(`bucket_boundaries`, `single_bucket_profile_pads_everything_to_one_size`).

## Versioning and relay coordination

- **Version policy at spec 1.0.** There is no version negotiation. A receiver
  accepts outer `version` `0x01` only; every other value is an
  unsupported-version rejection. (The former "open item" on v2+ negotiation
  posture is closed by the lockstep fact below: a future outer version is a
  coordinated deployment, not a negotiated one.)
- **Client/relay lockstep (Horizon §H4.2).** The relay pins the outer envelope
  version at deposit admission — it accepts a blob only if `blob[4] == 0x01`
  (`relay-api.md`, `POST /v1/mailboxes/{id}/messages` ⇒ `400` otherwise). An
  **outer-envelope version bump is therefore a client-AND-relay lockstep
  change, never client-only.** Relay WebSocket delivery/ack frames carry no
  version byte; their evolution hook is the `/v1/` URL prefix.
- **Inner evolution is client-only.** The relay reads nothing past byte 4 —
  the `kind` byte, the ciphertext, and everything inside it are opaque — so
  new payload types and new `type_version`s never require a relay change.
- **Relay blob ceiling.** The relay's default `--max-blob-bytes` is 16384,
  which admits an 8192-byte inner bucket plus libsignal message overhead
  (including a `PreKeySignalMessage` carrying Kyber material); a larger blob
  is rejected with `413`. (Closes the former Phase-3 open item.)
- **Reserved: admission credential (Horizon §H6.3).** An optional, opaque
  **admission-credential field on relay operations** (connect / create /
  deposit) is reserved for org-scoped relays. At spec 1.0 it is **undefined on
  the wire**: no relay operation carries it, the reference relay reads no such
  field, and the public relay never requires it. When a later design freeze
  specifies it, it is **additive and default-absent**, carried per the relay
  API's existing conventions (header or body field), and a spec-1.0 client
  remains valid against any relay that does not require it (§H6.2(i): the
  consumer/global network is unchanged).

Reference: `tezca-relay/src/wire.rs` (`deposit_admissible`: length ≥ 9, magic,
`blob[4] == 0x01` — nothing further; unit test
`admission_checks_magic_version_and_length_only`); `tezca-relay/src/api.rs`
(`router` — body limit from `max_blob_bytes`; `deposit` ⇒ `400` on
inadmissible; handlers take only connection address, path id, and body — no
credential is read); `tezca-relay/src/config.rs` (`max_blob_bytes: 16 * 1024`);
tests `tezca-relay/tests/limits.rs` `deposit_negatives` (version `0x02` ⇒ 400;
17000-byte blob ⇒ 413), `tezca-relay/tests/zero_knowledge.rs`
`relay_treatment_is_byte_identical_for_differing_inner_payload_types`.

## Conformance vectors (NORMATIVE)

Conforming implementations MUST reproduce the envelope vectors below byte-exact
and MUST accept/reject the committed pairing-offer fixtures as stated.

| vector | location | pinned by |
|---|---|---|
| envelope V1–V5 and the negative table | this section (inline) | `tezca-core/tests/envelope_spec.rs` |
| pair-offer **v3** — accept (layout, signature, validity) | `proto/fixtures/pairing-offer-v3.link.txt` + `pairing-offer-v3.expected.txt` | `tezca-core/src/pairing.rs` `committed_conformance_vector_link_round_trips_and_parses`; `titlan-android/app/src/test/kotlin/app/titlan/pairing/QrCodecConformanceTest.kt` |
| pair-offer **v2** — reject (unsupported version 2) | `proto/fixtures/pairing-offer-v2.link.txt` + `pairing-offer-v2.expected.txt` | `tezca-core/src/pairing_v3_acceptance.rs` `r7_v2_fixture_bytes_are_unsupported_version` |

How to read the offer fixtures: `pairing.md` §Conformance vectors.

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

Relay-side negatives (`relay-api.md`; `tezca-relay/tests/limits.rs`
`deposit_negatives`): bad magic, version `0x02`, empty body, or an 8-byte
blob ⇒ `400`; a 17000-byte blob under the default ceiling ⇒ `413`.

## Future directions (INFORMATIVE — nothing here is normative)

Recorded because the Horizon freeze directs the published spec to state them;
none of it is authorized for implementation, and each requires its own design
freeze → red → green cycle.

- **Attachments are out of scope** for spec 1.0. They will never transit the
  relay: the designated future home is a separate, disk-persistent blob
  service (`tezca-blob`, Horizon §H5, protocol at the P11 freeze), addressed by
  capability and end-to-end encrypted client-side; `0x0A attachment-pointer`
  is the reserved carrier for its pointers. The relay never proxies, caches,
  or references blobs (INV-8).
- **Groups** (Horizon §H3): MLS is rejected for this architecture (a blind,
  unordered, stateless mailbox cannot provide epoch ordering). The ratified
  direction is per-sender symmetric ratchets ("sender keys") distributed over
  the existing pairwise sessions via reserved control-plane types, with
  client-side fanout; membership authority, rotation policy, and
  fanout-metadata mitigation are P10 freeze scope. The relay stays
  group-unaware.
- **Identity is a device-set** (Horizon §H2): spec 1.0 fixes the set size at
  exactly one (`pairing.md` §Device-set semantics); the device model is P7
  freeze scope.
- **Org control plane** (Horizon §H6): org-scoped relays, admin-issued pairing
  offers, client-side attestation, and the admission-credential hook reserved
  above; the consumer/global network — no accounts, no directory — is
  unchanged.
