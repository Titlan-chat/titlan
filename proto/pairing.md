<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan Pairing — Bundle v1 and Pairing Offer v3

**Status: FROZEN — Titlan wire protocol spec 1.0 (Phase 5, unit 5a-3).**
This document specifies the **pairing bundle** (format v1), the **pairing
offer** (v3 — the only offer version a spec-1.0 acceptor admits), the pairing
control frame `mailbox-update/1`, and the QR/link threat model. The pairing
response `pair-ack/2` and the handoff frames `mailbox-update/2`,`/3` are laid
out in `proto/inner-frame.md`; derived-mailbox recovery is `proto/recovery.md`;
the payload-type registry is `proto/envelope.md`.

Ratified sources this document implements and cites:
`docs/design/2026-08-pair-offer-v3-freeze.md` (the v3 freeze, V3-D1…D4,
ratified 2026-08-10) and `docs/design/2026-07-horizon-freeze.md` (§H2
device-set, §H7 offer lifetime). **Pairing offer v2 and the v1 QR payload are
RETIRED** (freeze §7 / Horizon §H7.5): their layouts are kept at the foot of
this document for the record only, and a spec-1.0 acceptor rejects both.

All integers big-endian; `len`-prefixed fields carry a u16 byte length unless
stated otherwise.

---

# Part I — Pairing bundle (format v1, NORMATIVE)

The pairing bundle is the serialized libsignal pre-key bundle exchanged
out-of-band at pairing (A7). All key material inside is produced and
serialized by libsignal (INV-6); this format is pure framing.

| field | encoding |
|---|---|
| format_version | u8 = `0x01`; unknown ⇒ reject (malformed) |
| address_name | u16 len + UTF-8 (local pairing pseudonym: the lowercase hex encoding of the 33-byte serialized identity public key — 66 hex characters; see §Address derivation) |
| registration_id | u32 |
| device_id | u32; **MUST be 1** in protocol v1 — any other value ⇒ reject (malformed); see §Device-set semantics |
| identity_key | u16 len + libsignal-serialized public key |
| signed_prekey_id | u32 |
| signed_prekey_pub | u16 len + bytes |
| signed_prekey_sig | u16 len + bytes |
| kyber_prekey_id | u32 |
| kyber_prekey_pub | u16 len + bytes (ML-KEM — REQUIRED; a bundle without post-quantum material is invalid, A2) |
| kyber_prekey_sig | u16 len + bytes |
| onetime_prekey_id | u32; `0xFFFFFFFF` = absent |
| onetime_prekey_pub | u16 len + bytes; len 0 when absent |

Receiver rules, in parse order: reject an unknown `format_version`; reject a
non-UTF-8 `address_name`; reject `device_id ≠ 1` **before any key material is
touched** (fail-closed); reject an empty `kyber_prekey_pub`; reject any
truncation; reject any trailing bytes after the last field. Every rejection is
the malformed class. Identity keys received here are recorded as TOFU
(trust-on-first-use) identities; key-change handling and safety numbers are
post-MVP (directory/key-transparency deferred per A7).

Reference: `tezca-core/src/pairing.rs` (`FORMAT_VERSION`, `ABSENT_ID`,
`serialize`, `parse`, `put_bytes`); `tezca-core/src/session.rs`
(`establish_session` — the sole bundle consumer, PQXDH via libsignal
`process_prekey_bundle`). Tests: `pairing.rs`
`bundle_with_device_id_other_than_1_is_malformed`;
`tezca-core/tests/session_roundtrip.rs`
`pqxdh_establishment_and_first_roundtrip`,
`bundles_carry_post_quantum_material`.

## Device-set semantics (Horizon §H2)

**An identity is a set of one or more devices sharing a pairing context.**
Protocol v1 fixes the set size at **exactly one**: the device carried in the
pairing bundle is the sole member. The v1 collapse of identity ↔ identity-key ↔
address ↔ device into a 1:1:1:1 relationship is a *property of v1*, not part
of the definition; the device model is P7 design-freeze scope.

**v1 conformance rule.** The bundle's `device_id` field **MUST equal 1**.
Parsers **MUST reject any other value as malformed**, at parse time, before
any session state is created. The u32 wire field remains as headroom; a later
protocol version relaxes the rule. Sessions are addressed as
`(address_name, 1)`; the sender of an inbound message is **derived** from the
identity key it carries, never parsed from a device field (nothing to
version).

Reference: `tezca-core/src/pairing.rs` (`parse` — `device_id != 1` ⇒
`Malformed("unsupported device id in v1")`); `tezca-core/src/identity.rs`
(`DEVICE_ID = 1`); `tezca-core/src/session.rs` (`device_id`, `address`,
`local_protocol_address`, `decrypt_setup_from_unknown`). Test:
`bundle_with_device_id_other_than_1_is_malformed`.

## Address derivation

A party's pairing address (`address_name`) is the lowercase hex of its
serialized identity public key, derived deterministically so a recipient can
compute a sender's address from the identity key embedded in an incoming
`PreKeySignalMessage` — needed to decrypt the pairing response (`pair-ack/2`)
that arrives on a pairing inbox whose sender is otherwise unknown (blind relay,
sealed sender). The address is a **client-side** value: it lives in the
SQLCipher-encrypted session store and, on the wire, appears solely inside
end-to-end-encrypted payloads (the bundle inside an offer or a `pair-ack/2`)
and in the out-of-band QR — never as a distinct relay-visible field (deposits
carry only the encrypted envelope, and mailbox ids are relay-generated random).
It therefore adds **no wire linkability beyond the pre-existing
`PreKeySignalMessage` identity-key exposure** described below: because the
address is a function of the identity key, anyone able to correlate by address
must already hold the key and could correlate by it directly.

Reference: `tezca-core/src/identity.rs` (`address_for_identity` —
`hex::encode(identity_key.serialize())`); `tezca-core/src/session.rs`
(`decrypt_setup_from_unknown`); `tezca-core/src/relay_client/mod.rs`
(`handle_pair_ack_v2`).

## Privacy note (threat model)

The first message(s) of a session are libsignal `PreKeySignalMessage`s, whose
header carries the sender's identity public key unencrypted inside the
(relay-opaque) blob. With no directory and per-conversation mailboxes this is
an unlinkable pseudonym, but a relay could correlate identical identity keys
across conversations during session setup. Accepted for MVP; sealed-sender-
style outer wrapping is a post-MVP hardening option.

---

# Part II — Pairing Offer — Specification v3 (NORMATIVE)

The offer is an **asymmetric** capability: the offerer (A) displays it; the
responder (B) consumes it. v3 is v2 plus an **authenticated validity window**
(`issued_at`, `ttl_s`, `offer_sig`) — the one governing offer lifetime
(Horizon §H7.1). A spec-1.0 acceptor is **v3-only**: `offer_version` `0x01`
and `0x02` are unsupported-version rejections with no compatibility window
(freeze §7, V3-D4).

## Offer payload (QR / link, byte-identical) — freeze §2, V3-D1

| field | encoding |
|---|---|
| offer_version | u8 = `0x03`; any other value ⇒ reject (unsupported version) |
| bundle | u16 len + the pairing bundle (Part I; `format_version` stays `0x01`) |
| relay_url | u16 len + UTF-8 (A's relay for this pairing) |
| pairing_inbox_id | 43 bytes (A's single-use **pairing** mailbox id, base64url as issued by the relay; MUST be valid UTF-8) |
| pairing_secret | 32 bytes — a random 256-bit secret from A's OS CSPRNG, carried **outside the key bundle** |
| issued_at | u64, Unix seconds, big-endian, **offerer clock** |
| ttl_s | u32, seconds, big-endian; default `OFFER_DEFAULT_TTL_S` = 3600 |
| offer_sig | 64 bytes — XEd25519 signature by the offer's identity key over **all preceding wire bytes** (`offer_version` … `ttl_s`) |

Trailing bytes after `offer_sig` ⇒ reject (malformed). The `pairing_secret`
is a bearer secret that only a party who obtained the actual offer bytes can
hold; it is **not** key material (not mixed into PQXDH) — it keys the
proof-of-scan MAC (§Proof-of-scan). The size delta over v2 is +76 raw bytes;
the committed v3 vector is 2073 raw bytes = 2764 base64url characters.

Reference: `tezca-core/src/pairing.rs` (`OFFER_VERSION_V3`, `OFFER_SIG_LEN`,
`PAIRING_SECRET_LEN`, `MAILBOX_ID_LEN`, `OfferV3`, `encode_pairing_offer_v3`,
`parse_offer_v3_structure`). Tests: `tezca-core/src/pairing_v3_acceptance.rs`
`r1_fresh_mint_round_trips_and_accepts`,
`r8_trailing_bytes_after_offer_sig_reject`; `pairing.rs`
`committed_conformance_vector_link_round_trips_and_parses` (the committed
prefix equals an independent construction of this table).

### Carriers

One payload is carried across two encodings — a QR code and a
`titlan://pair#<base64url-payload>` link — **byte-identical** before/after
encoding (base64url, RFC 4648 §5, no padding). A conforming implementation
MUST satisfy:

```
QR_text         = base64url_nopad(offer_bytes)          # scanners also accept the full link text
link            = "titlan://pair#" + base64url_nopad(offer_bytes)
offer_bytes'    = base64url_decode(fragment_of(link))
assert offer_bytes' == offer_bytes
```

The fragment is decoded **locally**; it never touches any server. A future
`https://titlan.chat/pair#<payload>` carries the same bytes again (App Links
migration is additive).

Reference: `tezca-core/src/pairing_v3_acceptance.rs`
`r10_qr_link_byte_identity_round_trip_v3`;
`titlan-android/app/src/main/kotlin/app/titlan/pairing/QrCodec.kt`,
`PairingScreen.kt` (`qrTextToLink`);
`titlan-android/app/src/androidTest/kotlin/app/titlan/pairing/PairingRoundTripTest.kt`
`qrAndLinkPayloadsAreByteIdentical`; Kotlin conformance guard
`QrCodecConformanceTest.kt` (decodes the committed link with the RFC 4648
url-safe decoder to the pinned bytes).

## Authentication — freeze §3, V3-D3

- **Mint:** `offer_sig = calculate_signature(identity_private_key, prefix)`
  where `prefix` is the exact serialized bytes `offer_version … ttl_s`
  (sign-the-wire-bytes; no canonicalization layer exists to get wrong).
- **Verify:** the acceptor verifies `offer_sig` over the received prefix with
  the **identity public key inside the same offer's bundle**
  (`verify_signature`). Failure ⇒ **signature-invalid** (crypto class,
  distinct from proof-of-scan failure).
- Both primitives are libsignal's own (`PrivateKey::calculate_signature` /
  `PublicKey::verify_signature`, the same operations used for pre-key
  signatures at bundle mint) — INV-6.
- **Defends:** any post-mint tamper of any offer field without identity
  substitution — specifically the timestamp-resurrection attack (an expired
  offer recovered from history, re-dated to look fresh) and
  `relay_url`/`pairing_inbox_id` redirection grief. **Does not defend:**
  wholesale substitution of the entire offer under an attacker's own identity
  — the ledgered complete-offer-compromise risk, unchanged from v2.
  Proof-of-scan semantics are untouched.

Reference: `tezca-core/src/pairing.rs` (`encode_pairing_offer_v3` — signs the
whole prefix; `parse_pairing_offer_v3` — verifies with the bundle's identity
key); `tezca-core/src/identity.rs` (pre-key signing call site, same
primitive). Tests: `r1_fresh_mint_round_trips_and_accepts` (independent
verification of the trailing 64 B), `r4_bit_flipped_issued_at_is_signature_invalid_not_expired`.

## Validity rule — freeze §4, V3-D2 (NORMATIVE)

Evaluated by the acceptor **at decode, before any network I/O** — an expired
offer fails fast locally with no relay round-trip. With `now` = acceptor clock
(Unix seconds), in this order:

1. **Structure and version:** parse per §Offer payload — `offer_version ==
   0x03` (else unsupported version), exact length with no trailing bytes
   (else malformed); the embedded bundle parses (Part I rules); then the
   signature verifies (else signature-invalid).
2. **TTL bounds:** `1 ≤ ttl_s ≤ MAX_OFFER_TTL_S` (86 400) — else malformed
   (out of range), even under a valid signature.
3. **Future skew:** `issued_at ≤ now + FUTURE_SKEW_S` (300) — else
   **offer-expired / NotYetValid**.
4. **Expiry:** expired iff `now ≥ issued_at + ttl_s` ⇒ **offer-expired /
   Expired**. Valid strictly before that instant. Arithmetic saturates (no
   overflow wrap).

The time seam: production passes the system clock; the reference parser takes
`now` as an explicit parameter so tests inject fixed instants.

Reference: `tezca-core/src/pairing.rs` (`parse_pairing_offer_v3` — the four
steps in this order); `tezca-core/src/relay_client/mod.rs`
(`begin_pairing_from_offer` — `parse_pairing_offer_v3(payload, unix_now())`
is the first statement, before any I/O; `unix_now`). Tests:
`r2_expired_offer_is_offer_expired_with_zero_network_io` (dead relay proves
zero I/O), `r3_boundary_now_equals_issued_plus_ttl_is_expired`,
`r5_ttl_zero_and_over_max_are_malformed`,
`r6_future_dated_beyond_grace_is_not_yet_valid` (exactly at the grace bound
still admits), `r7_v2_fixture_bytes_are_unsupported_version`.

## Error classes — freeze §5

Core error classes on the acceptor path, and how they cross the FFI and reach
the user (the 5a-2 four-way vocabulary, P5-D2):

| condition | core error | FFI (`TitlanError`) | user class |
|---|---|---|---|
| `offer_version ≠ 0x03` | `UnsupportedVersion { got }` | `Malformed` | MALFORMED |
| truncation, trailing bytes, bundle rules, `ttl_s` out of range | `Malformed(..)` | `Malformed` | MALFORMED |
| `offer_sig` fails | `OfferSignatureInvalid` | `OfferSignatureInvalid` | CRYPTO |
| outside window | `OfferExpired { issued_at, ttl_s, now, detail: Expired \| NotYetValid }` | `OfferExpired { … }` | EXPIRED |
| proof-of-scan fails (offerer side) | `ProofOfScanFailed` | `ProofOfScanFailed` | CRYPTO |
| libsignal key decode / PQXDH failure | `Signal(..)` | `Protocol` | CRYPTO |
| pairing inbox `404` (consumed/expired) | `PairingUnavailable` | `PairingUnavailable` | EXPIRED |
| relay unreachable | `Network(..)` | `Network` | NETWORK_UNREACHABLE |

`OfferExpired` carries timestamps only (no INV-1 exposure). Both `detail`s
share one user message — "offer expired or not yet valid — check both
devices' clocks, then re-mint" — while the core detail stays distinct for
diagnostics. A signature failure MUST never surface as expiry, and an
unsupported version MUST never surface as a crypto failure.

Reference: `tezca-core/src/error.rs` (`OfferExpiryDetail`, `CoreError`);
`tezca-core/src/ffi.rs` (`TitlanError`, `From<CoreError>` — `UnsupportedVersion`
⇒ `Malformed`); `titlan-android/app/src/main/kotlin/app/titlan/pairing/PairingFailure.kt`
(`classify`, `userMessage`). Tests: `ffi.rs` error-mapping tests;
`PairingFailureTest.kt` `classificationIsFourWayCorrect`,
`expiredStringIsTheFrozenCopyVerbatim`, `signatureFailureNeverSurfacesAsExpired`,
`unsupportedVersionNeverSurfacesAsCrypto`.

## Single-sourced constants — freeze §6

| constant | value | consumers |
|---|---|---|
| `OFFER_DEFAULT_TTL_S` | 3600 | mint path (`ttl_s` written into the offer); pairing-listener fuse; UI countdown (reads the embedded value); deposit-harness fuse |
| `MAX_OFFER_TTL_S` | 86 400 | acceptor step 2 |
| `FUTURE_SKEW_S` | 300 | acceptor step 3 |

There is exactly one governing lifetime value per offer: the embedded
`issued_at + ttl_s`. The UI countdown and the deposit harness **read it from
the minted bytes** (`peek_offer_validity`); no display-only duplicate exists.

Reference: `tezca-core/src/config.rs` (the three constants);
`tezca-core/src/relay_client/mod.rs` (`export_offer` — `ttl_s =
OFFER_DEFAULT_TTL_S`, listener fused to `ttl_s`); `tezca-core/src/client.rs`
(`peek_offer_validity`, `OfferValidity`);
`titlan-android/.../pairing/PairingCoordinator.kt` (`createOffer` — countdown
from `peekOfferValidity`); `tezca-core/examples/deposit_harness.rs` (wait
fuse := embedded `ttl_s`). Test: `r9_harness_fuse_equals_embedded_ttl`.

## Offerer behavior

1. Create the single-use pairing mailbox (`POST /v1/mailboxes`), mint a
   32-byte `pairing_secret` (OS CSPRNG), set `issued_at` = now (offerer
   clock) and `ttl_s` = `OFFER_DEFAULT_TTL_S`, sign, and emit the offer bytes.
   Each offer advertises a **freshly minted one-time pre-key with a unique
   id**, so processing one offer's response consumes exactly that offer's
   pre-key and every other live or future offer keeps its own.
2. Listen on the pairing mailbox for a `pair-ack/2`, **fused to the embedded
   TTL**: at `issued_at + ttl_s` the listener stops and the offerer **deletes
   the pairing mailbox** (Horizon §H7.3 SHOULD — the existing oracle-free
   `DELETE`, best-effort).
3. On a verified `pair-ack/2`: create the conversation, compute and persist
   the recovery root, **delete the pairing mailbox**, send the inbox-handoff
   (`mailbox-update/2`), and stop listening (single-use).
4. On a failed proof-of-scan: **burn** — ack the frame, delete the pairing
   mailbox, stop listening (§Proof-of-scan).
5. Any other frame on the pairing mailbox is acked and ignored; the offer
   stands until TTL.

Reference: `tezca-core/src/relay_client/mod.rs` (`export_offer`,
`spawn_pairing_v2`, `pairing_listener_v2`, `handle_pair_ack_v2`);
`tezca-core/src/identity.rs` (`export_offer_bundle`,
`mint_offer_onetime_prekey`). Tests: `tezca-relay/tests/relay_client_e2e.rs`
`pair_v2_offer_proof_and_exchange`,
`offerer_can_export_again_after_being_paired_into`,
`two_live_offers_are_each_independently_pairable`,
`photographed_qr_is_consumed_after_pairing`.

## Acceptor (responder) flow

1. Decode and run the **validity rule** (above) — before any network I/O.
2. Run PQXDH against A's bundle (libsignal `process_prekey_bundle`); record
   A's identity as TOFU.
3. Create B's own per-conversation inbox; mint B's 32-byte
   `recovery_root_contribution` (OS CSPRNG).
4. Send B's **first sealed frame** — a `pair-ack/2` (`inner-frame.md`) carrying
   B's bundle, B's routing coordinates, B's contribution, and the
   proof-of-scan MAC — to A's `pairing_inbox_id` at A's `relay_url`. A `404`
   ⇒ pairing-unavailable (the offer was consumed or lapsed).
5. Await A's inbox-handoff (`mailbox-update/2`) on B's inbox (10 s deadline in
   the reference implementation); adopt A's long-lived inbox as the send
   target and compute the recovery root (`recovery.md` §1).

Reference: `tezca-core/src/relay_client/mod.rs` (`begin_pairing_from_offer`,
`await_inbox_handoff_v2`); `tezca-core/src/session.rs` (`establish_session`).

## Proof-of-scan (unchanged from v2 — freeze §3 "untouched")

The offer's key bundle is public (anyone photographing the QR obtains it — see
§QR threat model). Proof-of-scan binds session completion to possession of the
**offer bytes**, not just the bundle:

```
proof = HMAC-SHA256(pairing_secret, responder_bundle ‖ recovery_root_contribution)  # libsignal signal-crypto, INV-6
```

- B computes `proof` and places it in `pair-ack/2` (fixed 32 bytes), which
  also **folds B's inbox announcement into this first frame**, so the return
  direction (B→A) needs no separate handoff at pairing.
- A decrypts, then verifies `proof` over the received `responder_bundle ‖
  recovery_root_contribution` keyed by the `pairing_secret` A minted, in
  **constant time**. The contribution is inside the MAC input, so an off-path
  party cannot substitute a recovery-root contribution without failing
  proof-of-scan.
- Any mismatch ⇒ proof-of-scan-failed: A **invalidates (burns) the offer** and
  does not record the return.

**Why invalidate on failure (not merely discard):** a failed proof is evidence
that a party who did *not* hold the complete offer nonetheless reached the
pairing inbox and attempted a return — the offer (or its bundle) leaked. A
known-possibly-compromised offer must not stay scannable, so it is burned and
A re-mints. Its cost is an **offer-burning grief** vector (a party holding
the bundle can force A to re-mint) — an accepted nuisance class (bounded,
non-compromising, self-heals on re-mint).

Trust root: **possession of the complete offer**. A party holding the entire
offer (all bytes, including `pairing_secret`) can satisfy proof-of-scan — the
ledgered complete-offer-compromise risk (§Ledgered risks).

Reference: `tezca-core/src/pairing.rs` (`compute_proof_of_scan`,
`verify_proof_of_scan` — `subtle` constant-time compare ⇒
`ProofOfScanFailed`, `encode_pair_ack_v2`, `parse_pair_ack_v2`);
`tezca-core/src/relay_client/mod.rs` (`handle_pair_ack_v2`,
`pairing_listener_v2` — burn path). Tests: `pairing.rs`
`proof_verifies_with_matching_secret_bundle_and_contribution`,
`proof_fails_on_wrong_secret_bundle_contribution_or_mac`,
`pair_ack_v2_roundtrips_and_carries_verifiable_proof`;
`relay_client_e2e.rs` `scanner_session_cannot_decrypt_third_party_blob`.

## Mailbox rotation at pairing (leaked offer contains no durable routing id)

The offer carries a **pairing-only** mailbox (`pairing_inbox_id`). After the
session is established:

1. A hands its **long-lived, relay-generated** inbox id to B **in-band**
   (sealed `mailbox-update/2`, which also carries A's recovery-root
   contribution — `inner-frame.md`).
2. A **DELETEs the pairing mailbox** (`DELETE /v1/mailboxes/{id}`).

So a leaked offer never leaks a durable routing identifier — the pairing
mailbox is a bridge, not a home. Every pairing creates a **fresh conversation
id**; core keeps no same-peer dedup, so re-pairing the same peer creates a new
conversation.

**Non-default relay:** when the offer's `relay_url` differs from the app
default, B's pairing UI **displays** the relay to the user and requires
confirmation before session establishment. Silent adoption is rejected.

Reference: `tezca-core/src/relay_client/mod.rs` (`handle_pair_ack_v2` —
`delete_mailbox(pairing_inbox)` then `mailbox-update/2`);
`tezca-core/src/storage/mod.rs` (`create_routed_conversation` — fresh id, no
peer lookup); `titlan-android/.../pairing/PairingScreen.kt` (`onOfferBytes` —
`relay != BuildConfig.RELAY_URL` ⇒ "Confirm and pair" gate; `offerRelay` via
`peek_offer_relay`). Test: `relay_client_e2e.rs`
`photographed_qr_is_consumed_after_pairing`.

## Per-path security claims (NORMATIVE for user-facing presentation)

The same offer bytes travel two carriers with **different** exposure. An
implementation MUST present these honestly to the user:

- **QR (proximal / visual):** exposure is whoever can see the screen. The
  displayer forces max screen brightness while showing it and restores on
  dismiss. Shoulder-surfing / photographs are the threat; proof-of-scan does
  **not** defend against a party who photographs the *whole* QR (they hold the
  offer). It defends against a party who obtained only the bundle by other
  means.
- **`titlan://` link (rides arbitrary channels):** the link may traverse
  channels an adversary can read (chat apps, clipboard managers, browser
  history for a future `https://` form). The scheme is **unverified and
  interceptable by on-device malware** registering the same scheme; the
  fragment can persist in browser history. A party that reads the link in
  transit holds the complete offer and defeats proof-of-scan. Link pairing is
  therefore a **convenience path with strictly weaker guarantees than QR**,
  and the UI states so.

Both carriers share: the offer is single-use and self-expiring (below); a
leaked offer is initiate-only and non-impersonating (the private identity key
never leaves A); no existing message is exposed. v3 adds: a leaked offer is
**dead past `issued_at + ttl_s`** on every acceptor clock within skew, and
cannot be re-dated (§Authentication).

Reference: `titlan-android/.../pairing/PairingScreen.kt` (brightness override
while the QR is shown; link-paste section copy).

## Offer lifecycle

- **Single-use; validity = embedded `issued_at + ttl_s`** (default 1 h).
  Completion (a verified proof-of-scan), a **failed** proof-of-scan (offer
  burned), or expiry invalidates the offer. An expired offer is rejected by
  every acceptor (§Validity rule) and its pairing mailbox is deleted by the
  offerer at expiry (SHOULD, best-effort).
- A may mint a fresh offer at any time; live offers are independent (each has
  its own pairing mailbox, secret, and one-time pre-key).
- Offerer UI states: **outstanding** (QR + link + countdown read from the
  embedded window); **completed** (conversation appears); **expired** (plain
  state + one-tap "New offer"). Dismissing the screen does **not** cancel an
  outstanding offer, and the UI says so (a core cancel method is a ledgered
  follow-up, `docs/acceptance-venues.md`).
- Acceptor degradation to the link flow has three triggers: camera permission
  denied, no camera hardware, or a 20 s decode timeout — the link path is
  offered proactively, not as an error.

Reference: `tezca-core/src/relay_client/mod.rs` (`spawn_pairing_v2`,
`pairing_listener_v2`); `titlan-android/.../pairing/PairingScreen.kt`
(`OfferLifecycle.Expired` ⇒ "New offer"; `OfferSection` TTL watch and dismiss
copy; `ScanSection` — the three triggers, `SCAN_TIMEOUT_MS = 20_000`). Tests:
`r9_harness_fuse_equals_embedded_ttl`; `relay_client_e2e.rs`
`two_live_offers_are_each_independently_pairable`.

## Relay TTL is a storage bound (Horizon §H7.4)

The relay has **no pairing-mailbox class and no offer awareness** (INV-8). Its
14-day default message/idle-mailbox TTL (`relay-api.md` `--ttl-secs`) is a
**storage bound, not an offer-validity bound**: an offer's validity is decided
solely by its embedded window at the acceptor. A pairing mailbox that outlives
its offer (e.g. the offerer was offline at expiry and the SHOULD-delete did
not run) still accepts deposits until the relay TTL reaps it, but any deposit
there is useless — the offerer's listener has stopped, and a scanner rejects
the offer before depositing.

Reference: `tezca-relay/src/config.rs` (`ttl: 336 h`; no pairing-specific
state); `tezca-relay/src/api.rs` (no offer-aware path);
`tezca-core/src/relay_client/mod.rs` (`spawn_pairing_v2` — listener ends at
`ttl`). Test: `tezca-relay/tests/limits.rs` `ttl_expires_messages_and_mailboxes`.

## Ledgered risks (accepted for MVP; unchanged from v2 except as noted)

- **Complete-offer compromise:** any party holding the entire offer (bundle +
  `pairing_secret`, and therefore also a valid `offer_sig`) can complete
  pairing as the responder within the validity window. Proof-of-scan raises
  the bar from "saw the bundle" to "held the offer"; the signature adds
  nothing against a holder of the whole offer. Not a man-in-the-middle
  defense. Accepted; re-pair and safety-number verification (post-MVP
  directory/key-transparency) are the escalation path.
- **Offer-burning grief:** a party holding only the bundle cannot complete
  pairing, but a bad return burns the offer and forces A to re-mint. Bounded,
  non-compromising, self-healing — accepted nuisance class.
- **Scheme squatting:** on-device malware may register `titlan://`. The link
  path is documented as weaker than QR; QR is the recommended path.
- **`https://` fragment in browser history:** carried into the App Links
  threat model; a static landing page must never read the fragment. v3 bounds
  the exposure in time: a recovered fragment is dead past its window and
  cannot be re-dated.

## Conformance vectors (NORMATIVE)

| vector | files | expected |
|---|---|---|
| **v3 offer — accept** | `proto/fixtures/pairing-offer-v3.link.txt` (the `titlan://pair#…` link, no trailing newline), `pairing-offer-v3.expected.txt` (`decoded_sha256`, `decoded_len`=2073, `relay`, `inbox`, `onetime_id`, `bundle_len`=1897, `identity_pub`, `issued_at`=1755000000, `ttl_s`=3600) | decode the fragment → bytes with the pinned sha256/length; the prefix before `offer_sig` equals the §Offer payload construction from the pinned fields (bundle with `device_id`=1, synthetic pre-key fills, the pinned identity key); `offer_sig` verifies with `identity_pub`; with `now = issued_at + 1` the validity rule **accepts** and yields the pinned fields |
| **v2 offer — reject** | `proto/fixtures/pairing-offer-v2.link.txt`, `pairing-offer-v2.expected.txt` | decode → 1997 bytes with the pinned sha256; a spec-1.0 acceptor rejects with **unsupported version 2** before any other check |

The v3 vector is not regenerable bit-for-bit from source (the signature is
randomized) but is fully deterministic to **verify**; the reference
regeneration path is the ignored test `regen_committed_v3_vector`.

Reference: `tezca-core/src/pairing.rs` `v3_conformance_tests`;
`tezca-core/src/pairing_v3_acceptance.rs`
`r7_v2_fixture_bytes_are_unsupported_version`;
`titlan-android/app/src/test/kotlin/app/titlan/pairing/QrCodecConformanceTest.kt`
`committedVectorDecodesToPinnedBytes`.

---

# Part III — Pairing control frames

These are inner-frame payload types (`envelope.md` registry), encrypted
end-to-end like any chat message — the relay never sees them in the clear.
Every control payload begins with a u8 `version` equal to the frame's
`type_version` (`envelope.md` §Control-frame payload header).

- **`pair-ack/2`** (`0x05`, `type_version` 2) — the pairing response with
  proof-of-scan: `inner-frame.md` §Control frame: `pair-ack/2`.
- **`mailbox-update/2`** (`0x06`, `type_version` 2) — pairing inbox-handoff
  carrying A's recovery-root contribution; **`mailbox-update/3`**
  (`type_version` 3) — recovery-time rotation: `inner-frame.md`
  §Control frame: `inbox-handoff`; protocol in `recovery.md`.
- **`mailbox-update/1`** (`0x06`, `type_version` 1) — below.

### `mailbox-update/1` — one-sided recovery for conversations without a recovery root

When a party's own inbox is gone (e.g. 14-day TTL expiry of an idle direction)
but the peer's inbox still works, and the conversation holds **no recovery
root** (`recovery.md` §6), the party creates a fresh **random** relay-generated
inbox and announces it over the existing session:

| field | encoding |
|---|---|
| version | u8 = `0x01` |
| relay_url | u16 len + UTF-8 |
| inbox_id | 43 bytes (the new relay-generated inbox) |

Trailing bytes after `inbox_id` ⇒ reject (malformed). The receiver adopts the
announced coordinates as its send target and flushes pending sends. This
introduces **no** derived identifier and **no** new relay endpoint. If the
announcing deposit itself returns `404` (both inboxes gone), the conversation
is **re-pair-only** (`RePairRequired`); conversations with a recovery root use
`recovery.md` instead.

Reference: `tezca-core/src/pairing.rs` (`CONTROL_VERSION`,
`encode_mailbox_update`, `parse_mailbox_update`);
`tezca-core/src/relay_client/mod.rs` (`recover_v1`; `handle_incoming` —
adopt + `flush_pending`). Test: `pairing.rs`
`mailbox_update_v1_with_trailing_bytes_is_malformed`.

---

# Part IV — QR threat model (what a photographed offer leaks and cannot do)

A pairing QR (or link) is **public**. Anyone who photographs it obtains
exactly the offer bytes. This section states precisely what that does and
does not enable, so the property is documented, not assumed.

**A photographed offer reveals** (all public or bearer values):
- the pre-key **bundle** — the displayer's identity *public* key and signed /
  kyber / one-time *public* prekeys;
- the displayer's **relay URL** for this pairing;
- the **single-use pairing inbox id**;
- the **`pairing_secret`** (bearer) and the validity window.

**It lets the photographer:**
- **Complete a pairing** with the displayer as the responder, within the
  validity window — inherent to no-directory QR pairing (the complete-offer
  risk above). The displayer sees a new, unknown conversation and may ignore
  or delete it. No existing message is exposed.
- **Deposit to the pairing inbox** until it is retired or its TTL lapses —
  bounded by relay rate limits, mailbox capacity, and TTL.

**It cannot:**
- **Impersonate the displayer.** The offer contains only public keys; the
  private identity key never leaves the device. The photographer cannot sign
  as, decrypt for, or pair *as* the displayer with anyone.
- **Read any message.** Each responder derives its own fresh PQXDH session;
  it cannot decrypt the legitimate peer's traffic or anyone else's.
- **Recover the private key or the local database.** Nothing secret beyond
  the bearer `pairing_secret` is in the offer.
- **Compute recovery mailboxes.** The recovery root is built from two
  contributions that are never in the offer (`recovery.md` §1).
- **Work past its window, or be re-dated.** The offer is dead at
  `issued_at + ttl_s` on every acceptor, and `offer_sig` pins the window.
- **Work after the legitimate pairing.** The pairing mailbox is deleted on
  completion; later deposits 404 ("stale-QR-dead"); the one-time pre-key is
  consumed.

**Accepted nuisance (work order §10.7 / flag 6a):** if an attacker
photographs an offer and pairs *before* the intended recipient, the attacker
consumes the single-use pairing mailbox first; the intended recipient's later
scan then 404s (`PairingUnavailable`) and they simply regenerate an offer.
This is a griefing nuisance, **not** a compromise — no impersonation, no
message exposure, and the displayer sees the attacker's pairing as an unknown
conversation it can reject.

Net: a leaked offer is an **initiate-only, non-impersonating, time-bounded,
self-expiring** capability.

Reference: `tezca-relay/tests/relay_client_e2e.rs`
`photographed_qr_is_consumed_after_pairing`,
`scanner_session_cannot_decrypt_third_party_blob`; `tezca-core/src/error.rs`
(`PairingUnavailable`).

---

# Appendix A — RETIRED: Pairing Offer v2 (Phase 4b-2)

> **RETIRED (freeze §7, V3-D4; Horizon §H7.5).** v2 carried no timestamp
> fields, so offer validity could not be enforced at the acceptor. It is
> superseded by Part II; a spec-1.0 acceptor rejects `offer_version 0x02` as
> unsupported version with **no compatibility window** (the deployed
> population was the maintainer's own devices, which re-minted after
> upgrade). The v2 codec has been deleted from the reference implementation;
> the committed v2 fixture remains as the **rejection** conformance vector.
> The layout is kept here for the record only.

| field | encoding (historical) |
|---|---|
| offer_version | u8 = `0x02` |
| bundle | u16 len + pairing bundle (Part I) |
| relay_url | u16 len + UTF-8 |
| pairing_inbox_id | 43 bytes |
| pairing_secret | 32 bytes |

Everything v2 introduced besides the layout — proof-of-scan, `pair-ack/2`, the
inbox-handoff, per-path claims, mailbox rotation, and the ledgered risks —
carries forward **unchanged** into v3 (Part II) and is specified there.

Reference: `tezca-core/src/pairing.rs` (`parse_offer_v3_structure` — version
`≠ 3` ⇒ `UnsupportedVersion { got }`; comment at the former v2 codec site);
test `r7_v2_fixture_bytes_are_unsupported_version`.

# Appendix B — RETIRED: v1 pairing payload and `pair-ack/1` (Phase 4a)

> **RETIRED.** The Phase-4a QR payload (`payload_version 0x01`) and its
> `pair-ack/1` response predate the asymmetric offer. A spec-1.0 acceptor
> rejects `0x01` as unsupported version; no `pair-ack/1` encoder or parser
> exists in the reference implementation, and a `pair-ack` frame with
> `type_version ≠ 2` arriving on a pairing inbox is acked and ignored. The
> layouts are kept for the record only. (`mailbox-update/1`, which also dates
> from Phase 4a, is **not** retired — Part III.)

v1 pairing payload (historical):

| field | encoding |
|---|---|
| payload_version | u8 = `0x01` |
| bundle | the pairing bundle (Part I) |
| relay_url | u16 len + UTF-8 |
| pairing_inbox_id | 43 bytes ASCII |

`pair-ack/1` (historical; `0x05`, `type_version` 1):

| field | encoding |
|---|---|
| version | u8 = `0x01` |
| relay_url | u16 len + UTF-8 |
| inbox_id | 43 bytes ASCII |
| address_name | u16 len + UTF-8 |

Conversations paired under v1 carry **no `pairing_secret` and no recovery
root**; on total loss they are re-pair-only, permanently (`recovery.md` §6).

Reference: `tezca-core/src/pairing.rs` (`parse_offer_v3_structure`);
`tezca-core/src/relay_client/mod.rs` (`handle_pair_ack_v2` — non-`/2`
`pair-ack` ⇒ ignored; `pairing_listener_v2` — acked).
