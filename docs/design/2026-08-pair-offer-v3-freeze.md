<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Pair-Offer v3 — Design Freeze

**Gate:** Phase 5 unit 5a-1 mini-gate (plan-of-record ratified 2026-08-05);
implements Horizon freeze §H7.
**Predecessor (hash-chained):** `docs/design/2026-07-horizon-freeze.md`,
sha256 `c1a08ef33a09f7f1e13a8a05dafd0239633506b8d2e86405c1b3036e7214b4c0`.
**Status:** FROZEN — ratified 2026-08-10 (record at foot). Changes require
maintainer re-ratification.
**Inputs of record:** `proto/pairing.md` @ ff92722 (sha256
`6e8917c0…ad58f97` — the v2 offer layout, fetched and verified at review
time); `proto/envelope.md` @ ff92722 (`3bac436c…d3960a`); work-order §10
item 12 (offer-lifetime reconciliation, CLOSED into H7); the ledgered risk
register (complete-offer compromise; offer-burning grief; scheme squatting;
fragment-in-browser-history).

## 1. Scope: what H7 directs and what this freeze specifies

H7 fixed the semantics: offer validity = embedded `issued_at` + `ttl`
(default 1 h), acceptor-enforced with a distinct expired-offer error; the
offerer SHOULD delete the pairing mailbox at expiry; harness fuse and UI
countdown align to the embedded TTL; v2 retired before spec publication; no
relay awareness (the 14 d relay TTL stays a storage bound). H7 did NOT fix
the byte layout or the authentication mechanism. This freeze specifies both.

## 2. v3 wire layout (FROZEN — V3-D1)

| field | encoding |
|---|---|
| offer_version | u8 = `0x03`; unknown ⇒ reject |
| bundle | pairing bundle, unchanged (format_version stays `0x01`) |
| relay_url | u16 len + UTF-8 (unchanged) |
| pairing_inbox_id | 43 bytes ASCII (unchanged) |
| pairing_secret | 32 bytes (unchanged) |
| issued_at | u64, Unix seconds, big-endian, offerer clock |
| ttl_s | u32, seconds, big-endian; default `OFFER_DEFAULT_TTL_S` = 3600 |
| offer_sig | 64 bytes — XEd25519 signature by the offer's identity key over ALL preceding wire bytes (`offer_version` … `ttl_s`) |

Sign-the-wire-bytes, verify-the-wire-bytes: the signed region is the exact
serialized prefix — no canonicalization layer exists to get wrong. Trailing
bytes after `offer_sig` ⇒ reject (symmetry per work-order item 18d). QR and
`titlan://pair#` link remain byte-identical carriers of the same bytes. Size
delta +76 raw bytes (~+101 base64url chars) on a ~2 KB raw payload —
negligible against QR density and the 20 s decode budget; the on-device
pairing e2e re-exercises decode regardless.

## 3. Authentication (FROZEN — V3-D3, subject to V3-V1)

Mechanism: mint-time `calculate_signature` by A's identity private key;
scan-time `verify_signature` with the identity public key inside the same
offer's bundle. **Defends:** any post-mint tamper of any offer field without
identity substitution — specifically the timestamp-resurrection attack (an
expired offer recovered from browser history or a chat log, re-dated to look
fresh) and, additionally, `relay_url`/`pairing_inbox_id` redirection grief.
**Does not defend:** wholesale substitution — an attacker replacing the
entire offer with their own identity and their own valid signature. That is
the ledgered complete-offer-compromise risk, unchanged from v2; this freeze
claims nothing against it. A MAC keyed by `pairing_secret` was considered
and rejected: the key rides the same bytes, so any tamperer re-MACs.
Proof-of-scan semantics are untouched.

**INV-6:** both primitives are libsignal's own (`PrivateKey::
calculate_signature` / `PublicKey::verify_signature`) — the same operations
already exercised for signed/kyber pre-key signatures at bundle mint. See §9
(V3-V1) for the open verification obligation.

## 4. Validity rule (NORMATIVE — V3-D2)

Evaluated at decode in tezca-core, BEFORE any network I/O — an expired offer
fails fast locally with no relay round-trip (A3: Kotlin surfaces the typed
error only). With `now` = acceptor clock:

1. structure valid, `offer_version == 0x03`, signature verifies — else the
   respective malformed / unsupported-version / signature error;
2. `1 ≤ ttl_s ≤ MAX_OFFER_TTL_S` (86 400) — else malformed (out-of-range);
3. `issued_at ≤ now + FUTURE_SKEW_S` (300) — else NotYetValid;
4. expired iff `now ≥ issued_at + ttl_s` ⇒ `OfferExpired` — the H7 distinct
   error. Valid strictly before that instant.

## 5. Error surface — the 5a-1/5a-2 seam

5a-1 lands core variants + FFI surface: `OfferExpired { issued_at, ttl_s,
now, detail: Expired | NotYetValid }` (timestamps only — no INV-1 exposure),
`OfferSignatureInvalid` (crypto class, distinct from `ProofOfScanFailed`),
plus the existing malformed and unsupported-version paths. 5a-2 then builds
the four-way user vocabulary (network-unreachable / expired / malformed /
crypto-MAC) replacing the unified dialog — per ratified P5-D2. User copy for
both `OfferExpired` details (one surface, V3-D2): "offer expired or not yet
valid — check both devices' clocks, then re-mint"; the core detail enum
stays distinct for diagnostics.

## 6. Offerer-side and tooling alignment (H7 SHOULDs)

`OFFER_DEFAULT_TTL_S = 3600` single-sourced in tezca-core config; the mint
path writes it into the offer; the UI countdown READS the embedded `ttl_s`
(the display-only `OFFER_TTL_MS` duplicate is removed — the item-12
four-lifetime split collapses to one governing value). The offerer schedules
the pairing-mailbox DELETE at `issued_at + ttl_s` while the offer is
outstanding (existing oracle-free DELETE; best-effort per SHOULD). The
deposit-harness fuse := the offer's embedded `ttl_s`, replacing
`DEFAULT_WAIT_SECS = 600`.

## 7. Retirement and scope containment (V3-D4)

Acceptor accepts `0x03` only; `0x01`/`0x02` ⇒ unsupported-version reject. No
compatibility window: the deployed population is the maintainer's own
devices, which re-mint after upgrade (per H7.5's rationale). Untouched:
bundle format, pair-ack/2, inbox-handoff / mailbox-update family, recovery
design, relay (zero offer awareness — INV-8). Spec text: 5a-1 is code +
fixtures only; pairing.md gains its normative v3 section and the v2
retired-marking in 5a-3, the single spec touch.

## 8. Acceptance signatures for the 5a-1 red phase

R1 fresh mint round-trips and accepts; R2 expired offer ⇒ `OfferExpired`
with zero network I/O attempted; R3 boundary `now == issued_at + ttl_s` ⇒
expired; R4 bit-flipped `issued_at` ⇒ `OfferSignatureInvalid`, NOT expired;
R5 `ttl_s = 0` and `> MAX` ⇒ malformed; R6 future-dated beyond grace ⇒
`OfferExpired { detail: NotYetValid }`; R7 v2 fixture bytes ⇒
unsupported-version (fixture corpus exists per 4b2-codec-fixture-tests); R8
trailing bytes after `offer_sig` ⇒ reject; R9 harness fuse == embedded
`ttl_s`; R10 QR/link byte-identity round-trip holds for v3 bytes.

## 9. Open verification obligation

**V3-V1:** confirm `PrivateKey::calculate_signature` and
`PublicKey::verify_signature` are public API at the pinned libsignal
v0.99.1, citing the existing pre-key-signing call site in tezca-core.
Discharged at the 5a-1 order's T0, before any red commit. Failure = HALT +
FLAG per the design-assumption rule (CLAUDE.md); no substitute mechanism
exists by construction, and none may be silently adopted.

## 10. Ratification record

Ratified 2026-08-10 by the maintainer — words "lets go with your
recommendations", adopting the reviewer recommendation set
(Horizon-precedent form):

- **V3-D1** — layout §2 as specified (field order, u64-seconds/u32-seconds
  big-endian, fixed 64 B signature, signed region = entire preceding prefix,
  trailing-byte reject): RATIFIED.
- **V3-D2** — bounds and surfaces §4–§5 (default 3600 s / cap 86 400 s /
  future-skew grace 300 s; NotYetValid folded into the expired user surface
  with the clock hint, core detail distinct): RATIFIED.
- **V3-D3** — authentication §3 via libsignal signature primitives:
  RATIFIED, subject to V3-V1 (§9).
- **V3-D4** — no compatibility window; acceptor v3-only, `0x01`/`0x02`
  rejected outright: RATIFIED.

Commit placement: this file lands as the first commit of the 5a-1 branch;
its sha256 enters the work-order ledger at the 5a-1 unit close.
