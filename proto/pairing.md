<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan Pairing Bundle — Specification v1

**Status: NORMATIVE.** Bundle framing is Phase 2; the QR/link payload and the
pairing control messages (§Pairing payload, §Control messages, §QR threat
model) are Phase 4a. All integers big-endian; `len`-prefixed fields carry a
u16 byte length unless stated otherwise.

The pairing bundle is the serialized libsignal pre-key bundle exchanged
out-of-band at pairing (A7). All key material inside is produced and
serialized by libsignal (INV-6); this format is pure framing.

| field | encoding |
|---|---|
| format_version | u8 = `0x01`; unknown ⇒ reject |
| address_name | u16 len + UTF-8 (local pairing pseudonym: 32 lowercase hex chars = 16 random bytes, generated once at identity initialization) |
| registration_id | u32 |
| device_id | u32 = 1 in MVP |
| identity_key | u16 len + libsignal-serialized public key |
| signed_prekey_id | u32 |
| signed_prekey_pub | u16 len + bytes |
| signed_prekey_sig | u16 len + bytes |
| kyber_prekey_id | u32 |
| kyber_prekey_pub | u16 len + bytes (ML-KEM — REQUIRED; a bundle without post-quantum material is invalid, A2) |
| kyber_prekey_sig | u16 len + bytes |
| onetime_prekey_id | u32; `0xFFFFFFFF` = absent |
| onetime_prekey_pub | u16 len + bytes; len 0 when absent |

Receiver rules: reject unknown `format_version`, any truncation, and any
trailing bytes after the last field. Identity keys received here are recorded
as TOFU (trust-on-first-use) identities; key-change handling and safety
numbers are post-MVP (directory/key-transparency deferred per A7).

Privacy note (threat model, Phase 5): the first message(s) of a session are
libsignal `PreKeySignalMessage`s, whose header carries the sender's identity
public key unencrypted inside the (relay-opaque) blob. With no directory and
per-conversation mailboxes this is an unlinkable pseudonym, but a relay could
correlate identical identity keys across conversations during session setup.
Accepted for MVP; sealed-sender-style outer wrapping is a post-MVP hardening
option.

Address derivation (Phase 4a): a party's pairing address (`address_name`) is
the hex of its serialized identity public key, derived deterministically so a
recipient can compute a sender's address from the identity key embedded in an
incoming `PreKeySignalMessage` — needed to decrypt a `pair-ack/1` that arrives
on a pairing inbox whose sender is otherwise unknown (blind relay, sealed
sender). The address is a **client-side** value only: it lives in the
SQLCipher-encrypted session store and, on the wire, appears solely inside
end-to-end-encrypted payloads (e.g. `pair-ack/1`) and in the out-of-band QR —
never as a distinct relay-visible field (deposits carry only the encrypted
envelope, and mailbox IDs are relay-generated random). It therefore adds **no
wire linkability beyond the pre-existing `PreKeySignalMessage` identity-key
exposure** described above: because the address is a function of the identity
key, anyone able to correlate by address must already hold the key (via the QR
or a parsed setup blob) and could correlate by it directly.

## Pairing payload (QR / link, Phase 4a)

The payload displayed as a QR code (or shared as a link) wraps the bundle
above with the coordinates a scanner needs to reach the displayer.

| field | encoding |
|---|---|
| payload_version | u8 = `0x01`; unknown ⇒ reject |
| bundle | the pairing bundle above (self-delimiting) |
| relay_url | u16 len + UTF-8 (the displayer's relay for this pairing) |
| pairing_inbox_id | 43 bytes ASCII (base64url mailbox id, per relay-api.md) |

`pairing_inbox_id` is a **single-use pairing inbox** the displayer creates
fresh each time it shows a QR — distinct from any conversation inbox. The
link form carries the same bytes base64url-encoded in the URL **fragment**
(`https://<titlan-domain>/p#<payload>`); the fragment is never transmitted to
the host, so the link leaks nothing server-side beyond a normal page fetch.

## Pairing flow

1. **Displayer** (shows QR): generates the bundle, creates the single-use
   pairing inbox on its relay, encodes the payload.
2. **Scanner**: decodes, runs PQXDH against the bundle, creates its own
   per-conversation inbox, and sends the first message as a **`pair-ack/1`**
   control message (below) to the pairing inbox, carrying its own reply
   coordinates.
3. **Displayer**: decrypts the `pair-ack/1`, creates the conversation, records
   the scanner's reply coordinates, and **retires the pairing inbox** (deletes
   it / stops advertising). Both sides then use their per-conversation inboxes.

## Control messages (typed inner payloads)

These are `InnerFrame` payload types (see `envelope.md`), encrypted end-to-end
like any chat message — the relay never sees them in the clear.

### `pair-ack/1` (payload_type reserved for pairing)

Sent by the scanner as the first message of a new session. Fields:

| field | encoding |
|---|---|
| version | u8 = `0x01` |
| relay_url | u16 len + UTF-8 (scanner's relay for this conversation) |
| inbox_id | 43 bytes ASCII (scanner's per-conversation inbox) |
| address_name | u16 len + UTF-8 (scanner's pairing pseudonym) |

### `mailbox-update/1` (payload_type reserved for pairing)

In-band recovery for **one-sided** mailbox loss (§10.7). When a party's own
inbox is gone (e.g. 14-day TTL expiry of an idle direction) but the peer's
inbox still works, the party creates a fresh **random** inbox and announces it
over the existing session:

| field | encoding |
|---|---|
| version | u8 = `0x01` |
| relay_url | u16 len + UTF-8 |
| inbox_id | 43 bytes ASCII (the new random inbox) |

This introduces **no** derived identifier and **no** new relay endpoint — it
is an ordinary encrypted message announcing an ordinary relay-generated
mailbox. **Total** loss (both inboxes gone at once, the common case when both
parties share one relay that restarts) has no surviving channel to carry a
`mailbox-update/1`, so it falls back to re-pairing (work order §10.7 option
ii): the client surfaces `RePairRequired` and the users re-scan. No rendezvous
mailbox and no shared derived identifier are used at MVP; option (i) may be
revisited as an opt-in later.

> **Superseded for v2 conversations (frozen design §8, 4b-2).** The text above
> is preserved as the Phase-4a history. For conversations paired via the v2
> asymmetric offer, **total** loss is handled by **derived recovery mailboxes**
> (`proto/inner-frame.md` `recovery-hello` + generation convergence; frozen
> design §8), not by immediate re-pair; re-pair remains only the exhaustion
> fallback (relative generation offset ≥ W, or probe cycles spent). **Scoping:**
> a v1-paired conversation carries **no `pairing_secret` and no recovery root**,
> so it can never derive recovery mailboxes and retains **re-pair-only**
> behavior on total loss **permanently** — v2 recovery is not retrofitted onto
> v1 conversations. Accepted for MVP, stated.

## QR threat model (what a photographed QR leaks and cannot do)

A pairing QR is **public**. Anyone who photographs it (over a shoulder, from a
posted image, etc.) obtains exactly the payload bytes. This section states
precisely what that does and does not enable, so the property is documented,
not assumed.

**A photographed QR reveals** (all public values):
- the pre-key **bundle** — the displayer's identity *public* key and signed /
  kyber / one-time *public* prekeys;
- the displayer's **relay URL** for this pairing;
- the **single-use pairing inbox id**.

**It lets the photographer:**
- **Initiate a conversation** with the displayer — inherent to no-directory QR
  pairing. The displayer sees a new, unknown conversation and may ignore it.
  No existing message is exposed.
- **Deposit to the pairing inbox** until it is retired or its TTL lapses —
  bounded by relay rate limits, mailbox capacity, and TTL.

**It cannot:**
- **Impersonate the displayer.** The QR contains only public keys; the private
  identity key never leaves the device. The photographer cannot sign as,
  decrypt for, or pair *as* the displayer with anyone.
- **Read any message.** Each scanner derives its own fresh PQXDH session; it
  cannot decrypt the legitimate peer's traffic or anyone else's.
- **Recover the private key or the local database.** Nothing secret is in the
  QR.
- **Work forever — the QR is initiate-only and self-expiring ("stale-QR-dead").**
  It dies once the legitimate pairing retires the single-use pairing inbox, or
  once that inbox's TTL lapses; deposits then return 404. The one-time prekey
  is single-use.

**Accepted nuisance (work order §10.7 / flag 6a):** if an attacker photographs
a QR and pairs *before* the intended recipient, the attacker consumes the
single-use pairing inbox first; the intended recipient's later scan then 404s
and they simply regenerate a QR. This is a griefing nuisance, **not** a
compromise — no impersonation, no message exposure, and the displayer sees the
attacker's pairing as an unknown conversation it can reject. Accepted for MVP.

Net: a leaked pairing QR is an **initiate-only, non-impersonating,
self-expiring** capability.

---

# Titlan Pairing Offer — Specification v2 (Phase 4b-2)

**Status: NORMATIVE for Phase 4b-2** (frozen design 2026-07-18, §3/§4). The
v1 pairing payload / `pair-ack/1` flow above is the Phase 4a shape; v2 is an
**asymmetric offer** that adds a proof-of-scan trust root and mailbox
rotation. A displayer speaks exactly one version per QR (the payload's first
byte selects it); a v1 scanner and a v2 offerer never silently half-pair
(`payload_version`/`OFFER_VERSION` mismatch ⇒ reject). This section is
third-party implementable on its own.

## Offer payload (QR / link, byte-identical)

The offer is an **asymmetric** capability: the offerer (A) displays it; the
responder (B) consumes it. One payload spec is carried across two encodings —
a QR code and a `titlan://pair#<base64url-payload>` link — **byte-identical**
before/after encoding. Future `https://titlan.chat/pair#<payload>` is the same
bytes again (§4; App Links migration is additive, Phase 5).

| field | encoding |
|---|---|
| offer_version | u8 = `0x02`; unknown ⇒ reject |
| bundle | the pairing bundle (§Pairing bundle above, self-delimiting) — identity key, signed pre-key, Kyber pre-key (REQUIRED, A2), one-time pre-key |
| relay_url | u16 len + UTF-8 (A's relay for this pairing) |
| pairing_inbox_id | 43 bytes ASCII (base64url mailbox id; A's single-use **pairing** mailbox) |
| pairing_secret | 32 bytes — a random 256-bit secret from A's CSPRNG, carried **OUTSIDE the key bundle** |

The `pairing_secret` is the crux of v2: it is a bearer secret that only a
party who obtained the actual offer bytes can hold. It is **not** key material
(it is not mixed into PQXDH); it keys the proof-of-scan MAC (below).

Byte-identical encodings — a conforming implementation MUST satisfy:

```
QR_modules      = qr_encode(offer_bytes)
link            = "titlan://pair#" + base64url_nopad(offer_bytes)
offer_bytes'    = base64url_decode(fragment_of(link))
assert offer_bytes' == offer_bytes            # link round-trips
assert qr_decode(QR_modules) == offer_bytes   # QR round-trips
```

The `titlan://` fragment is decoded **locally**; it never touches any server
(§4). Encoded size target ≈ 2.7 KB; the link must survive common share
channels without truncation, and a clipboard-detection path handles
dead-text delivery (§4 link tests).

## Proof-of-scan

The offer's key bundle is public (anyone photographing the QR obtains it — see
the v1 QR threat model, which still applies to the bundle). Proof-of-scan
binds session completion to possession of the **offer bytes**, not just the
bundle:

1. B decodes the offer, runs PQXDH against A's bundle, and creates its own
   per-conversation inbox.
2. B's **first sealed frame** to A's pairing inbox is a `pair-ack/2` control
   frame (`proto/inner-frame.md`) carrying B's own reply bundle, B's routing
   coordinates (relay + inbox), B's 32-byte `recovery_root_contribution`
   (B2 — never in the offer), and a **fixed 32-byte** MAC (F2):

   ```
   proof = HMAC-SHA256(pairing_secret, responder_bundle ‖ recovery_root_contribution)  # libsignal, INV-6
   ```

   `pair-ack/2` **folds B's inbox announcement into this first frame**, so the
   return direction (B→A) needs no separate `inbox-handoff` at pairing. A's own
   contribution is delivered to B in the `inbox-handoff` (`mailbox-update/2`);
   the per-conversation recovery root is `HMAC-SHA256(A_contribution,
   B_contribution)` (`proto/inner-frame.md` §Derived recovery-mailbox IDs).
3. A decrypts, then verifies `proof` over the received `responder_bundle ‖
   recovery_root_contribution` (F2) keyed by the `pairing_secret` A minted.
   **Constant-time** compare. Any mismatch ⇒ `ProofOfScanFailed`: A
   **invalidates the offer** (it moves to the failed UI state with one-tap
   re-mint) and does not record the return.

**Why invalidate on failure (not merely discard):** a failed proof is not
noise — it is evidence that a party who did *not* hold the complete offer
nonetheless reached the pairing inbox and attempted a return, i.e. the offer
(or its bundle) leaked. A known-possibly-compromised offer must not stay
scannable, so it is burned and A re-mints. This is both cleanly implementable
(a single terminal failure state) and strictly safer than leaving a suspect
offer live. Its cost is an **offer-burning grief** vector — a party holding
the bundle can force A to re-mint by sending a bad return — an accepted
**nuisance class** (bounded, non-compromising, self-heals on re-mint), of a
piece with the §10.7 / flag-6a attacker-pairs-first nuisance.

Trust root: **possession of the complete offer**. A party that holds the
entire offer (all bytes, including `pairing_secret`) can satisfy proof-of-scan
— this is an accepted MVP risk, ledgered below.

## Per-path security claims (NORMATIVE)

The same offer bytes travel two carriers with **different** exposure. An
implementation MUST present these honestly to the user (§3):

- **QR (proximal / visual):** exposure is whoever can see the screen. The
  displayer forces max screen brightness while showing it and restores on
  dismiss. Shoulder-surfing / photographs are the threat; proof-of-scan does
  **not** defend against a party who photographs the *whole* QR (they hold the
  offer). It defends against a party who obtained only the bundle by other
  means.
- **`titlan://` link (rides arbitrary channels):** the link may traverse
  channels an adversary can read (chat apps, clipboard managers, browser
  history for the `https://` form). The scheme is **unverified and
  interceptable by on-device malware** registering the same scheme; the
  fragment can persist in browser history. A party that reads the link in
  transit holds the complete offer and defeats proof-of-scan. Link pairing is
  therefore a **convenience path with strictly weaker guarantees than QR**,
  and the UI states so.

Both carriers share: the offer is single-use and self-expiring (below); a
leaked offer is initiate-only and non-impersonating (the private identity key
never leaves A); no existing message is exposed.

## Offer lifecycle

- **Single-use, TTL 1 hour** (config; approved). Completion (a verified
  proof-of-scan), a **failed** proof-of-scan (offer burned, §Proof-of-scan),
  OR expiry invalidates the offer.
- On invalidation A **releases/replaces the consumed one-time pre-key** so a
  fresh offer can be minted cleanly; A may mint a fresh offer at any time.
- UI states: **outstanding** (QR + countdown + cancel); **completed**
  (conversation appears); **expired/failed** (plain state + one-tap re-mint).
- Degradation to the link flow has three triggers (§5): camera permission
  denied, no camera hardware, or a 20 s decode timeout — the link path is
  offered proactively, not as an error.

## Mailbox rotation (leaked-offer contains no durable routing id)

The offer carries a **pairing-only** mailbox (`pairing_inbox_id`). After the
session is established:

1. A hands off its **long-lived, relay-generated** inbox ID to B **in-band**
   (sealed `inbox-handoff` control frame, `proto/inner-frame.md`).
2. A **DELETEs the pairing mailbox** (relay `DELETE /v1/mailboxes/{id}`).

So a leaked offer never leaks a durable routing identifier — the pairing
mailbox is a bridge, not a home. Fresh `conversationId` per pairing (F9);
core keeps no same-peer dedup, so re-pairing the same peer creates a new
conversation.

**Non-default relay:** when `relay_url` differs from the app default, B's
pairing UI **DISPLAYS** the relay to the user before session establishment.
Silent adoption is rejected.

## v2 ledgered risks (accepted for MVP)

- **Complete-offer compromise:** any party holding the entire offer (bundle +
  `pairing_secret`) can complete pairing as the responder. Proof-of-scan
  raises the bar from "saw the bundle" to "held the offer"; it is not a
  man-in-the-middle defense. Accepted; re-pair and safety-number verification
  (post-MVP directory/key-transparency) are the escalation path.
- **Offer-burning grief:** a party holding only the bundle (not the
  `pairing_secret`) cannot complete pairing, but a bad return burns the offer
  and forces A to re-mint (§Proof-of-scan: invalidate-on-failure). Bounded,
  non-compromising, self-healing — accepted nuisance class.
- **Scheme squatting:** on-device malware may register `titlan://`. The link
  path is documented as weaker than QR; QR is the recommended path.
- **`https://` fragment in browser history:** carried into the Phase 5 App
  Links threat model (§4); the static landing page never reads the fragment.
