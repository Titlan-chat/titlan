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
