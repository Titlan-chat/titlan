<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan Pairing Bundle — Specification v1

**Status: NORMATIVE for bundle framing (Phase 2).** The QR/link transport of
these bytes is Phase 4. All integers big-endian; `len`-prefixed fields carry
a u16 byte length.

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
