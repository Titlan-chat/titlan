<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Tezca Relay API — Specification v1

**Status: NORMATIVE (Phase 3).** The relay is blind by design (INV-2): it
stores opaque padded blobs in RAM with TTL expiry and learns only recipient
mailbox ID and timing. It never parses, stores, or logs sender identity,
plaintext, contact graphs, or PII. Nothing in the relay logs at all.

Transport: HTTP/1.1 over TLS (the relay terminates its own TLS). A
`--plain-http` mode exists for reverse-proxied deployments and tests.

## Endpoints

### `POST /v1/mailboxes`
Create a mailbox. Empty request body.
- `201 Created`, `application/json`: `{"mailbox_id":"<43-char base64url>"}`
- `429 Too Many Requests` (+ `Retry-After`): per-source create limit
- `503 Service Unavailable`: global mailbox capacity reached

The mailbox ID is 32 bytes from the relay's OS CSPRNG (256-bit), base64url
unpadded. Server-side generation prevents clients choosing fingerprintable
IDs; 256 bits makes enumeration and correlation infeasible.

### `POST /v1/mailboxes/{id}/messages`
Deposit one blob (one outer envelope). Body: `application/octet-stream`.
- `202 Accepted` (empty body)
- `400 Bad Request`: blob fails the magic+version+length admission check
- `404 Not Found` (empty body): unknown / expired / deleted / malformed ID —
  **all indistinguishable**
- `413 Payload Too Large`: blob exceeds `--max-blob-bytes`
- `429 Too Many Requests` (+ `Retry-After`): per-source or per-mailbox rate
- `507 Insufficient Storage`: mailbox message/byte capacity reached

The relay validates ONLY the first five bytes of the blob (magic `TZCA` +
version `0x01`, per `envelope.md`) plus a minimum length. It does not read
the `kind` byte or anything after it; the ciphertext is opaque.

### `GET /v1/mailboxes/{id}/ws`
WebSocket subscribe for delivery.
- On upgrade: queued messages replay in deposit order, then live delivery.
- `404`: unknown/expired/deleted/malformed ID
- `429` (+ `Retry-After`): per-mailbox WS-connect rate

A second subscriber to the same mailbox replaces the first (the older
connection closes) — device-restart semantics.

Frames (binary):
- server → client delivery: `0x01 || message_id(16) || envelope`
- client → server ack: `0x02 || message_id(16)` → the relay deletes that
  message. Unacked messages are redelivered on reconnect (at-least-once; the
  client ratchet rejects true duplicates).

### `DELETE /v1/mailboxes/{id}`
Delete a mailbox and its queued blobs.
- `204 No Content`, **unconditionally** — the response is byte-identical
  whether or not the mailbox existed (no existence oracle).

Capability note: the mailbox ID is a bearer capability, and the only party
that deposits to a given mailbox is the conversation peer who was given that
ID. Deleting a mailbox therefore destroys only the deleting party's own
undelivered messages and closes their own channel — it exposes nothing about
a third party (IDs are unguessable). Useful for clean conversation deletion.

### `PUT /v1/mailboxes/{id}`
Idempotent create-at-client-specified-id (Phase 4b-2, frozen §8) — for §10.7
derived-recovery mailboxes, whose ids both conversation peers compute
independently (`proto/inner-frame.md` §Derived recovery-mailbox IDs). Empty
request body. `{id}` is a caller-chosen **256-bit** value (43-char base64url).
- `201 Created` (empty body): the mailbox exists after the call —
  **byte-identical whether it was created or already existed** (no existence
  oracle; the client already holds the id, so nothing is returned).
- `400 Bad Request`: `{id}` is not a 43-char base64url value (shape-only; no
  server state consulted, so it leaks no existence information).
- `429 Too Many Requests` (+ `Retry-After`): per-source create-at-id rate.
- `503 Service Unavailable`: global mailbox capacity reached — returned
  **uniformly regardless of whether `{id}` already exists** (no oracle at cap;
  recovery-blocked-at-cap is accepted, frozen §8).

There is **no per-mailbox rate limit** on PUT (the id is caller-chosen and may
not exist yet). PUT counts against the global mailbox cap identically to POST.
Idempotent create-at-id is safe here because ids are unguessable 256-bit values
derived from a per-conversation secret both peers share; a third party cannot
guess an id to squat it (and even a squatted id yields the uniform 201/503
response, no oracle).

### `GET /healthz`
Liveness. `200 OK`, body `ok`. No state, no auth.

## Invariants realized here

- **INV-2 (blind):** no endpoint reads beyond the envelope magic+version;
  error bodies are empty and identical across unknown/expired/deleted;
  DELETE reveals nothing; the two rate limiters are structurally disjoint
  (per-source keyed by a per-boot keyed hash of the address, per-mailbox
  keyed by ID) so no mailbox↔source pairing exists as data; nothing logs.
- **INV-3 (no persistence):** RAM only; restart loses all mailboxes; clients
  recover via reconnect + resend. Process hardening: `RLIMIT_CORE=0`,
  not ptrace-dumpable, best-effort `mlockall`; deploy adds `MemorySwapMax=0`.
- **INV-5 (configurable relay):** the relay contains no self-URL and no
  client registry; addressing lives entirely in client conversation config.

## Configuration (flags; defaults = work order §10.2, 2026-07-14)

| flag | default | meaning |
|------|---------|---------|
| `--listen` | `127.0.0.1:8443` | bind address |
| `--tls-cert` / `--tls-key` | — | PEM paths (required unless `--plain-http`) |
| `--plain-http` | off | serve without TLS (reverse-proxy / tests) |
| `--ttl-secs` | 1209600 (14 d) | message and idle-mailbox TTL |
| `--sweep-secs` | 3600 | sweep interval |
| `--max-blob-bytes` | 16384 | max deposit size |
| `--mailbox-max-messages` | 1000 | per-mailbox message cap |
| `--mailbox-max-bytes` | 4194304 | per-mailbox byte cap |
| `--max-mailboxes` | 100000 | global mailbox cap |
| `--rate-create-per-min` | 10 | per-source mailbox creates |
| `--rate-put-per-min-source` | 30 | per-source PUT create-at-id (§8) |
| `--rate-deposit-per-min-source` | 60 | per-source deposits |
| `--rate-deposit-per-min-mailbox` | 120 | per-mailbox deposits |
| `--rate-ws-per-min-mailbox` | 6 | per-mailbox WS connects |

## Open items (post-MVP)

- Mailbox re-exchange after relay restart when both directions die at once
  (work order §10.7, a Phase 4 client design item).
- TLS certificate hot-reload (MVP rotates via process restart).
