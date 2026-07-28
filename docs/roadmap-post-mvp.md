<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

> **STATUS (2026-07-28): DISCUSSION-STATE ONLY.** This document is
> dependency-ordered planning material. NOTHING herein is authorized for
> implementation; every phase listed requires its own design freeze -> red ->
> green cycle before any code. Locked decisions and invariants in
> titlan-mvp-work-order.md are not open for revision by this document.

CONTEXT BRIEF — Titlan post-MVP feature expansion planning
(This brief describes planning state as of 2026-07-28. It authorizes
discussion/design work only — no implementation is gated open.)

## Project

Titlan: open-source, privacy-first E2EE messenger (publisher: Oculux
Technologies LLC). Architecture: shared Rust core (tezca-core) with
UniFFI bindings; Kotlin/Compose Android app (titlan-android); stateless
RAM-only relay (tezca-relay). Crypto exclusively via libsignal
(X3DH/PQXDH + Double Ratchet) — custom crypto banned. SQLCipher at
rest, hardware-Keystore-wrapped key. No accounts, no phone numbers, no
directory server, sealed sender, per-conversation configurable relay
addresses, no FCM/GMS (GrapheneOS-first, foreground-service WebSocket
sync). Typed+versioned message envelope (chat/1 implemented;
posture/1, policy/1, alert/1 reserved) with padded ciphertext buckets.
Non-negotiable invariants include: no plaintext at rest or in logs;
blind relay (no sender identity, no PII, no logging of mailbox IDs
with IPs); no server-side persistence (relay restart loses all
mailboxes); versioned envelope; no custom crypto.

Business target: B2B/OT teams and CMMC-obligated defense
subcontractors. Development is governed by strict gates: design
freeze → red (failing-tests) commit → green implementation, separate
reviewer and implementing AI instances, maintainer holds all pushes.

## Current build state

MVP Phase 4b-2 is MERGED: PR #20 → main merge commit 5812aa3
(2026-07-28), CI run #68 fully green (relay_client_e2e 14/14, core
19/19, instrumented 23/23), both device checklists passed with
evidence filed on the PR — (e) locked-boot 2026-07-22; (f) doze
latency measured 1271/932/1660 ms under forced deep Doze,
no-exemption posture. First successful device pairing achieved
2026-07-28. Next on the MVP track: the Protocol Horizon design gate,
then Phase 5 (pre-publish hardening).

## Feature expansion under discussion (NOT yet designed or authorized)

Motivated by competitive analysis against Glacier Security
(glacier.chat) — a closed-source commercial secure-comms suite whose
feature table (voice/video, groups, file sharing, audio messages,
ephemeral timers, read receipts, location sharing, multi-device, iOS,
push, VPN) is effectively the procurement checklist for our target
segment. Our differentiators vs. Glacier: verifiability (AGPL/Apache,
reproducible builds, SBOMs, SLSA provenance), explicit PQXDH crypto
provenance, and a genuinely blind relay with no server-side org state.

Agreed feasibility triage:
- Tier 1 (cheap, additive payload types on existing envelope):
  ephemeral timers, read receipts, location sharing (MapLibre/OSM,
  no Google Maps).
- Tier 2 (new subsystems, each needs own design gate): attachments +
  audio messages (requires a NEW separate blob service "tezca-blob"
  with disk persistence and its own invariant ledger — current relay
  caps at 16 KiB blobs, RAM-only); groups (sender keys + pairwise
  fanout; MLS rejected — dumb-mailbox relay cannot provide epoch
  ordering; hard problem is membership consistency without a
  directory); multi-device (per-device sessions, in-band device-list
  management since no directory server; schema migration expected).
- Tier 3 (separate products/infrastructure): voice/video (TURN/media
  relay opex, WebRTC dependency); VPN (its own future suite module);
  push (contentless wake-ups acceptable; forces GMS+FOSS build
  variants). iOS is coupled to push: no background sockets on iOS,
  so iOS cannot ship before push exists. UniFFI makes the core
  portable; only UI + Secure Enclave keywrap are new.

Agreed sequencing (post-MVP phases, dependency-ordered):
P6 cheap payload types → P7 multi-device (do earliest; schema/protocol
earthquake) → P8 push → P9 iOS → P10 groups (after multi-device, so
group membership is solved once for the general case) → P11
attachments on tezca-blob. Voice/video and VPN: off-track,
partner-or-later.

Key architectural decision pending: a "Protocol Horizon" design gate
inserted before Phase 5 (pre-publish hardening), because Phase 5
publishes the protocol spec and the repo goes public — that is the
real wire-format freeze. Horizon decision items: (a) reserve payload
types receipt/1, control/1, attachment-pointer/1; (b) redefine
identity as a device-SET (MVP ships set-size 1) as the multi-device
down-payment; (c) ratify the group model on paper; (d) spec
tezca-blob + its invariants; (e) resolve the org control plane
tension — enterprise buyers need provision/deprovision/fleet
visibility, which conflicts with our no-directory invariant; working
shape is org-scoped relay + admin-issued pairing offers +
client-side attestation, keeping the relay itself blind.

Open verification item (due at the Protocol Horizon gate): confirm
the wire formats (pair-ack/2, inbox-handoff) and the SQLCipher schema
leave versioned headroom for a future device index (migration, not
rebuild) — single-device assumptions are threaded through the frozen
recovery-root and derived-mailbox designs. Status of record: §10 of
titlan-mvp-work-order.md.

## Ground rules

- Nothing above beyond the merged MVP is frozen or authorized for
  implementation. Treat all Tier/phase items as design-discussion
  material.
- Any output that proposes protocol or schema changes must respect
  the invariants listed and flag conflicts explicitly rather than
  relax them.
- Locked decisions (libsignal-only crypto, blind relay, no directory,
  configurable relay, typed envelope) are not open for revision.
