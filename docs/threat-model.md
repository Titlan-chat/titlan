<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan Threat Model

**Titlan threat model 1.0 — STRIDE-lite; describes the system as frozen at
wire protocol spec 1.0 (main b7fe509) and as built; maintained alongside the
spec.**

This document DESCRIBES; it does not DECIDE. It records, for the client, the
relay, and the pairing flow, which threats are mitigated — each with a venue
that a reader can run or read — and which are RESIDUAL or ACCEPTED, each with
the record that ratified the acceptance. Nothing here authorizes a change;
proposed mitigations are not part of this document (they travel in the unit
report to the maintainer). Every threat entry ends in exactly one verdict:

- **MITIGATED** — the claim carries at least one venue: (a) a named test
  (`file :: test_name`), (b) a named CI job or a named check in
  `scripts/check-invariants.sh`, (c) a NORMATIVE section of a frozen spec
  under `proto/`, or (d) a ratified design decision (a `docs/design/` freeze
  section, or a work-order invariant INV-1..8 / locked decision A1..A11).
- **RESIDUAL** — the threat is real, is not mitigated by anything venued, and
  is carried with the record that acknowledged it (or is flagged as needing
  one).
- **ACCEPTED** — a deliberate design consequence, ratified by a named record.

Every RESIDUAL/ACCEPTED entry is collected in the closing register, which is
the part of this document the maintainer re-ratifies.

## How to read this document

**Citation forms** (mechanically checked against the tree at each revision):

| form | meaning |
|---|---|
| `tezca-relay/tests/zero_knowledge.rs :: relay_never_writes_to_storage` | a named test: repo-relative file `::` test function |
| `androidTest/crypto/DbKeyManagerTest.kt :: keyUsableWhileDeviceLocked` | as above; `androidTest/` abbreviates `titlan-android/app/src/androidTest/kotlin/app/titlan/`, `androidUnit/` abbreviates `titlan-android/app/src/test/kotlin/app/titlan/` |
| CI job "Rust — cargo deny + audit (INV-6/INV-7)" | a job `name:` in `.github/workflows/ci.yml` (or `release.yml`) |
| `scripts/check-invariants.sh family 12` | a numbered assertion family in the invariants script (run by CI jobs "Repo invariants (SPDX, appId, naming)" and "Android — lint, unit tests, assemble") |
| `proto/pairing.md §Per-path security claims` | a section of a frozen spec (the text after § is the heading's leading text) |
| Horizon §H4.1 · v3 freeze §3 / V3-D3 · A5 · INV-2 | ratified decisions: `docs/design/2026-07-horizon-freeze.md`, `docs/design/2026-08-pair-offer-v3-freeze.md`, the work order's locked decisions A1–A11 and invariants INV-1..8 |
| 4b-2 freeze §2 | the predecessor design freeze (private by hash per Horizon §H8.3, sha256 `6b79fb39c90acabb4f3464c6d8037de1f4165961602c8bdcd34101dfa638b631`); cited only as the RECORD of an acceptance, never as a mitigation venue |
| ledger item N | the maintainer's work-order §10 ledger (private governance record); cited only as the record of an acceptance |

Test venues run in CI: Rust tests in CI job "Rust — fmt, clippy, build, test";
Android `androidTest/` classes in
CI job "Android — instrumented (Keystore wrap, INV-1 at-rest)"; Android
`androidUnit/` classes in CI job "Android — lint, unit tests, assemble".
Two device-bound procedures are DOCUMENTED-MANUAL
venues (`docs/checklists/4b2-e-locked-boot.md`,
`docs/checklists/4b2-f-doze-latency.md`), with their evidence of record named
where cited.

STRIDE-lite: each surface opens with a table of the six STRIDE categories.
A category that does not apply to a surface is collapsed to one line saying
why; the rest expand into numbered entries (TM-C# client, TM-R# relay, TM-P#
pairing, TM-X# cross-cutting).

## 1. Assets

| asset | where it exists | notes |
|---|---|---|
| **Message plaintext** | on-device only: in process memory during compose/decrypt/display; at rest in the SQLCipher store | never on the wire (Double Ratchet, A2) and never at the relay (INV-2) |
| **Identity and session keys** | the device-generated identity keypair (A1), signed/Kyber/one-time pre-keys, and libsignal session state, at rest in SQLCipher; the 32-byte SQLCipher key, at rest only AES-GCM-wrapped under a non-exportable Android Keystore key | the private identity key never leaves the device (`proto/pairing.md §Part IV`) |
| **Recovery root and the derived-mailbox sequence** | per-conversation 32-byte root (dual contribution) and the generation counters, at rest in SQLCipher on both peers | forever computable from persisted client state — the reason derived mailboxes are a bridge, not a home (`proto/recovery.md §4. Convergence`) |
| **Pairing offers and the pairing secret** | transient: minted on the offerer, displayed as QR / `titlan://pair#` link, consumed by one responder; the 32-byte bearer `pairing_secret` rides inside the offer | single-use, self-expiring; possession of the whole offer is the trust root of proof-of-scan |
| **Contact graph** | on-device only: the `conversations` table (peer address, relay URL, send/receive mailbox ids) | the relay holds no directory and no identity (INV-2, A7); the metadata shadow of the graph is a separate asset below |
| **Metadata** | at the relay and on the network path: mailbox ids, deposit/delivery timing, bucketed blob sizes, source IPs, WebSocket presence; the identity public key inside session-setup blobs | minimized (A6, A8), not eliminated — TM-R2 states the exposure plainly |

## 2. Trust model and boundaries

**Device trust boundary.** The trusted computing base on a phone is the Titlan
process, the Android Keystore (StrongBox where available, TEE fallback), and
the OS's credential-encrypted (CE) app-private storage. The OS and anyone with
root or physical memory access are INSIDE the boundary: compromise of that
class is out of scope for every mitigation below and is carried as the
device-compromise ACCEPTED class (TM-C10). Other apps on the device are
OUTSIDE the boundary (the Android sandbox is relied upon), with one reachable
exception — a malicious app can register the `titlan://` scheme (TM-P2).

**Blind relay by design (A5, A6).** The relay is a stateless, RAM-only
mailbox store that learns only recipient mailbox id and timing. It is
UNTRUSTED for confidentiality: nothing in the design assumes the relay keeps
a secret, and INV-2/INV-8 forbid it from acquiring the ability to. It is
RELIED UPON for availability in the honest-but-curious sense: an operator
that drops or delays traffic degrades service without learning content
(TM-R7). Blindness is unconditional for every relay, org relays included
(Horizon §H6.2).

**No accounts, no directory (A1, A7).** Identity is a device-generated
keypair; a person is introduced to a peer only by pairing (QR or link); the
peer's identity key is recorded trust-on-first-use. There is no server-side
identity to spoof and no directory to poison — and, at spec 1.0, no in-app
identity verification either (TM-P8).

**Configurable relay (INV-5).** The relay address is per-conversation
configuration behind a single default constant; a self-hosted or on-premise
relay is a first-class deployment. At spec 1.0 the per-conversation address
governs the SEND side; the receive subscription uses the engine-global relay
(TM-C9).

**Transport TLS.** Every relay connection is `https`/`wss` under rustls on
the ring provider; the relay terminates its own TLS and advertises
`http/1.1` only. Because every message is end-to-end encrypted, a transport
adversary — CA mis-issuance, a hostile network — obtains at most the relay
operator's view (TM-R2), never content. Trust anchoring is platform roots by
default with a designed-but-not-yet-user-reachable per-conversation leaf pin
(TM-R6). Cleartext is never permitted in release builds.

**Adversaries considered.** A passive network observer; a hostile network
(active transport MITM); the relay operator (honest-but-curious, and
separately malicious for availability); a peer who misbehaves within their
own conversation; a QR photographer or link interceptor; a malicious app on
the same device; a device thief (before and after first unlock); the supply
chain (dependencies, toolchain, CI). Not considered: an adversary inside the
device trust boundary (root, OS, hardware).

## 3. CLIENT — titlan-android + tezca-core on-device

| STRIDE | applies? | where |
|---|---|---|
| Spoofing | yes — sender authenticity after pairing rests on the Double Ratchet (A2); spoofing at introduction is the pairing surface | TM-P1, TM-P8 |
| Tampering | yes — hostile bytes from the peer or the relay reach the parsers; local storage tamper | TM-C1, TM-C6 |
| Repudiation | n/a — Titlan makes no non-repudiation claim and keeps no audit log; the ratchet's deniability properties are libsignal's, not asserted here | — |
| Information disclosure | yes — the client is where plaintext exists | TM-C1–TM-C5 |
| Denial of service | yes — parser crashes; OS power management; hung network I/O | TM-C6, TM-C7, TM-C8 |
| Elevation of privilege | yes — same-user malware (sandboxed) and the device-compromise class | TM-C10, TM-P2 |

### TM-C1 — Plaintext at rest (INV-1)

Message content, contact names, session state, and keys are written only to
a SQLCipher database (A4) whose 32-byte key is born from the OS CSPRNG in
`tezca-core`, handed once across the FFI, and stored at rest only as
`IV ‖ AES-GCM ciphertext` under a 256-bit non-exportable Android Keystore
key (StrongBox where available, TEE fallback); the wrapped blob is written
atomically to CE app-private storage. A blob that fails GCM authentication is
NEVER silently regenerated (tampering must not masquerade as data loss). The
FFI-side transient copies of the key are zeroized. Backups and device-to-
device transfer are disabled so no extracted copy of app data exists.
**MITIGATED.** Venues: INV-1; A4;
`tezca-core/tests/persistence.rs :: no_plaintext_at_rest_smoke_check`,
`tezca-core/tests/persistence.rs :: wrong_key_is_rejected_cleanly`,
`tezca-core/tests/persistence.rs :: sessions_survive_process_restart`;
`androidTest/Inv1AtRestTest.kt :: noPlaintextAtRestAfterIdentityCreation`
(walks every app-accessible storage root after key-wrap, core open, and
identity generation);
`androidTest/crypto/DbKeyManagerTest.kt :: firstCallCreatesWrappedKeyAtRest`,
`androidTest/crypto/DbKeyManagerTest.kt :: tamperedBlobFailsToUnwrap`,
`androidTest/crypto/DbKeyManagerTest.kt :: wrappingIsRandomized`,
`androidTest/crypto/DbKeyManagerTest.kt :: unwrapRoundTripAcrossInstances`;
`androidTest/BackupDisabledTest.kt :: mergedManifestDisablesBackup` plus the
CI step "Backup rules — aapt2 vs built APK (cloud + d2d excluded)" in
CI job "Android — instrumented (Keystore wrap, INV-1 at-rest)".

### TM-C2 — Plaintext in logs, crash reports, or debug output (INV-1)

No key material, plaintext, or mailbox routing id may reach logcat, and no
crash-reporting or telemetry pathway may exist. The debug build carries
exactly four pinned logcat emitters (a fixed-literal delivery sentinel and
three hash-plus-length probes) whose only dynamic content is a SHA-256 hex
and a bare count; every other logcat call in those files is a failure.
**MITIGATED.** Venues:
`androidTest/LogcatHygieneTest.kt :: dbKeyNeverAppearsInLogcat` (all
buffers, every common encoding, across the key's full lifecycle, with a
positive-control canary);
`androidTest/sync/SyncLogcatHygieneTest.kt :: noSecretsInLogcatAcrossSyncPath`;
`scripts/check-invariants.sh family 6`, `scripts/check-invariants.sh family 9`,
`scripts/check-invariants.sh family 10` (the pinned emitters and stray-log
sweeps); `scripts/check-invariants.sh family 12` (crash-SDK absence: zero
`acra|crashlytics|sentry|bugsnag|firebase` tokens in the Gradle lockfile and
build script); `docs/checklists/4b2-e-locked-boot.md` property 4 ("no
INV-1-violating log output", DOCUMENTED-MANUAL; PASS 2026-07-22 on a physical
GrapheneOS Pixel 9, ledger item 9). Observation, not a claim: `tezca-core`
carries no logging framework on any receive path (the spec text in
`proto/envelope.md §Unknown and unsupported types` says so), but no standing
check asserts it for the core crate — the zero-logging sweep of
`scripts/check-invariants.sh family 4` covers the relay only.

### TM-C3 — The native-tombstone RESIDUAL (INV-1 "crash reports")

Decrypted content transits native memory: the libsignal decrypt output and
the inner-frame plaintext live on the Rust heap in `tezca-core`, cross the
UniFFI boundary as byte buffers, and become Kotlin `String` objects for
display. Nothing guarantees zeroization of message plaintext across
allocator frees on any of those three layers (the SQLCipher key is the one
value with zeroize-on-drop discipline; message content is not). Consequently
(i) a native crash produces an Android tombstone that can capture stack and
nearby heap memory of the process, which may include plaintext or key bytes
at the instant of the crash, and (ii) freed-but-unscrubbed pages may hold
plaintext until reused. Tombstones are readable only by the system/root, and
process memory only by the same class; so the bound is the
**device-compromise class**: an adversary who can read tombstones or process
memory can already read the unwrapped SQLCipher key and the database, and
gains nothing new in kind — but the residual persists a copy of plaintext
past the crash, and no check covers it. **RESIDUAL.** Record: ledger item 24
(2026-08-13, INV-1 matrix: "ledgered residuals: native-tombstone bound → 5b-3
threat model"); INV-1's "crash reports" clause is otherwise enforced by
`scripts/check-invariants.sh family 12` (no crash-reporting SDK), which
bounds the exposure to on-device tombstone files.

### TM-C4 — Device loss and lock posture

Two regimes, decided by the 4b-2 boot-and-storage design:

- **Before first unlock (BFU).** The wrapped key lives in CE storage, which
  is sealed until the user's first unlock after boot; there is no direct-boot
  support and no key material in device-protected storage. Every entry point
  (service start, app launch, receivers) checks `isUserUnlocked` before any
  CE touch and "declines cleanly": no crash, no retry-spin against sealed
  storage, no notification, no INV-1-violating log output. A stolen device
  that is never unlocked yields nothing. **MITIGATED** (DOCUMENTED-MANUAL):
  `docs/checklists/4b2-e-locked-boot.md` (steps 1–17, four properties),
  evidence of record PR #20 (PASS 2026-07-22, physical GrapheneOS Pixel 9;
  ledger item 9); design record 4b-2 freeze §2.
- **After first unlock (AFU), device locked.** The wrapping key requires no
  user authentication and is not invalidated by lock-screen or biometric
  changes, so the foreground sync service can decrypt and persist deliveries
  while the screen is locked. The key itself is non-exportable, but an
  adversary who achieves code execution as the app or as root on an
  AFU-locked device can unwrap the database key. **ACCEPTED** — a deliberate
  trade for always-on sync. Record: 4b-1 flag F1 (maintainer-resolved; the
  resolution is recorded in `DbKeyManager.kt` and pinned by
  `androidTest/crypto/DbKeyManagerTest.kt :: keyUsableWhileDeviceLocked` and
  `androidTest/crypto/DbKeyManagerTest.kt :: wrappingKeyLifecycleMatchesResolvedF1`).
- **Uninstall / reset.** Uninstall destroys the Keystore key and the wrapped
  blob together; the database is unrecoverable and recovery is re-pairing.
  A data-loss property, not a threat (recorded in `DbKeyManager.kt`).
- **TTL edge.** A device rebooted and never unlocked for ≥ 14 days loses
  its queued inbound messages to the relay's idle-mailbox TTL (its
  subscription cannot run while CE storage is sealed). Documented, not
  discovered. **ACCEPTED.** Record: 4b-2 freeze §2 ("TTL edge documented,
  not discovered: reboot + never-unlocked ≥14 days loses queued messages to
  relay TTL. Stated in threat model + user docs"); the relay side of the
  bound is `proto/relay-api.md §Configuration` (`--ttl-secs` 14 d) and the
  loss-detection path `proto/recovery.md §3. Generations`.

### TM-C5 — Screen surface

Screenshots, screen recording, and the recents thumbnail are suppressed by
`FLAG_SECURE` on every activity window, set centrally in the Application's
lifecycle callbacks so no activity can opt out by omission. Shoulder-surfing
of a displayed screen is physical and out of scope. **MITIGATED.** Venue:
`androidTest/FlagSecureTest.kt :: mainActivityWindowIsSecure`. The pairing
QR is the one screen designed to be photographed — its exposure is the
pairing surface (TM-P1).

### TM-C6 — Hostile bytes at the parsers (INV-4)

Every byte a client parses before authentication is attacker-controlled: the
outer envelope (from the relay), the inner frame and control frames (from a
peer, after ratchet decryption), the pairing bundle and offer (from a QR or
link), and the relay's WebSocket frames. All Titlan parsers reject cleanly
with typed errors and never panic; unknown versions and types are rejected,
never guessed. **MITIGATED.** Venues: INV-4; `proto/envelope.md §Layer 1`,
`proto/envelope.md §Layer 2`, `proto/envelope.md §Control-frame payload header`;
`tezca-core/tests/envelope_spec.rs :: outer_negatives`,
`tezca-core/tests/envelope_spec.rs :: inner_negatives`,
`tezca-core/tests/envelope_spec.rs :: unknown_type_is_a_protocol_error_not_a_recognized_one`,
`tezca-core/tests/envelope_spec.rs :: prop_outer_parse_never_panics`,
`tezca-core/tests/envelope_spec.rs :: prop_inner_parse_never_panics`,
`tezca-core/tests/envelope_spec.rs :: oversize_fails_before_any_crypto`;
`tezca-core/src/pairing.rs :: bundle_with_device_id_other_than_1_is_malformed`,
`tezca-core/src/pairing.rs :: mailbox_update_v1_with_trailing_bytes_is_malformed`,
`tezca-core/src/pairing_v3_acceptance.rs :: r8_trailing_bytes_after_offer_sig_reject`;
CI job "Fuzz — envelope + relay parsers (INV-4)" (four cargo-fuzz targets,
90 s each, on every push and PR). Workspace-wide `#![forbid(unsafe_code)]`
removes memory-unsafety from the parser threat class (ledger item 23, F1
ADOPT-A; enforced by the compiler in
CI job "Rust — fmt, clippy, build, test"). The pairing-specific frame
threats are expanded in TM-P4.

### TM-C7 — Availability under OS power management (A9)

Delivery depends on a long-lived WebSocket held by a foreground service (no
FCM/push rails, by decision). The service posts a fixed-text persistent
notification, survives backgrounding, and queues-then-delivers across an
airplane-mode gap. **MITIGATED** for the foreground-service lifecycle:
`androidTest/sync/SyncServiceLifecycleTest.kt :: startPostsPersistentNotificationAndSurvivesBackground`,
`androidTest/sync/SyncServiceLifecycleTest.kt :: airplaneModeQueuesAndDeliversOnReconnect`,
`androidTest/sync/SyncManifestTest.kt :: syncServiceDeclaredWithSpecialUseForegroundType`,
`androidTest/LaunchSyncTest.kt :: coldLaunchWithPairedConversationStartsSync`.
**ACCEPTED — the no-exemption Doze posture:** the app requests no
battery-optimization exemption (the prompt is out of MVP scope); under forced
deep Doze on a physical GrapheneOS Pixel 9, delivery latency measured
1271 / 932 / 1660 ms with deep state IDLE 3/3, and manual whitelisting is
documented as a user choice. The OS may still defer or stop the service under
conditions the measurement did not cover. Record: 4b-2 freeze §9(f) via
`docs/checklists/4b2-f-doze-latency.md`; evidence of record PR #20 (PASSED
2026-07-28; ledger item 9). There are no per-message notifications at spec
1.0 (messages appear when the app is opened) — a deferral ledgered as its own
post-MVP design gate (4b-2 freeze §7).

### TM-C8 — Unbounded network I/O (availability)

No timeouts are configured on relay HTTP/WebSocket operations; a joined
`stop_sync` landing during a control frame's shielded network leg waits on
OS TCP behavior. A hostile or broken relay can therefore hold a client
operation open for as long as the OS allows. **RESIDUAL.** Record:
`docs/acceptance-venues.md` ledgered
follow-up "Bounded network-I/O timeouts (Phase 5 hardening, recorded 2026-07-28)".

### TM-C9 — INV-5 on the receive path

`set_conversation_relay` repoints the SEND side only; the subscribe/receive
endpoint is the engine-global relay given at `open()`. A conversation "moved"
to a self-hosted relay still receives on the device's default relay, so the
default relay's operator retains the receive-side metadata view (TM-R2) for
that conversation, contrary to what a user configuring a per-conversation
relay might expect. **RESIDUAL.** Record: `docs/acceptance-venues.md`
ledgered follow-up "INV-5 gap on the receive path" (4b-3 / Phase 5
invariant-audit item, recorded 2026-07-21). The single-constant half of
INV-5 is mitigated: `scripts/check-invariants.sh family 7` (release
BuildConfig placeholder, debug-only override) and
`scripts/check-invariants.sh family 14` (no relay-URL literal outside
`tezca-core/src/config.rs`), plus
`tezca-core/tests/persistence.rs :: conversations_and_messages_persist_and_relay_url_is_per_conversation`.

### TM-C10 — The device-compromise class

Root, a compromised OS, a malicious Keystore implementation, physical memory
extraction, or a same-user process with debugging privileges can read the
unwrapped database key, session state, and plaintext from process memory.
No client mitigation addresses this class; it is the boundary of the model.
**ACCEPTED.** Record: A4 (the at-rest design assumes a hardware-backed
Keystore) and INV-1's scope ("at rest"; "logs, crash reports, or debug
output") — neither extends to a compromised device; see also TM-C3.

## 4. RELAY — tezca-relay

| STRIDE | applies? | where |
|---|---|---|
| Spoofing | yes — a spoofed relay (transport); a spoofed client is n/a by construction (no client identity exists; mailbox ids are bearer capabilities) | TM-R6, TM-R10 |
| Tampering | yes — a relay (or transport MITM) can alter, replay, reorder, or drop blobs | TM-R7 |
| Repudiation | n/a — the relay keeps no log by design (INV-2) and asserts nothing about who sent what; there is nothing to repudiate | — |
| Information disclosure | yes — the central design goal; the accepted exposure is stated plainly | TM-R1, TM-R2, TM-R9 |
| Denial of service | yes — resource exhaustion, transport-level DoS, restart loss | TM-R3, TM-R4, TM-R5 |
| Elevation of privilege | yes — compromise of the relay host | TM-R8 |

### TM-R1 — Blindness: content and sender (INV-2, INV-8)

The relay never receives, parses, or stores sender identity, plaintext,
contact graphs, or PII. Mechanically: deposit admission reads `blob[0..4]`
(magic) and `blob[4]` (version) and the 9-byte minimum, nothing further; the
`kind` byte and ciphertext are opaque; delivery returns the deposited bytes
verbatim; error bodies are empty and identical across unknown / expired /
deleted mailboxes; there is no logging statement anywhere in the relay
outside the fixed startup line; the relay binary's normal dependency graph
excludes `tezca-core` (it cannot decode an envelope even by accident); and
the pipeline's observable behavior is identical for envelopes that differ
only in interior bytes. The human leg — every relay PR reviewed against the
six-point checklist — covers what automation cannot. **MITIGATED.** Venues:
INV-2; INV-8 (Horizon §H4.1); A5; A6;
`proto/relay-api.md §Invariants realized here`; `proto/envelope.md §Layer 1`
(relay admission is a strict subset of the receiver rules);
`scripts/check-invariants.sh family 4` (zero-logging and no-filesystem sweep
of `tezca-relay/src`); `scripts/check-invariants.sh family 11` (dependency-
graph blindness: `cargo tree -e normal` excludes `tezca-core`);
`tezca-relay/src/wire.rs :: admission_checks_magic_version_and_length_only`;
`tezca-relay/tests/limits.rs :: relay_stores_blobs_verbatim_and_blindly`;
`tezca-relay/tests/zero_knowledge.rs :: reject_paths_never_emit_mailbox_id_or_source`;
`tezca-relay/tests/zero_knowledge.rs :: relay_output_contains_no_mailbox_ids_or_source_addresses`;
`tezca-relay/tests/zero_knowledge.rs :: relay_treatment_is_byte_identical_for_differing_inner_payload_types`
(admission verdicts, HTTP responses, delivery framing, and rate accounting
independent of envelope interiors); `docs/checklists/inv8-relay-blindness.md`
(the review procedure, applied to every PR touching `tezca-relay/`).

### TM-R2 — The ACCEPTED EXPOSURE: what the relay and the network necessarily see

The relay, and any party with the relay operator's view (a transport MITM,
a host intruder), necessarily observes:

- **Mailbox ids** — 256-bit random (POST) or root-derived (PUT) tokens;
  opaque, but stable for the life of a mailbox, so they name a
  conversation-direction over time.
- **Timing** — every deposit and every WebSocket delivery, with the source
  IP of the depositor and the subscriber's connection. A deposit into
  mailbox X from address A followed by delivery to a subscriber at address B
  links A and B for that mailbox; repeated over time this reconstructs
  who-talks-to-whom, message frequency, and online presence, without any
  identity.
- **Blob sizes** — bucketed: the inner frame is padded to 512 / 2048 / 8192
  bytes before encryption, so ciphertext sizes cluster into three classes
  (≈ 1.6 bits of length per message) plus libsignal overhead; a
  session-setup blob (kind `0x01`, carrying Kyber material) is
  distinguishable from a ratchet blob by size and by the outer `kind` byte.
- **Source IPs** — at the TCP layer, for every request. The per-source rate
  limiter keys on a per-boot keyed hash of the address and is structurally
  disjoint from the per-mailbox limiter, so no mailbox↔source pairing exists
  as data; but the socket itself pairs them for the duration of each request.
- **The identity public key during session setup** — the first message(s) of
  a session are libsignal `PreKeySignalMessage`s whose header carries the
  sender's identity public key unencrypted inside the relay-opaque blob. The
  relay does not read it (TM-R1), but the bytes are present; a relay that
  chose to parse them could correlate identical identity keys across
  conversations at setup time.

**What sealed sender and padding DO mitigate:** no cleartext sender field,
recipient field, payload-type field, or true-length field exists on the wire
(A6, A8); the relay cannot tell chat from control frames, cannot tell a
message's real size within its bucket, and holds no identity to log.
**What they DO NOT mitigate:** timing correlation between deposit and
delivery; frequency and presence; IP-level attribution; the session-setup
identity-key exposure above; and the residual ≈ 1.6-bit length channel.
There is no cover traffic, no timing jitter, no mixing, no batching, and no
anonymity network integration at spec 1.0; a global passive observer or the
relay operator can perform traffic analysis to the limits stated. Users who
need IP-level unlinkability must supply it outside Titlan. **ACCEPTED.**
Records: A6 (rationale "metadata minimization", not elimination); A8 and
`proto/envelope.md §Padding buckets and profiles` (the 1.6-bit leak is
stated; single-bucket profiles are informative guidance for future mixed
conversations); `proto/pairing.md §Privacy note` (identity-key exposure at
setup "Accepted for MVP; sealed-sender-style outer wrapping is a post-MVP
hardening option"); the Phase 5 plan of record's "sealed-sender metadata
bounds" line (ledger item 22). Future group fanout would add
temporally-clustered N-deposit patterns (Horizon §H3.3 — P10 scope, not
spec 1.0).

### TM-R3 — No server-side persistence (INV-3)

Mailboxes exist only in process RAM. The relay source contains no filesystem
API; a live relay child performs no storage writes under load; core dumps
are disabled (`RLIMIT_CORE=0`, not ptrace-dumpable) inside the binary; the
binary calls `mlockall(CURRENT|FUTURE)` best-effort and, when the
environment grants memlock, its pages are verifiably locked (`VmLck > 0`);
the shipped systemd unit adds `MemorySwapMax=0`, `LimitCORE=0`,
`LimitMEMLOCK=infinity`, `ProtectSystem=strict`, `ReadOnlyPaths=/`,
`PrivateTmp=yes` (each content-asserted, not merely syntax-checked), runs as
a `DynamicUser` with `NoNewPrivileges`, `MemoryDenyWriteExecute`, and a
`@system-service` syscall filter. Memory stays flat under sustained load.
**MITIGATED.** Venues: INV-3; `proto/relay-api.md §Invariants realized here`;
`scripts/check-invariants.sh family 4` (no-filesystem sweep);
`scripts/check-invariants.sh family 13` (unit hardening directives);
CI job "Relay — systemd unit hardening (INV-3)";
`tezca-relay/tests/zero_knowledge.rs :: relay_never_writes_to_storage`;
`tezca-relay/src/hardening.rs :: hardening_applies_core_limit`;
`tezca-relay/tests/relay_lifecycle.rs :: relay_memory_is_locked_when_memlock_granted`;
`tezca-relay/tests/relay_lifecycle.rs :: memory_stays_flat_under_sustained_load`
(run single-threaded in CI job "Rust — fmt, clippy, build, test").
**RESIDUAL (deployment-dependent):** the in-binary `mlockall` is
best-effort and silently continues on `EPERM` (zero-logging leaves no warn
channel); a deployment that does not grant memlock or does not use the
shipped unit's `MemorySwapMax=0` may have mailbox memory swapped to disk.
The `VmLck` test skips cleanly where the environment denies memlock. Record:
`proto/relay-api.md §Invariants realized here` ("best-effort `mlockall`;
deploy adds `MemorySwapMax=0`"); the `LimitMEMLOCK` rationale in
`deploy/tezca-relay.service`.

### TM-R4 — Restart message loss, with client redelivery and recovery

A relay restart destroys every mailbox and every queued blob. Three
consequences, each with its venue:

1. **Unacked-in-flight messages redeliver.** A blob delivered over the
   WebSocket but not yet acked is redelivered on reconnect; the client acks
   only after decrypt AND durable SQLCipher persist, so a process death
   between persist and display loses nothing, and a relay-side redelivery of
   an already-persisted blob is rejected by the ratchet as a replay
   (TM-P5). **MITIGATED:** `proto/relay-api.md §GET /v1/mailboxes/{id}/ws`;
   `tezca-relay/tests/relay_lifecycle.rs :: thousand_messages_with_kill_and_restart`;
   `tezca-relay/tests/relay_lifecycle.rs :: unacked_messages_are_redelivered_on_reconnect`;
   `tezca-relay/tests/relay_client_e2e.rs :: delivered_message_is_durably_persisted`;
   `tezca-relay/tests/relay_client_e2e.rs :: ack_after_persist_holds_across_stop_in_raced_interleavings`.
2. **Routing is re-established without re-pairing** via derived recovery
   mailboxes: on the `404` loss signal each party PUT-creates and subscribes
   its own derived inbox at the next generation and probes the peer's
   derived inboxes across a W = 4 window with a sealed `recovery-hello`;
   convergence on `max(g)` is followed by an offerer-initiated
   drain-then-switch rotation onto fresh relay-generated inboxes, so no
   in-flight chat is stranded and the derived ids are retired. Messages
   queued on the sender while the relay was down deliver after recovery.
   Recovery is bounded: window offset ≥ 4 or three completed probe cycles
   without verified contact ⇒ `conversation-needs-repair`, surfaced through
   the FFI. **MITIGATED:** `proto/recovery.md §3. Generations`,
   `proto/recovery.md §4. Convergence`, `proto/recovery.md §5. Exhaustion`,
   `proto/inner-frame.md §Rotation ordering`;
   `tezca-relay/tests/relay_client_e2e.rs :: v2_single_total_loss_recovers_via_derived_mailboxes`;
   `tezca-relay/tests/relay_client_e2e.rs :: v2_two_consecutive_total_losses_each_recover`;
   `tezca-relay/tests/relay_client_e2e.rs :: v2_message_queued_while_relay_down_delivers_after_recovery`;
   `tezca-relay/tests/relay_client_e2e.rs :: v2_peer_unreachable_exhausts_recovery_and_needs_repair`;
   `tezca-core/src/recovery.rs :: double_restart_desync_converges_to_max`;
   `androidTest/sync/RecoveryTest.kt :: needsRepairSurfacesThroughFfiOnRecoveryExhaustion`;
   `androidTest/sync/RecoveryTest.kt :: pacing429sDoNotSurfaceNeedsRepairThroughFfi`.
3. **What is lost anyway.** Blobs deposited at the relay but not yet fetched
   by the recipient at the instant of restart are gone, silently: there is
   no end-to-end delivery receipt at spec 1.0 (`0x08 receipt` is reserved,
   semantics unspecified), so the sender learns nothing. Three sub-cases
   are re-pair-only: total loss after `pair-ack/2` but before the
   `mailbox-update/2` handoff landed (the two parties share no root yet);
   conversations without a persisted root (paired before the v2/v3 offer
   flow, or whose handoff never landed) fall back to one-sided
   `mailbox-update/1` recovery and are re-pair-only on total loss,
   permanently; and recovery blocked at the global mailbox cap (uniform
   `503`). **ACCEPTED.** Records: INV-3 ("Relay restart loses all queued
   messages (acceptable for MVP; client handles redelivery via
   acknowledgment/retry)"); `proto/inner-frame.md §Derived recovery-mailbox IDs`
   ("Edge — total loss before the handoff lands … Accepted (frozen §8)");
   `proto/recovery.md §6. Conversations without a recovery root`;
   `proto/relay-api.md §PUT /v1/mailboxes/{id}` ("recovery-blocked-at-cap
   is accepted, frozen §8"); 4b-2 freeze §8;
   `proto/envelope.md §Payload type registry` (receipt reserved, Horizon §H1.1).

### TM-R5 — Availability and denial of service

Per-source and per-mailbox rate limits, per-mailbox message and byte caps, a
global mailbox cap, a blob-size ceiling, and TTL expiry bound what any one
source or mailbox can consume; the limiters are in-memory and reset on
restart. The TLS listener advertises `http/1.1` only in ALPN, so no HTTP/2
surface (and no h2-class flow-control DoS, cf. the RUSTSEC-2026-0258 arc)
exists on the relay; the two byte-level parsers (deposit admission, ack
frame) are fuzzed in CI. **MITIGATED** for the listed classes. Venues:
`proto/relay-api.md §Configuration` (caps and defaults, work order §10.2
resolved 2026-07-14);
`tezca-relay/tests/limits.rs :: create_rate_limit_per_source`,
`tezca-relay/tests/limits.rs :: deposit_rate_limit_per_mailbox`,
`tezca-relay/tests/limits.rs :: mailbox_message_capacity`,
`tezca-relay/tests/limits.rs :: mailbox_byte_capacity`,
`tezca-relay/tests/limits.rs :: ttl_expires_messages_and_mailboxes`,
`tezca-relay/tests/limits.rs :: deposit_negatives` (`413` above the blob
ceiling);
`tezca-relay/tests/put_mailbox.rs :: put_rate_limited_returns_429_when_source_limit_exhausted`,
`tezca-relay/tests/put_mailbox.rs :: put_at_cap_is_uniform_capacity_error_regardless_of_existence`;
`tezca-relay/tests/alpn_pin.rs :: relay_offers_http1_alpn_only_and_never_h2`;
CI job "Fuzz — envelope + relay parsers (INV-4)";
`tezca-relay/tests/relay_lifecycle.rs :: memory_stays_flat_under_sustained_load`.
**RESIDUAL:** volumetric and transport-layer denial of service (SYN floods,
TLS-handshake exhaustion, bandwidth saturation) has no in-protocol defense —
it is a deployment concern (reverse proxy, network filtering) outside the
relay's venues. **ACCEPTED (limiter shape):** per-source limits key on the
client IP, so populations behind one NAT share a budget (an availability
nuisance) and an adversary with many addresses multiplies theirs; the global
mailbox cap can be filled by a distributed adversary, at which point new
pairings and recoveries fail uniformly (`503`). Records: work order §10.2
relay-defaults resolution (2026-07-14: "All config; defaults only");
`proto/relay-api.md §PUT /v1/mailboxes/{id}` (recovery-blocked-at-cap
accepted). No ratified text names the volumetric residual — see the register.

### TM-R6 — Spoofed relay and transport TLS

The client speaks `wss`/`https` under rustls (ring provider) and accepts a
server certificate in one of two ways: **platform trust roots** (the
default, via the platform verifier), or a **per-conversation leaf-certificate
pin** (SHA-256 of the leaf DER) that bypasses CA validation and trusts
exactly one certificate. Cleartext is never permitted outside the debug
build, and the debug-only CI trust anchor is kept out of release by five
static checks and a binary scan of the release `.so`. A spoofed relay under
platform trust therefore requires CA mis-issuance or a compromised root
store, and even then obtains only the relay operator's view (TM-R2) plus the
ability to drop traffic (TM-R7) — never content. **MITIGATED** for the
pin path and for the release-carries-no-test-anchor property: A2 (rustls/ring
are the audited TLS crates INV-6 names);
`tezca-core/src/relay_client/ws/pin.rs :: pinned_certificate_is_accepted`,
`tezca-core/src/relay_client/ws/pin.rs :: certificate_not_matching_pin_is_rejected`,
`tezca-relay/tests/tls_anchor_e2e.rs :: anchored_wss_pairs_and_delivers_and_wrong_cert_is_rejected`
(both client legs under a pin, and the wrong-certificate rejection);
`scripts/check-invariants.sh family 5` (network-security-config debug-only,
no cleartext outside debug, `test-relay-anchor` never a default feature,
debug/release Gradle split, anchor string absent from every release `.so`).
**ACCEPTED — the certificate-pinning posture at spec 1.0:** pinning is
"optional-but-designed" (work order §6 Phase 4): the core stores an optional
`relay_pin` per conversation and honors it on every subscribe, but no FFI
method and no UI sets it, so every release build runs on platform trust
roots; the pin is exercised only by the debug/CI test anchor. SPKI-scoped
pinning (surviving certificate renewal) is likewise designed, not built.
Records: work order §6 Phase 4 ("certificate pinning to configured relay
optional-but-designed"); the Phase 5 plan of record's "certificate-pinning
posture" line (ledger item 22); ledger item 24 ("release trust-anchor row
exercised at 5d-2"). The relay's own TLS certificate is rotated by process
restart (no hot reload) — `proto/relay-api.md §Resolved and open items`, a
post-MVP operational item.

### TM-R7 — A malicious relay (integrity and availability)

An operator, or a transport MITM, can drop, delay, or withhold blobs, replay
them, deliver them out of order across mailboxes (per-mailbox FIFO is an
honest-relay promise), subscribe to any mailbox whose id it holds and ack
(delete) its contents, or alter bytes. **MITIGATED** for integrity and
replay: an altered blob fails Double Ratchet authentication and a
redelivered one is rejected as a replay, so no forged or duplicated message
is ever accepted (A2 — libsignal's authenticated encryption is the locked
mechanism; `tezca-core/tests/session_roundtrip.rs :: duplicate_delivery_is_rejected_as_replay`;
`tezca-core/tests/session_roundtrip.rs :: ratchet_150_messages_with_out_of_order_delivery`
for reordering within a session). **RESIDUAL** for availability: a relay
that silently drops or withholds traffic is indistinguishable from a quiet
peer; there is no delivery receipt, no second path, and no relay
attestation. The trust model states the relay is relied upon for
availability in the honest-but-curious sense; no ratified text accepts the
malicious-availability case explicitly — see the register.

### TM-R8 — Relay host compromise (elevation of privilege)

An intruder on the relay host gains the operator's view (TM-R2) and the
contents of RAM at that moment: queued ciphertext blobs (useless without
session keys) and the live set of mailbox ids (usable to subscribe, deposit,
or delete until the affected conversations rotate). There is nothing on disk
to exfiltrate (TM-R3), and the systemd sandbox (`DynamicUser`,
`NoNewPrivileges`, `ProtectSystem=strict`, syscall filter) limits what a
compromised relay process can reach. **MITIGATED** for persistence and
process containment by the TM-R3 venues. **RESIDUAL:** mailbox ids learned
at compromise remain valid until the clients rotate them, and rotation
happens only at pairing and at recovery convergence — there is no
"suspected-compromise" rotation trigger; the six unit directives beyond the
content-asserted set (`NoNewPrivileges`, `MemoryDenyWriteExecute`, the
syscall filter, and the `Protect*`/`Restrict*` lines) are verified for
well-formedness only (CI job "Relay — systemd unit hardening (INV-3)"), not
content-asserted. No ratified text addresses the post-compromise rotation
gap — see the register.

### TM-R9 — Existence oracles and enumeration

Mailbox ids are 256-bit values generated by the relay's OS CSPRNG (POST) or
derived from a per-conversation secret (PUT); unknown, expired, deleted, and
malformed ids all yield the same empty `404`; `DELETE` returns `204`
unconditionally; `PUT` returns byte-identical `201` whether it created or
found the mailbox and a uniform `503` at cap regardless of existence; a
malformed `PUT` id is rejected on shape alone with no state consulted.
Enumeration and correlation by probing are infeasible. **MITIGATED.**
Venues: `proto/relay-api.md §POST /v1/mailboxes`,
`proto/relay-api.md §DELETE /v1/mailboxes/{id}`,
`proto/relay-api.md §PUT /v1/mailboxes/{id}`;
`tezca-relay/tests/zero_knowledge.rs :: unknown_and_expired_mailboxes_are_indistinguishable`;
`tezca-relay/tests/zero_knowledge.rs :: delete_reveals_nothing_about_mailbox_existence`;
`tezca-relay/tests/put_mailbox.rs :: put_creates_idempotently_with_byte_identical_response`;
`tezca-relay/tests/put_mailbox.rs :: put_source_counter_is_independent_of_create_and_deposit`;
`tezca-relay/src/wire.rs :: mailbox_id_encoding_is_43_chars_and_shape_checked`.

### TM-R10 — Mailbox ids as bearer capabilities

Whoever holds a mailbox id can deposit to it, subscribe to it (a second
subscriber replaces the first — device-restart semantics), ack its queued
messages, and delete it. For a third party this is infeasible (TM-R9). For
the conversation peer — who necessarily holds the id it deposits to — the
capability exposes nothing beyond their own conversation: the only depositor
to a mailbox is that peer, so subscribing to or deleting it destroys only
their own undelivered messages and closes their own channel. For a holder of
the operator's view, the capability is TM-R7's availability residual.
**MITIGATED** for third parties and bounded for peers: `proto/relay-api.md
§DELETE /v1/mailboxes/{id}` (the capability note),
`proto/relay-api.md §GET /v1/mailboxes/{id}/ws` (subscriber replacement);
`proto/pairing.md §Mailbox rotation at pairing` (a leaked offer never leaks
a durable routing id; the pairing mailbox is deleted on completion);
`tezca-relay/tests/relay_client_e2e.rs :: photographed_qr_is_consumed_after_pairing`.

## 5. PAIRING FLOW — QR path, link path, offer v3 lifecycle, recovery re-derivation

| STRIDE | applies? | where |
|---|---|---|
| Spoofing | yes — a party completing pairing as someone other than the intended peer; a peer's identity never verified out of band | TM-P1, TM-P2, TM-P7, TM-P8 |
| Tampering | yes — altered or re-dated offers; hostile control frames | TM-P3, TM-P4 |
| Repudiation | n/a — pairing produces no signed statement of who paired; nothing is asserted to a third party | — |
| Information disclosure | yes — what a leaked offer reveals | TM-P1, TM-P2 |
| Denial of service | yes — replay/duplicate delivery; recovery exhaustion; nuisance classes | TM-P5, TM-P6, TM-P9, TM-P11 |
| Elevation of privilege | yes — scheme squatting by same-device malware | TM-P2 |

### TM-P1 — QR observation and proof-of-scan

A pairing QR is public: anyone who photographs it obtains the exact offer
bytes — the offerer's public pre-key bundle, relay URL, single-use pairing
inbox id, the 32-byte bearer `pairing_secret`, and the validity window.
Proof-of-scan binds session completion to possession of the OFFER BYTES, not
merely the bundle: the responder's first sealed frame (`pair-ack/2`) carries
`HMAC-SHA256(pairing_secret, responder_bundle ‖ recovery_root_contribution)`,
verified by the offerer in constant time; any mismatch burns the offer. The
offer's key bundle is public-key material only, so a photographer cannot
impersonate the offerer, decrypt anyone's traffic, recover the private key or
database, compute the recovery mailboxes (the root's two contributions are
never in the offer), use the offer past its window or re-date it, or use it
after the legitimate pairing (the pairing mailbox is deleted and the one-time
pre-key consumed). **MITIGATED** for everything but the whole-offer case:
`proto/pairing.md §Proof-of-scan`, `proto/pairing.md §Mailbox rotation at pairing`,
`proto/pairing.md §Offerer behavior` (fresh one-time pre-key per offer;
burn on failed proof; delete on completion), `proto/pairing.md §Part IV`;
`proto/inner-frame.md §Derived recovery-mailbox IDs` (the pairing-secret-
derived root was REJECTED precisely so a photographer cannot pre-derive and
squat recovery mailboxes; work order §10 item 10, resolved 2026-07-19);
`tezca-core/src/pairing.rs :: proof_verifies_with_matching_secret_bundle_and_contribution`,
`tezca-core/src/pairing.rs :: proof_fails_on_wrong_secret_bundle_contribution_or_mac`,
`tezca-core/src/pairing.rs :: pair_ack_v2_roundtrips_and_carries_verifiable_proof`;
`tezca-relay/tests/relay_client_e2e.rs :: photographed_qr_is_consumed_after_pairing`;
`tezca-relay/tests/relay_client_e2e.rs :: scanner_session_cannot_decrypt_third_party_blob`;
`tezca-relay/tests/relay_client_e2e.rs :: two_live_offers_are_each_independently_pairable`.
The displayer forces maximum screen brightness while the QR is shown
(`proto/pairing.md §Per-path security claims`) — a usability choice that
widens the visual exposure window; QR pairing is nonetheless the
recommended path because its exposure is proximal and visual.
**ACCEPTED — complete-offer compromise:** a party holding the entire offer
(bundle + `pairing_secret`, hence also a valid `offer_sig`) can complete
pairing as the responder within the window. Proof-of-scan raises the bar from
"saw the bundle" to "held the offer"; the v3 signature adds nothing against a
holder of the whole offer; this is not a man-in-the-middle defense. The
displayer sees an unknown new conversation it can ignore or delete; no
existing message is exposed. Records: `proto/pairing.md §Ledgered risks`;
v3 freeze §3 ("Does not defend: wholesale substitution … the ledgered
complete-offer-compromise risk, unchanged from v2; this freeze claims nothing
against it"); 4b-2 freeze §3 and §10.

### TM-P2 — Link-path interception and `titlan://` scheme squatting

The same offer bytes travel as a `titlan://pair#<base64url>` link that may
traverse channels an adversary can read — chat apps, clipboard managers,
notification previews, and (for a future `https://titlan.chat/pair#` form)
browser history. A party that reads the link in transit holds the complete
offer and defeats proof-of-scan (TM-P1's accepted case). The fragment is
decoded locally and never touches a server. On the device, the app registers
NO `VIEW` intent filter for `titlan://` at spec 1.0 — link entry is a paste
field reached through the scanner's three degradation triggers — so any app
that does register the scheme receives every tapped `titlan://` link
outright; the scheme is unverified and interceptable by on-device malware.
The link path is therefore a convenience path with strictly weaker
guarantees than QR, and the UI MUST say so; it does. **MITIGATED** for the
disclosure obligation and the byte-identity of the carriers:
`proto/pairing.md §Per-path security claims` (NORMATIVE for presentation);
`proto/pairing.md §Carriers`;
`androidUnit/pairing/LinkPathDisclosureTest.kt :: linkPathSecurityCopyExistsAndNamesQrAsStronger`
(the copy exists, is non-empty, names QR as stronger, and is wired into the
paste path);
`androidTest/pairing/PairingRoundTripTest.kt :: qrAndLinkPayloadsAreByteIdentical`;
`tezca-core/src/pairing_v3_acceptance.rs :: r10_qr_link_byte_identity_round_trip_v3`.
**ACCEPTED — scheme squatting:** on-device malware may claim `titlan://`;
QR is the recommended path and the link path is documented as weaker.
Record: `proto/pairing.md §Ledgered risks`; 4b-2 freeze §3 and §10.
**ACCEPTED — `https://` fragment in browser history:** carried into the
App Links threat model (a static landing page must never read the fragment);
v3 bounds the exposure in time — a recovered fragment is dead past
`issued_at + ttl_s` and cannot be re-dated. Record: `proto/pairing.md
§Ledgered risks`; 4b-2 freeze §4 (App Links migration additive, Phase 5 /
pre-publish; "fragment-in-browser-history caveat in threat model"). The App
Links migration itself has not landed at spec 1.0.

### TM-P3 — Offer expiry and the v3 validity sequence

Offer v3 carries an authenticated validity window: `issued_at` (offerer
clock), `ttl_s` (default 3600, maximum 86 400), and a 64-byte XEd25519
`offer_sig` by the offerer's identity key over every preceding wire byte.
The acceptor evaluates, at decode and before any network I/O, in this order:
structure and version (v3 only), signature, TTL bounds, future skew
(`issued_at ≤ now + 300`), expiry (`now ≥ issued_at + ttl_s`, saturating).
This defeats timestamp resurrection (an expired offer recovered from history
and re-dated), `relay_url`/`pairing_inbox_id` redirection of a genuine offer,
stale-offer acceptance, and any post-mint tamper without identity
substitution. A signature failure never surfaces as expiry and an
unsupported version never as a crypto failure, so the user's four-way
vocabulary (network / expired / malformed / crypto) is truthful. There is
exactly one governing lifetime — the embedded window — read by the UI
countdown, the listener fuse, and the harness alike. **MITIGATED.** Venues:
`proto/pairing.md §Validity rule`, `proto/pairing.md §Authentication`,
`proto/pairing.md §Error classes`, `proto/pairing.md §Single-sourced constants`;
Horizon §H7; v3 freeze §4 / V3-D2 and §3 / V3-D3;
`tezca-core/src/pairing_v3_acceptance.rs :: r1_fresh_mint_round_trips_and_accepts`,
`tezca-core/src/pairing_v3_acceptance.rs :: r2_expired_offer_is_offer_expired_with_zero_network_io`,
`tezca-core/src/pairing_v3_acceptance.rs :: r3_boundary_now_equals_issued_plus_ttl_is_expired`,
`tezca-core/src/pairing_v3_acceptance.rs :: r4_bit_flipped_issued_at_is_signature_invalid_not_expired`,
`tezca-core/src/pairing_v3_acceptance.rs :: r5_ttl_zero_and_over_max_are_malformed`,
`tezca-core/src/pairing_v3_acceptance.rs :: r6_future_dated_beyond_grace_is_not_yet_valid`,
`tezca-core/src/pairing_v3_acceptance.rs :: r9_harness_fuse_equals_embedded_ttl`;
`tezca-core/src/pairing.rs :: committed_conformance_vector_link_round_trips_and_parses`;
`androidUnit/pairing/QrCodecConformanceTest.kt :: committedVectorDecodesToPinnedBytes`;
`tezca-core/src/ffi.rs :: accept_path_classification_is_total_and_four_way`,
`tezca-core/src/ffi.rs :: structural_family_never_surfaces_as_crypto`,
`tezca-core/src/ffi.rs :: crypto_family_is_distinct_and_never_expired`;
`androidUnit/pairing/PairingFailureTest.kt :: classificationIsFourWayCorrect`,
`androidUnit/pairing/PairingFailureTest.kt :: signatureFailureNeverSurfacesAsExpired`,
`androidUnit/pairing/PairingFailureTest.kt :: unsupportedVersionNeverSurfacesAsCrypto`,
`androidUnit/pairing/PairingFailureTest.kt :: expiredStringIsTheFrozenCopyVerbatim`.
**ACCEPTED — clock dependence:** validity is judged against the offerer's
clock at mint and the acceptor's at scan, with a 300 s future-skew grace; a
badly wrong clock on either device makes offers unusable (an availability
nuisance surfaced with a clock hint, never a silent failure). Record: v3
freeze §4 / V3-D2 (ratified 2026-08-10).

### TM-P4 — Hostile or unknown frames

Every frame a client fetches was sealed by SOME session (or fails to
decrypt); the threat is a peer, or a leaked offer's holder on a pairing
inbox, sending frames the receiver must not misinterpret. Four rules close
the misinterpretation class: (i) a frame that fails to decrypt, is unknown,
or is recognized-but-unsupported is acked and discarded — persisted nowhere,
no user-visible error, no redelivery loop, nothing logged that pairs the
type with a conversation — and the listener keeps delivering; (ii)
`mailbox-update` dispatch is STRICT on `type_version` (only 1 routes to the
`/1` parser, only 3 to `/3`; anything else is ack-and-discard), so a frame
whose version is outside the implemented set but whose body is `/1`-shaped
cannot rewrite the conversation's send coordinates and silently redirect
every subsequent outbound message; (iii) every control payload's leading
byte must equal its `type_version` and trailing bytes are malformed; (iv)
control-class and message-class frames never cross — a control frame is
never surfaced as a message, a message-class frame never consumed as
control. On a pairing inbox, only a `pair-ack` with `type_version 2` is
processed; a failed proof burns the offer; anything else is acked and
ignored. A responder bundle with `device_id ≠ 1` is rejected before any key
material is touched. **MITIGATED.** Venues:
`proto/envelope.md §Unknown and unsupported types` (NORMATIVE; Horizon §H1.4);
`proto/envelope.md §Control-frame payload header`;
`proto/inner-frame.md §Discrimination rule`;
`proto/pairing.md §Offerer behavior`; `proto/pairing.md §Device-set semantics`;
`tezca-relay/tests/relay_client_e2e.rs :: mailbox_update_with_unknown_type_version_is_never_processed_as_v1`;
`tezca-relay/tests/relay_client_e2e.rs :: unimplemented_payload_type_is_acked_and_discarded_on_live_inbox`;
`tezca-core/src/pairing.rs :: mailbox_update_v1_with_trailing_bytes_is_malformed`;
`tezca-core/src/pairing.rs :: bundle_with_device_id_other_than_1_is_malformed`;
`tezca-core/tests/envelope_spec.rs :: chat_extraction_declines_machine_payloads_gracefully`;
`tezca-core/tests/envelope_spec.rs :: reserved_types_round_trip_as_first_class_frames`;
`tezca-core/src/pairing.rs :: mailbox_update_v2_roundtrips_contribution`;
`tezca-core/src/recovery.rs :: recovery_hello_round_trips_and_rejects_malformed`.
Note the trust shape: a `mailbox-update` from the legitimate peer's session
is authenticated by the ratchet and is that peer's own routing announcement;
the rules above defend against confusion and version ambiguity, not against
a peer's authority over their own inbox.

### TM-P5 — Replay and duplicate delivery: the at-least-once contract

Delivery is AT-LEAST-ONCE by design: unacked messages are redelivered on
reconnect, a WebSocket subscriber replays the queue in deposit order, and the
recovery probe deposits the same sealed `recovery-hello` into up to W = 4
peer generations. Duplicates are neutralized in two layers. For chat and
control frames generally, the Double Ratchet rejects a redelivered blob as a
replay (the message key is consumed on first decrypt), and a rejected frame
is ack-and-discarded, so no message is persisted or displayed twice. For
`recovery-hello`, whose redelivery is the designed idempotent probe, the
receiver dedups by `(generation, nonce)` in a **512-entry per-conversation
ring**, oldest-evicted, held in memory only (no time-based eviction, no
configuration knob): a seen pair is acked but not reprocessed, so convergence
is applied exactly once per hello. Only a VERIFIED (ratchet-decrypted) hello
moves generations — an unauthenticated deposit into a derived inbox is not
contact. **MITIGATED.** Venues:
`proto/relay-api.md §GET /v1/mailboxes/{id}/ws` ("at-least-once; the
client ratchet rejects true duplicates"); `proto/recovery.md §7. Relay-side facts`;
`proto/inner-frame.md §Verified receipt and replay dedup`;
`proto/recovery.md §4. Convergence` (the 512-entry ring);
`tezca-relay/tests/relay_lifecycle.rs :: unacked_messages_are_redelivered_on_reconnect`
(the redelivery test; also the origin of the at-least-once characterization
in ledger item 25);
`tezca-core/tests/session_roundtrip.rs :: duplicate_delivery_is_rejected_as_replay`;
`tezca-relay/tests/relay_client_e2e.rs :: stop_sync_halts_receive_and_unacked_blob_redelivers_on_restart`;
`tezca-relay/tests/relay_client_e2e.rs :: delivered_message_is_durably_persisted`.
**ACCEPTED (ring properties):** the ring does not survive process restart,
so a hello redelivered after a restart is reprocessed once — an idempotent
`max(g)` adoption, never a regression; and a burst of more than 512 distinct
hellos in one conversation evicts the oldest pairs. Record: ledger item 28
(F2 amendment, 2026-08-24: "the implemented 512-entry per-conversation
in-memory ring — oldest-evicted, no time-based eviction, no configuration
knob"), as frozen in `proto/inner-frame.md §Verified receipt and replay dedup`.

### TM-P6 — Recovery re-derivation

Derived recovery mailboxes are `HMAC-SHA256(root, "titlan-recovery-mailbox-v1"
‖ role ‖ generation)` — 256-bit, role- and generation-separated, computable
only by the two holders of the root. The root is `HMAC-SHA256(A_contrib,
B_contrib)` from two 32-byte CSPRNG contributions exchanged only inside
sealed frames, never in the offer, so a QR photographer, a link interceptor,
or a relay operator cannot pre-derive or PUT-squat the sequence (the
pairing-secret-derived alternative was rejected for exactly that
recovery-denial attack). Creation is idempotent and oracle-free. A relay
operator observing a derived id at generation g learns nothing about g + 1.
Recovery is bounded (window and cycle exhaustion) so a dead or hostile peer
cannot drive an unbounded probe storm, and relay `429`s pace rather than
count. **MITIGATED.** Venues: `proto/recovery.md §1. Roles`,
`proto/recovery.md §2. Derived mailbox IDs`, `proto/recovery.md §5. Exhaustion`;
`proto/inner-frame.md §Derived recovery-mailbox IDs`; work order §10 item 10
(2026-07-19 resolutions: HMAC-PRF; dual-contribution root);
`tezca-core/src/recovery.rs :: root_is_symmetric_across_parties_but_order_sensitive`,
`tezca-core/src/recovery.rs :: mailbox_ids_are_43_chars_and_role_generation_separated`,
`tezca-core/src/recovery.rs :: sender_forward_window_is_w_wide`,
`tezca-core/src/recovery.rs :: offset_at_or_beyond_window_is_exhausted`,
`tezca-core/src/recovery.rs :: cycle_exhaustion_counts_attempts_and_429_within_an_attempt_cannot_advance`;
`tezca-relay/tests/relay_client_e2e.rs :: pair_v2_offer_proof_and_exchange`;
`tezca-relay/tests/relay_client_e2e.rs :: v2_peer_unreachable_exhausts_recovery_and_needs_repair`.
**ACCEPTED:** derived ids are forever computable from persisted client state
— a seized (unlocked) device yields the future routing-id sequence of every
conversation it holds, which is why rotation retires derived mailboxes as
soon as the two sides converge (they are a bridge, never a home). Record:
4b-2 freeze §8 (rotation "ledgered justification: … a seized device must not
yield the future routing-ID sequence"); `proto/recovery.md §4. Convergence`.

### TM-P7 — Redirection to a non-default relay

An offer names the offerer's relay. Under v3 the `relay_url` is inside the
signed prefix, so a genuine offer cannot be redirected after mint (TM-P3);
an attacker-minted offer can name any relay it likes (TM-P1's accepted
case). When the offer's relay differs from the app default, the responder's
UI displays it and requires explicit confirmation before session
establishment; silent adoption is rejected. **MITIGATED** (spec):
`proto/pairing.md §Mailbox rotation at pairing` (the "Non-default relay"
rule, NORMATIVE); 4b-2 freeze §3. No named test pins the confirmation gate;
the user's judgment of the displayed URL is the remaining control.

### TM-P8 — Trust-on-first-use and the absence of identity verification

The peer's identity key is recorded at pairing and trusted thereafter. Spec
1.0 provides no safety numbers, no key-change notification, and no directory
or transparency log (deferred by A7). A pairing completed by the wrong party
(TM-P1/TM-P2's accepted cases) is therefore detectable only out of band —
the offerer sees an unexpected new conversation — and a peer's key change is
not a first-class event. **RESIDUAL.** Record: A7 ("directory/key-
transparency deferred"); `proto/pairing.md §Part I` ("Identity keys received
here are recorded as TOFU … key-change handling and safety numbers are
post-MVP"); `proto/pairing.md §Ledgered risks` ("re-pair and safety-number
verification (post-MVP directory/key-transparency) are the escalation path").

### TM-P9 — Nuisance classes (bounded, non-compromising)

Three griefing vectors are open to a party holding an offer or its bundle:
**offer-burning** — a holder of the bundle alone cannot complete pairing but
can send a bad return, which burns the offer and forces a re-mint;
**first-scan-wins** — a photographer who pairs before the intended
recipient consumes the single-use pairing mailbox, so the intended scan
`404`s (`PairingUnavailable`) and the offerer regenerates; **pairing-inbox
flooding** — deposits to the pairing inbox until it is retired, bounded by
the relay's rate limits, capacity, and TTL. None exposes a message or
impersonates anyone; each self-heals on re-mint. **ACCEPTED.** Records:
`proto/pairing.md §Proof-of-scan` ("an accepted nuisance class");
`proto/pairing.md §Ledgered risks` (offer-burning grief);
`proto/pairing.md §Part IV` ("Accepted nuisance (work order §10.7 / flag
6a)"); bounds venued by the TM-R5 limit tests.

### TM-P10 — Retired offer versions and downgrade

A spec-1.0 acceptor admits `offer_version 0x03` only; `0x01` and `0x02` are
unsupported-version rejections with no compatibility window, so no attacker
can present a timestamp-less v2 offer to evade the validity rule, and no
retired `pair-ack/1` codec exists to be reached. **MITIGATED.** Venues:
`proto/pairing.md §Appendix A`, `proto/pairing.md §Appendix B`;
v3 freeze §7 / V3-D4; Horizon §H7.5;
`tezca-core/src/pairing_v3_acceptance.rs :: r7_v2_fixture_bytes_are_unsupported_version`;
`proto/envelope.md §Frozen component versions` (spec-1.0 receivers accept
exactly the frozen values).

### TM-P11 — Offer cancellation and stale pairing mailboxes

Dismissing the pairing screen does not cancel an outstanding offer: local
invalidation needs a core cancel method that is deliberately not yet FFI
surface, so a dismissed offer stays scannable and single-use until its
embedded window lapses (the UI says so). Separately, the offerer's deletion
of the pairing mailbox at expiry is a SHOULD, best-effort (an offerer
offline at expiry does not run it), so a pairing mailbox can outlive its
offer for up to the relay's 14-day storage bound as a useless deposit target
— useless because the offerer's listener has stopped and every acceptor
rejects the offer before depositing. **RESIDUAL** (cancel) / **ACCEPTED**
(best-effort delete). Records: `docs/acceptance-venues.md` ledgered
follow-up "Pairing-offer cancel (relay-side DELETE)"; Horizon §H7.3
(offerer-side hygiene is a SHOULD); `proto/pairing.md §Relay TTL is a storage bound`;
`proto/pairing.md §Offer lifecycle`. The relay side of the bound:
`tezca-relay/tests/limits.rs :: ttl_expires_messages_and_mailboxes`.

## 6. CROSS-CUTTING

### TM-X1 — Supply chain: dependencies, build, and provenance (INV-6, INV-7)

Every cryptographic primitive is libsignal's or one of the audited TLS
crates; a primitive crate reachable outside its audited wrapper fails CI
(`cargo deny` bans with per-crate wrapper lists; git sources allowed only
from the `signalapp` organization; unknown registries denied); `cargo audit`
runs on every push and PR; every CI cargo invocation is `--locked` and all
lockfiles (Cargo, both fuzz crates, Gradle app and settings) are committed;
toolchains are pinned (`rust-toolchain.toml`, a pinned NDK, a pinned nightly
for fuzzing); release and relay artifacts are built twice and byte-compared;
CycloneDX SBOMs are generated for core, relay, and the APK dependency
closure; tagged builds carry a SLSA-style build-provenance attestation over
the relay binary and the unsigned APK; `unsafe` is forbidden in-source in all
three crates. **MITIGATED.** Venues: INV-6; INV-7; A2;
CI job "Rust — cargo deny + audit (INV-6/INV-7)";
CI job "Reproducible build — double build + diff";
CI job "SBOM — CycloneDX (core, relay, APK deps)";
release.yml job "Build, SBOM, repro report, provenance"
(step "Attest build provenance"); CI job "Rust — fmt, clippy, build, test"
(`--locked`; the
`forbid(unsafe_code)` attributes compile under it — ledger item 23);
`scripts/check-invariants.sh family 1` (SPDX on every file — the license
split A10 is part of the supply-chain posture). The approval process for
extending any wrapper list is documented (`DEVELOPMENT.md`, "What is
enforced by machines, not promises"; the repository's standing rules).
**RESIDUAL:** the primitive deny-list is enumerative — a primitive crate not
on the list would not trip it mechanically and relies on the documented
review (recorded in the 5b-2 matrix, ledger item 24, as a noted boundary,
not a gap); and the release APK leaves CI UNSIGNED by design (signing keys
are external to the repository and CI; the attestation covers the unsigned
artifact), so end-user artifact trust rests on the maintainer's external
signing procedure — 5d-2 scope per the Phase 5 plan of record.

### TM-X2 — Client/relay version lockstep (Horizon §H4.2)

There is no version negotiation: a spec-1.0 receiver accepts exactly the
frozen selector values and rejects every other cleanly, and the relay pins
the outer envelope version at deposit admission (`blob[4] == 0x01`). A
downgrade or version-confusion attack has no surface — there is nothing to
negotiate down to — and an outer-envelope version bump is a coordinated
client-AND-relay deployment; inner evolution (new payload types or
`type_version`s) never requires a relay change. **MITIGATED.** Venues:
`proto/envelope.md §Frozen component versions` (the compatibility promise);
`proto/envelope.md §Versioning and relay coordination`;
`proto/relay-api.md §POST /v1/mailboxes/{id}/messages` (version lockstep);
Horizon §H4.2; `tezca-relay/src/wire.rs :: admission_checks_magic_version_and_length_only`;
`tezca-relay/tests/limits.rs :: deposit_negatives` (version `0x02` ⇒ `400`);
`tezca-core/tests/envelope_spec.rs :: outer_negatives`. **ACCEPTED:** during a
future coordinated bump, clients and relays on different sides of the change
cannot interoperate (availability during transition) — the designed
consequence of lockstep. Record: Horizon §H4.2.

### TM-X3 — Dependency-advisory watch (standing process)

Advisories are caught mechanically at every CI run (`cargo audit`,
`cargo deny` advisories with `yanked = "deny"`), Dependabot proposes grouped
weekly bumps gated by the full CI matrix, and the repository's dependency
rules require libsignal-coupled crates to move only in lockstep with a
libsignal bump and every duplicate-version skip to be pinned and ledgered
with a convergence condition. The response shape is precedented: the h2
advisory RUSTSEC-2026-0258 (published 2026-08-17) was diagnosed the same day
and closed by a lockfile-only bump (ledger item 27); the libsignal
v0.97.2 → v0.99.1 lockstep bump discharged three libcrux advisories
(ledger item 15). **PROCESS (documented; CI-audited).** Venues:
CI job "Rust — cargo deny + audit (INV-6/INV-7)"; `.github/dependabot.yml`;
`DEVELOPMENT.md`. **ACCEPTED:** the watch is reactive — a vulnerability is
mitigated only after its advisory is published and the bump ships; there is
no SLA on that interval (the SLA in `SECURITY.md` governs reports to the
project, not upstream advisories). Record: none ratified — see the register.

### TM-X4 — CI trust: third-party actions

The CI and release workflows reference third-party actions by mutable major
tags (`actions/checkout@v7`, `Swatinem/rust-cache@v2`,
`taiki-e/cache-cargo-install-action@v3`, `gradle/actions/setup-gradle@v6`,
`reactivecircus/android-emulator-runner@v2`, `EmbarkStudios/cargo-deny-action@v2`,
`actions/attest-build-provenance@v4`), not by commit SHA. A compromised
action publisher could therefore alter build inputs, and the provenance
attestation would attest the altered build faithfully. Reproducible builds
give a downstream verifier a way to detect a divergence, but only if they
rebuild. **RESIDUAL.** Record: none — see the register.

### TM-X5 — Development-process provenance

Code is substantially written by an AI coding agent under a human
decision-maker; every commit carries a `Co-Authored-By` trailer; designs are
approved before code, tests precede implementation and their red state is a
committed ancestor of the green, and invariants are enforced by machines
where possible. This is disclosed, not hidden, because a security product's
development provenance is part of its posture (`DEVELOPMENT.md`). Not a
threat entry; recorded so the reader can weigh it.

## 7. Reporting

Suspected vulnerabilities: `security@titlan.chat`, or GitHub Private
Vulnerability Reporting on this repository (`SECURITY.md`; acknowledgement
within 3 business days, assessment within 10, fix or mitigation plan for
confirmed critical issues within 30).

## 8. RESIDUAL / ACCEPTED register

Every entry above marked RESIDUAL or ACCEPTED, with its ratifying record.
Entries whose record column reads **none — needs maintainer words** have no
ratified acceptance text at spec 1.0; they are carried here so the
maintainer can ratify, reject, or assign them at grading.

| ID | surface | verdict | what is accepted / residual | ratifying record |
|---|---|---|---|---|
| TM-C3 | client | RESIDUAL | native-tombstone bound: decrypted content in native/JNI/Kotlin memory with no zeroization guarantee; tombstones and freed pages may hold plaintext; device-compromise class | ledger item 24 (2026-08-13, INV-1 matrix residual → 5b-3) |
| TM-C4 | client | ACCEPTED | AFU posture: the Keystore wrapping key needs no user authentication and is usable while locked (always-on sync); app/root code execution on an AFU-locked device can unwrap the DB key | 4b-1 flag F1 (maintainer-resolved; recorded in `DbKeyManager.kt`, pinned by `androidTest/crypto/DbKeyManagerTest.kt :: wrappingKeyLifecycleMatchesResolvedF1`) |
| TM-C4 | client | ACCEPTED | TTL edge: reboot + never-unlocked ≥ 14 d loses queued inbound messages to the relay idle-mailbox TTL | 4b-2 freeze §2 ("documented, not discovered … stated in threat model + user docs") |
| TM-C7 | client | ACCEPTED | no-exemption Doze posture: no battery-optimization prompt; measured 1271/932/1660 ms under deep Doze; manual whitelisting documented; OS may defer/stop the service beyond what was measured | 4b-2 freeze §9(f) via `docs/checklists/4b2-f-doze-latency.md`; ledger item 9 (PR #20 evidence, 2026-07-28) |
| TM-C7 | client | ACCEPTED | no per-message notifications at spec 1.0 (messages appear on open) | 4b-2 freeze §7 (deferral ledgered as its own post-MVP design gate) |
| TM-C8 | client | RESIDUAL | no bounded timeouts on relay HTTP/WS operations | `docs/acceptance-venues.md` follow-up "Bounded network-I/O timeouts" (recorded 2026-07-28) |
| TM-C9 | client | RESIDUAL | INV-5 receive path: per-conversation relay governs send only; receive stays on the engine-global relay | `docs/acceptance-venues.md` follow-up "INV-5 gap on the receive path" (recorded 2026-07-21) |
| TM-C10 | client | ACCEPTED | device-compromise class (root, OS, hardware, physical memory) is outside every mitigation | A4 and INV-1's scope (at rest; logs/crash/debug) — the model's boundary |
| TM-R2 | relay | ACCEPTED | metadata exposure to the relay/network: mailbox ids, deposit/delivery timing and their correlation, bucketed sizes (≈ 1.6-bit length channel), source IPs, presence, identity public key in session-setup blobs; no cover traffic, jitter, mixing, or anonymity-network integration | A6; A8 + `proto/envelope.md §Padding buckets and profiles`; `proto/pairing.md §Privacy note` ("Accepted for MVP"); plan of record "sealed-sender metadata bounds" (ledger item 22) |
| TM-R3 | relay | RESIDUAL | deployment-dependent: `mlockall` best-effort, silent on `EPERM`; without the shipped unit's memlock grant / `MemorySwapMax=0`, mailbox memory may swap | `proto/relay-api.md §Invariants realized here`; `deploy/tezca-relay.service` |
| TM-R4 | relay | ACCEPTED | restart loses deposited-but-unfetched blobs silently (no e2e receipt at 1.0); re-pair-only cases: total loss before the handoff lands; root-less conversations; recovery blocked at the global cap | INV-3; `proto/inner-frame.md §Derived recovery-mailbox IDs` (frozen §8); `proto/recovery.md §6. Conversations without a recovery root`; `proto/relay-api.md §PUT /v1/mailboxes/{id}`; 4b-2 freeze §8 |
| TM-R5 | relay | RESIDUAL | volumetric / transport-layer DoS has no in-protocol defense (deployment concern) | **none — needs maintainer words** |
| TM-R5 | relay | ACCEPTED | IP-keyed limiter shape: NAT populations share budgets; multi-address adversaries multiply theirs; a distributed adversary can fill the global mailbox cap (uniform `503`) | work order §10.2 relay-defaults resolution (2026-07-14, "All config; defaults only"); `proto/relay-api.md §PUT /v1/mailboxes/{id}` (recovery-blocked-at-cap) |
| TM-R6 | relay | ACCEPTED | certificate-pinning posture: designed in core (per-conversation `relay_pin`), not reachable from FFI/UI; release builds run on platform trust roots; SPKI pinning not built; relay cert rotation by restart only | work order §6 Phase 4 ("optional-but-designed"); plan of record "certificate-pinning posture" (ledger item 22); ledger item 24 (5d-2 row); `proto/relay-api.md §Resolved and open items` |
| TM-R7 | relay | RESIDUAL | a malicious relay can drop, delay, withhold, or ack-delete traffic undetectably (availability); no receipt, no second path, no attestation | **none — needs maintainer words** (the trust model states honest-but-curious reliance for availability) |
| TM-R8 | relay | RESIDUAL | post-compromise: mailbox ids learned on the host stay valid until pairing/recovery rotation; no suspected-compromise rotation trigger; unit directives beyond the content-asserted six are syntax-verified only | **none — needs maintainer words** |
| TM-P1 | pairing | ACCEPTED | complete-offer compromise: a holder of the entire offer can pair as the responder within the window; not an MITM defense | `proto/pairing.md §Ledgered risks`; v3 freeze §3; 4b-2 freeze §3, §10 |
| TM-P2 | pairing | ACCEPTED | scheme squatting: the app registers no `titlan://` handler; any app claiming the scheme receives tapped links; link path documented as weaker, QR recommended | `proto/pairing.md §Ledgered risks`; 4b-2 freeze §3, §10 |
| TM-P2 | pairing | ACCEPTED | `https://` fragment in browser history (App Links, not yet landed); a static landing page must never read the fragment; v3 bounds it in time | `proto/pairing.md §Ledgered risks`; 4b-2 freeze §4 |
| TM-P3 | pairing | ACCEPTED | clock dependence of offer validity (offerer/acceptor clocks; 300 s grace); wrong clocks make offers unusable, surfaced with a clock hint | v3 freeze §4 / V3-D2 (2026-08-10) |
| TM-P5 | pairing | ACCEPTED | `recovery-hello` dedup ring is in-memory (a post-restart redelivery is reprocessed once, idempotently) and bounded at 512 pairs, oldest-evicted | ledger item 28 (F2 amendment, 2026-08-24); `proto/inner-frame.md §Verified receipt and replay dedup` |
| TM-P6 | pairing | ACCEPTED | derived ids are forever computable from persisted client state; a seized unlocked device yields the future routing-id sequence until rotation retires the derived mailboxes | 4b-2 freeze §8 (rotation justification); `proto/recovery.md §4. Convergence` |
| TM-P8 | pairing | RESIDUAL | TOFU without safety numbers, key-change events, directory, or transparency log; a wrong-party pairing is detectable only out of band | A7; `proto/pairing.md §Part I`; `proto/pairing.md §Ledgered risks` |
| TM-P9 | pairing | ACCEPTED | nuisance classes: offer-burning grief; first-scan-wins; pairing-inbox flooding within relay bounds | `proto/pairing.md §Proof-of-scan`; `proto/pairing.md §Ledgered risks`; `proto/pairing.md §Part IV` (work order §10.7 / flag 6a) |
| TM-P11 | pairing | RESIDUAL | no offer cancel: a dismissed offer stays live until its window lapses | `docs/acceptance-venues.md` follow-up "Pairing-offer cancel (relay-side DELETE)" (2026-07-21) |
| TM-P11 | pairing | ACCEPTED | offerer-side pairing-mailbox delete at expiry is SHOULD/best-effort; a stale pairing mailbox may persist ≤ 14 d as a useless deposit target | Horizon §H7.3; `proto/pairing.md §Relay TTL is a storage bound` |
| TM-X1 | cross | RESIDUAL | enumerative primitive deny-list (unlisted primitive crates rely on documented review); release APK unsigned in CI, artifact trust rests on the external signing procedure | ledger item 24 (5b-2 matrix INV-6 boundary note); Phase 5 plan of record (5d-2 scope) |
| TM-X2 | cross | ACCEPTED | lockstep transition: clients and relays across a future outer-version bump cannot interoperate during rollout | Horizon §H4.2 |
| TM-X3 | cross | ACCEPTED | advisory watch is reactive with no SLA on publication-to-bump interval | **none — needs maintainer words** |
| TM-X4 | cross | RESIDUAL | third-party GitHub Actions referenced by mutable major tags, not commit SHAs | **none — needs maintainer words** |

Entries with a record are re-ratified by the maintainer at this document's
grading; entries marked **none — needs maintainer words** are the open
items of this threat model at spec 1.0.
