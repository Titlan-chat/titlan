<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Conversation UI (5e-1) Design Freeze — ratified 2026-09-27

Status: **FROZEN.** Maintainer ratification 2026-09-27, one verdict of record:
"package as recommended" (ratifies every recommendation of the reviewer's
working document r1, `p5-5e1-conversation-ui-gate.md`, sha256
`f1307fa6bbee9b86c49d22485e3efc85757a1b419aab33d1f22c9657d7116321`). This
document is the decision record for the unit named at the release-candidate
gate as Stage 2 (RC-D0): `5e-1 conversation UI`, the Phase 4 scope item "1:1
conversation list and chat screen" that the Phase 5 plan of record never
scheduled. Deviations require a governed amendment. Hash-chained predecessor:
`docs/design/2026-09-release-candidate-freeze.md`, whole-file sha256
`6d817c2f80276865e4f0df5b685b7aaa87cde6cac570b70fa04924fb3b41ff07`.
Base of the findings: titlan `main` `b87880190fc997e3e792a2fc1d742e7ddeb5a03e`
(`v0.1.0-rc.2`). Every `file:line` below is at that commit.

## CU-D0 — Scope (FROZEN)

- In: conversation list; chat screen (text only); in-app navigation; the
  offerer completion signal; post-pairing navigation for both roles; the UI
  sync sink; FLAG-2 copy normalization; INV-1 extensions for chat text;
  check-invariants family 20; release-checklist §0/§8 message-exchange
  amendments; this freeze; acceptance-venues annotations.
- Out, each with its venue: the `v0.1.0` release identity (tag, `versionName`,
  `versionCode`, release notes, checklist §7 wording, site/SECURITY wording
  under RC-D8) — successor unit `5e-2 v0.1.0 release`. The per-conversation
  relay setting of work order §5 item 3 — deferred to the INV-5 receive-path
  unit (there is no FFI read of a conversation's relay, and repointing only the
  send side cannot be offered honestly); `v0.1.0` ships with the relay chosen
  at pairing and not shown. Conversation labels (schema v4 + FFI) — successor.
  Message timestamps and delivery state in the UI — successor with P6 receipts
  (a relay-accepted tick would read as delivered). Per-message notifications
  (own future gate). Offer cancel FFI (F3). The post-unlock sync-restart
  receiver (frozen 4b-2 §2 item). PD-D2 offer compaction. RC-D1(b). The F-H and
  F-I core fixes (below).

## CU-D1 — Containment: zero core, zero new dependency (FROZEN)

- No change under `tezca-core/`, `tezca-relay/`, `proto/`, `uniffi-bindgen/`;
  `Cargo.lock`, `titlan-android/gradle.lockfile`,
  `titlan-android/gradle/libs.versions.toml` and the `dependencies {}` block of
  `titlan-android/app/build.gradle.kts` stay byte-identical to the base
  commit. The one FFI method not yet wrapped, `messages`, is wrapped in
  `CoreClient.kt` (Kotlin facade only; no new FFI surface).
- The relay binary therefore stays
  `4e91ee9d7e7efd58c320238996a9bdcb82a7c440400852897dc0021a6646ae1e` across
  this unit; `5e-2`'s droplet redeploy is skippable by the checklist's rule.
- No experimental-API opt-ins; no lint allow or suppression of any kind.

## CU-D2 — Navigation: one Activity, state-driven (FROZEN)

- `MainActivity` remains the single Activity (TM-C5's central `FLAG_SECURE`
  enforcement keeps its coverage). Destinations `Conversations`, `Chat(key)`,
  `Pairing`, held as a `sealed interface Screen` in Compose state;
  `BackHandler` from `activity-compose`. Start destination: `Conversations`
  when the store holds at least one conversation, else `Pairing`. Back: `Chat`
  → `Conversations`; `Pairing` → `Conversations` when one exists, else the
  Activity finishes.
- The only navigation state that may survive process death is a conversation
  key's hex. No message text, draft or offer bytes is ever saved.

## CU-D3 — `ConversationStore`: the one UI sink (FROZEN)

- A process-wide object that implements `SyncEvents` and is the only source
  Compose reads: the conversation list, per-conversation connection state,
  needs-repair set, not-delivered message set, the storage-error flag, and a
  per-conversation message list. Keys are hex strings (`ConversationKey`),
  never `ByteArray`.
- Callback rule: every `SyncEvents` method returns immediately after updating
  in-memory state or posting work to an IO dispatcher; no method calls core on
  the callback thread, and `startSync`/`stopSync` are never invoked from a
  callback. Reason of record: core clones the callback out of a `Mutex` inside
  an `if let` scrutinee (`tezca-core/src/relay_client/mod.rs:124-128`,
  `:497-499`) and, under edition 2024, that guard is held while the Kotlin
  callback runs; `set_callbacks` (`:115-122`) locks the same mutexes.
- The event carries ids only (frozen 4b-2 §1); bodies are re-read from the
  store by conversation id on IO. Refresh triggers: `onMessageArrived` →
  that conversation's messages; any event naming a key not in the current list
  → the conversation list; Activity `ON_START` → the list and the open
  conversation. All core reads off the main thread.

## CU-D4 — Offerer completion signal (FROZEN)

- Store poll: on mint the pre-mint set of conversation keys is captured; while
  the offer is Active, `listConversations()` is read on IO every 2 s and the
  first key not in that set is the paired conversation → sync starts with the
  UI sink → `Chat(key)`. Bounded by the offer TTL. The signal means
  "proof-of-scan verified and the conversation created"
  (`relay_client/mod.rs:326-339`), which precedes the handoff deposit by one
  round trip.
- A core `on_conversation_established` callback is the named successor and
  rides the PD-D2 pairing gate; it is not added here (new FFI surface; the F3
  precedent).

## CU-D5 — Post-pairing navigation, both roles (FROZEN)

- Responder: on `acceptScannedOffer` success the list is refreshed, sync starts
  with the UI sink, and the app navigates to `Chat(key)`. The
  `Paired — conversation established (…-byte id)` status line is retired as a
  screen. Offerer: the same after CU-D4.
- Evidence continuity: the chat screen's empty state (zero messages, either
  role) is the resource `chat_empty_paired`, whose text begins with the exact
  literal `Paired — conversation established`, so the device checklists' reads
  keep matching.

## CU-D6 — Chat screen (FROZEN)

- Header: conversation label and connection chip. Body: messages in store
  order, outgoing right, incoming left, text only. Composer: text field + Send.
- Decoding: `payloadType == 0x01 && typeVersion == 1` → strict UTF-8; malformed
  → `chat_message_undecodable`; any other type/version → `chat_message_unsupported`
  with the body never decoded.
- Send: disabled when the trimmed text is blank or its UTF-8 length exceeds
  `MAX_CHAT_UTF8_BYTES = 8186` (single site `conversation/ChatLimits.kt`,
  pinned to `proto/envelope.md`'s "Maximum payload under the default profile:
  8186 bytes" by a plain-JVM test and family 20c). This is the in-unit
  mitigation of finding F-H.
- No timestamps, no delivery ticks. `onPermanentSendFailure` marks the row
  `chat_message_not_delivered` for the process lifetime. `onStorageError` shows
  the fixed `chat_storage_error` banner; the detail string is never rendered or
  logged.
- Connection chip: the five `ConnectionState` values map to five resources; no
  chip until the first event for that conversation. `onConversationNeedsRepair`
  → persistent `chat_needs_repair` banner with `chat_pair_again` → `Pairing`.
- The composer draft is `remember`, never `rememberSaveable`.

## CU-D7 — Conversation list (FROZEN)

- Rows in `listConversations()` order (most recent first); label
  `conversations_row_label` with the first 8 hex characters of the key; the
  connection chip; tap → `Chat(key)`; `conversations_pair_device` → `Pairing`.
  No last-message preview.

## CU-D8 — Sync lifecycle wiring (FROZEN)

- `MainActivity.onCreate` starts sync with the UI sink when a paired
  conversation exists, replacing the no-observer launch-time form;
  `SyncController.start(context)` and `DefaultSyncEvents` remain for
  START_STICKY revival only. After any pairing completion the same call runs.
  No UI stop. INV-5 untouched.

## CU-D9 — FLAG-2 discharged: one convention, string resources (FROZEN)

- Every user-visible string lives in `res/values/strings.xml`; Kotlin holds no
  user-facing literal. Migrated: the twelve `PairingScreen.kt` literals, the
  five `PairingFailure` strings (now `userMessageRes(cls): Int` resolved at the
  call sites), and `SyncService.NOTIFICATION_TEXT` (value verbatim
  `Titlan sync active`). `pairing_failure_expired` carries the pair-offer v3
  freeze §5 wording verbatim. Strings containing an apostrophe use the
  double-quoted resource form. Payoff: family 3's A11 sweep now covers all
  copy.
- The wording was drafted in the work order and ratified by its dispatch; the
  resource names are normative.

## CU-D10 — INV-1 extensions for chat text (FROZEN)

- `ChatLogcatHygieneTest` and `ChatAtRestTest` (instrumented) prove a sent and
  a received canary never reach logcat or app-accessible storage in raw, hex
  or Base64 form. Family 20b pins the app layer's logcat surface to the two
  pinned emitter files; family 20d pins `rememberSaveable` absent from the two
  screens that hold message or offer text.

## CU-D11 — Red families and static gates (FROZEN)

- Plain-JVM: `ChatBodyDecodingTest`, `CopyConventionTest`, `PairingFailureTest`
  (rewritten to the resource-id shape). Instrumented: `ConversationStoreTest`,
  `OffererCompletionTest`, `PairingStartsSyncTest`, `ChatLogcatHygieneTest`,
  `ChatAtRestTest`. RED lands the tests with compile-only stubs whose bodies
  throw `NotImplementedError`, so every red fails at its first production call
  or intended assertion, never at plumbing.
- `scripts/check-invariants.sh` family 20 "Conversation UI (5e-1)": 20a copy
  convention, 20b stray-log sweep, 20c chat cap, 20d no saved plaintext, 20e
  evidence literals in `strings.xml` and in checklist §0 and §8, 20f this
  freeze present, Apache-2.0, hash-chained. Containment (20g) is asserted by
  the unit's order against the base commit.

## CU-D12 — Dynamic proof on devices (FROZEN)

- Release-checklist §0 and §8 gain, after the two pairing directions, the
  blocks **Message exchange (5e-1)** and **Airplane-mode round trip (5e-1)**
  with fixed typed literals and a logcat hygiene gate on both devices. The
  unit's own device run executes §0 on the merged head, throwaway-signed, on
  Pixel 9 `54030DLAQ000DX` and the AOSP emulator Titlan-A.

## CU-D13 — Documents (FROZEN)

- This freeze; `docs/acceptance-venues.md` annotations ("Blank post-pairing
  screen", "Link-paste field usability", "Swallowed peek failure" RESOLVED);
  `docs/threat-model.md` TM-C1/TM-C2 venue additions (two sentences, register
  unchanged); one `docs/user-notes.md` note; source comments that describe the
  UI as "4b-3" renamed to 5e-1; `docs/release-checklist.md` per CU-D12.
  README, site and SECURITY.md untouched (5e-2).

## CU-D14 — Riders (FROZEN)

- R-1 taken: a `peekOfferRelay` failure surfaces its 5a-2-classified copy
  (MALFORMED for a structurally invalid offer, INTERNAL for a device-local
  fault) and re-arms the scanner instead of proceeding to establish.
- R-2: `OfferLifecycle` carries hex keys. R-3: the pre-mint key set is captured
  by the screen at mint.

## Findings of record

- **F-H (core, latent):** `send_chat` persists an outgoing frame as pending
  before any size check (`relay_client/mod.rs:426-431`); `flush_pending` aborts
  its loop at the first frame `InnerFrame::encode` rejects (`:452-455`;
  `envelope/inner.rs:80-86`), so one oversized text blocks every later message
  in that conversation. Mitigated at the composer here; core fix is a named
  successor (encode-or-reject before `save_outgoing`; skip-and-surface in the
  flush loop).
- **F-I (core, latent edge):** the offerer's conversation row is created
  (`relay_client/mod.rs:334-339`) and the pairing inbox deleted (`:351`) before
  the handoff deposit (`:360`); a failed deposit leaves a conversation whose
  peer never learned the offerer's inbox. Successor with PD-D2.

## Sequencing (FROZEN)

1. This freeze and the RED commit (tests, stubs, family 20, ratified
   `strings.xml`) land together; the maintainer pushes the branch so CI records
   the red signatures; GREEN and RIDER follow in the same PR.
2. Merge; the unit's device run (CU-D12) on the merged head; ledger item 40.
3. Successor gate `5e-2 v0.1.0 release`.

## Amendments

(none)
