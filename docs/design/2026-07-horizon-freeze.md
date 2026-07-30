<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Protocol Horizon — Design Freeze

**Gate:** work-order §10 item 11 (agenda a–f) with §10 item 12 absorbed by maintainer ratification.
**Serves:** the §6 Phase-5 PRECONDITION. Phase 5 opens when this document is ratified and committed.

**RATIFICATION BLOCK**
- Status: `RATIFIED` — the decision set was ratified by the maintainer on 2026-07-30 ("I Approve all the recommendations", following the reviewer's enumerated recommendation set of the same day).
- Ratified text: 2026-07-30 — "Freeze text ratified as written" — the maintainer (Danny Martinez).
- Predecessor freeze document: `4b2-design-frozen.md`, sha256 `6b79fb39c90acabb4f3464c6d8037de1f4165961602c8bdcd34101dfa638b631`
- Evidence anchors: headroom audit report body-sha256 `60fd6720b4b0c8a40860d204629ad160bc619aad7e2a3432958807eb645d8b5d` (2026-07-30); gate working document r1 sha256 `74f8aca3a84cb5e863ec56aa5e736f21caa5d4c59441865ecc5e52e5cca70928`; repository main at gate = `19586f3a2b0da1b64f3bbf9777c4083872ad7342`.
- Authorship: reviewer instance (assembly); maintainer (all decisions). Hash-chain convention per §H8.

Frozen decisions are not open for revision by implementation work. Anything below found technically infeasible is flagged to the maintainer, never silently substituted.

---

## H1 — Payload-type registry additions and unknown-type handling

1. Three payload types are reserved, name and numeric ID only, semantics unspecified:
   `0x08` = `receipt` · `0x09` = `control` · `0x0A` = `attachment-pointer`.
   Each is reserved at type_version 1. Implementations MUST treat these as recognized-but-unsupported until a later design freeze specifies semantics; reserving an ID commits nothing about its eventual v1 semantics.
2. The existing private/experimental range `0x80–0xFF` (proto/envelope.md) stands unchanged. `0x0B–0x7F` remain unassigned and registry-controlled.
3. Registry policy: payload-type IDs are assigned only in the published envelope spec, by the maintainer. Per-function type assignment (the `pair-ack` / `mailbox-update` / `recovery-hello` precedent) remains the preferred pattern; the generic `control` reservation is an escape hatch, not a commitment to multiplexing.
4. Unknown/unsupported handling is NORMATIVE: a client that fetches a frame whose payload type or type_version it does not implement acks and discards it — no user-visible error, no redelivery loop, and nothing logged that pairs the type with conversation identifiers. This elevates the existing spec text (envelope.md "ack-and-drop") and the implemented listener behavior to a normative rule. The ack-after-persist guarantee applies only to accepted chat messages, unchanged. A test pinning ack-and-discard on a live inbox is an obligation of the fallout order (18b).

## H2 — Identity is a device-set (v1 set-size 1)

1. Definition (spec-level): **an identity is a set of one or more devices** sharing a pairing context. Protocol v1 fixes the set size at exactly one; the device carried in the pairing bundle is the sole member. The v1 collapse of identity ↔ identity-key ↔ address ↔ device into a 1:1:1:1 relationship is a *property of v1*, not part of the definition. This wording deliberately precludes neither a root-key/cross-signed device model nor alternatives; the device model is P7 design-freeze scope.
2. v1 conformance rule (ratified fix shape for the audited defect Q7-1): the pairing bundle's `device_id` field MUST equal 1 in v1. Parsers MUST reject any other value as Malformed. The u32 wire field remains as headroom; a later protocol version relaxes the rule. Implementation is a fallout-order obligation (A2); the normative sentence lands in proto/pairing.md (A1).
3. Headroom verdict, ratified on audit evidence: the wire layer is migration-clean — every Titlan-defined struct is version-led with tested unknown-version rejection; the pairing bundle already carries `device_id: u32`; sender identity is derived, never parsed (nothing to version); the derived-mailbox PRF label is version-suffixed (`…-v1`), so any future device-bearing derivation is a label bump producing disjoint IDs by construction.
4. Storage caveats, recorded: two tables would require SQLite table-rebuild migrations *if* P7's design demands them — `identities` (PK widening, only if trust becomes per-(address, device)) and `local_identity` (CHECK relaxation, only if the local row-set becomes plural). Both are data-preserving, in-place migrations executed inside the existing versioned migration mechanism; this document records that reading as satisfying the "migration, not rebuild" obligation — no flag-day, no data loss. No preemptive key-widening is performed: choosing a key shape now would presuppose P7's trust model.

## H3 — Group model (direction ratified; mechanism deferred to P10)

1. **MLS is rejected** for this architecture. MLS presumes ordered, consistent group state — epochs advanced by commits every member observes in a common order. The Titlan relay is a blind, unordered, at-most-once mailbox with no server-side state and must remain so (INV-2/INV-3/INV-8); epoch agreement would have to be rebuilt client-side over unordered, lossy channels, at which point MLS's efficiency advantages collapse while its complexity remains. The genuinely hard problem on this substrate — membership consistency without any directory — is not solved by MLS; it is presupposed by it.
2. **Direction:** per-sender symmetric ratchets ("sender keys"). Each sender generates a group-scoped sender key (with signing key), distributes and rotates it to members over the existing pairwise Double Ratchet sessions via reserved control-plane payload types; a group message is encrypted once under the sender key and deposited client-side into each member's mailbox (N deposits). The relay remains completely group-unaware.
3. **Explicitly unresolved, deferred to the P10 design freeze:** membership authority (admin-signed member lists over the control plane is the leading candidate), sender-key rotation policy on member removal, and fanout-metadata mitigation. Known cost recorded now: client-side fanout exposes N temporally clustered deposits from one source — group size/topology leakage; mitigations (jitter, decoys) are P10 scope.
4. Nothing in this section is normative for third-party implementation; the published spec carries it as informative "future directions" only.

## H4 — Platform invariant INV-8 and the envelope-version coordination fact

1. **INV-8 (adopted):** *The relay never acquires group, blob, directory, or any payload-semantic awareness. Any future feature that requires server-side semantics gets its own service with its own invariant ledger.* This invariant joins INV-1..7 with equal force; a change violating it is a defect, not a tradeoff.
2. Coordination fact (audit 18f), stated for the spec's versioning section: the relay pins the outer envelope version at deposit admission (`blob[4] == 0x01`). An outer-envelope version bump is therefore a client-and-relay lockstep change, never client-only. Relay WebSocket delivery/ack frames carry no version byte; their evolution hook is the `/v1/` URL prefix.

## H5 — `tezca-blob`: existence and invariant ledger (protocol at P11)

Attachments never transit the relay; a separate, disk-persistent blob service (`tezca-blob`) is the designated home, specified at the P11 design freeze. Its invariant ledger is frozen now:

- **B1** — blobs are end-to-end encrypted client-side before upload; keys travel only inside E2EE envelopes (`attachment-pointer`); the blob service can never decrypt. Cipher choice at P11 under INV-6 (libsignal/audited crates only).
- **B2** — capability addressing: unguessable blob ID; possession of the pointer (ID + key) is the only access path; no accounts, no directory (A1/A7 preserved).
- **B3** — persistence permitted but bounded: TTL mandatory; optional delete-after-N-fetches; no content inspection or indexing ever; server-side at-rest encryption is defense-in-depth only, never a substitute for B1.
- **B4** — metadata minimum: no linkage of blobs to identities, conversations, or mailboxes; per-source rate limiting in the relay's style.
- **B5** — the blob-service address is per-conversation/team configuration behind a single default constant; self-hostable single binary (INV-5 analog).
- **B6** — the relay never proxies, caches, or references blobs (special case of INV-8).

The published v1 spec states: attachments are out of scope; the pointer type is reserved; the blob service above is the designated future home (informative).

## H6 — Org control plane: shape and invariant boundary

1. **Shape (ratified):** org-scoped relay + admin-issued pairing offers + client-side attestation. Org onboarding is an offer-management workflow (pairing is the only introduction mechanism); org deployment is relay-address configuration (INV-5); deprovisioning is admission control at the org's own relay boundary.
2. **Invariant boundary (ratified, load-bearing):**
   (i) the consumer/global network is unchanged — no accounts, no directory; A1/A7 intact;
   (ii) INV-2 content/sender blindness is unconditional for every relay, org relays included;
   (iii) org control lives entirely at the org boundary — credential issuance client-side, admission checks org-relay-side — and never requires identity disclosure to the platform operator, the public relay, or the wire protocol at large;
   (iv) one client binary — org behavior is configuration- and credential-driven, never a fork; the single-brand rule (A11) extends to it.
3. **Reserved wire hook:** an optional, opaque admission-credential field on relay operations (connect / create / deposit). Carrier (header vs body field) follows the relay protocol's existing conventions at implementation time; the field is additive and default-absent; the public relay never requires it.
4. Credential cryptography (unlinkable blind-signature tokens vs per-device pseudonymous credentials, or both org-configurable) and fleet visibility tooling are deferred to the fleet-module design freeze. The adjacency between admission credentials and the existing licensing-trait seam is noted, not designed.

## H7 — Offer lifetime (absorbed §10 item 12)

1. **One governing value:** an offer's validity is its own embedded `issued_at` + `ttl` (default 1 hour — the ratified 4b-2 display value), carried inside the authenticated offer content.
2. **Acceptor-side enforcement is normative:** an acceptor MUST reject an expired offer, with a distinct, truthful error — "offer expired" becomes its own observable signal (this also pays down the ledgered 4b-3 unified-dialog defect).
3. **Offerer-side hygiene (SHOULD):** delete the pairing mailbox at offer expiry via the existing oracle-free DELETE. The deposit-harness wait fuse aligns to the offer TTL. The UI countdown displays the embedded TTL.
4. The relay gains no pairing-mailbox class and no offer awareness (INV-8). The 14-day relay TTL is a storage bound, not an offer-validity bound; the published spec states this explicitly.
5. Implementation consequence, recorded: pair-offer v2 carries no timestamp fields, so this freeze directs **pair-offer v3** (v2 + `issued_at` + `ttl`, authenticated, version-led like all pairing structs). v2 is retired before spec publication — there is no deployed user population beyond the maintainer's own devices — and the published spec carries v3 only. Implementation follows the red/green discipline in Phase-5 hardening.

## H8 — Freeze-document placement and hash chain

1. Ratified design-freeze documents are tracked in this repository under `docs/design/`, are public, and carry: a RATIFICATION BLOCK with the maintainer's ratification words and date verbatim, and the sha256 of the predecessor freeze document (hash chain). The phase-precondition tripwire checks ratification from the repository itself.
2. This document lands as `docs/design/2026-07-horizon-freeze.md` upon text ratification, after which the §6 Phase-5 PRECONDITION is satisfied.
3. Predecessor `4b2-design-frozen.md` is committed retroactively to `docs/design/` after a content scrub review; if the scrub finds non-publishable content it remains in the maintainer's private governance home and is referenced here by hash only. (Non-technical governance artifacts are out of scope for this repository by standing rule; their placement is recorded in the maintainer's private ledger.)

---

*End of frozen content. P6–P11 remain DISCUSSION-STATE per docs/roadmap-post-mvp.md; every phase requires its own design freeze → red → green cycle. Invariants INV-1..8 and locked decisions A1–A11 are not open for revision by this or any roadmap document.*
