<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Release-Candidate (5d-2) Design Freeze — ratified 2026-09-10

Status: **FROZEN.** Maintainer ratification 2026-09-10, one verdict of
record: "approved" (Horizon-precedent form; ratifies the recommendation set
of the reviewer's working document r3, sha256
`017e3b8b42dfa81d70aa18ca730f8df0e52979770a7168155657fc1a2ac0b1f2`). Text
r2 of 2026-09-11 supersedes the 2026-09-10 text (companion sha256
`f170e60018739ee318f456f599645ae5e41d83a3d447f35564b136c8ed1627c5`) before
commit: RC-D4 no longer repeats the applicationId literal, which
check-invariants family 2 forbids outside its single-source file; no
decision changed. This document is the decision record for the release-candidate unit — plan of
record 5d-2, "release build pipeline" — and deviations require a governed
amendment. Hash-chained predecessor: `docs/design/p5d-release-freeze.md`,
sha256 `3fcce2e496771b77954242bdd146323fc8dc82cfe7a590260d1363a528678689`.
Base of the findings: titlan `main` `0ea1f505b61f1e9715eb1b4a0bbc18839aa65694`.

## RC-D0 — Two-stage release (FROZEN)

- Stage 1 = this unit (5d-2): pin the default relay, author and execute the
  release checklist end to end on tag `v0.1.0-rc.1`, published on GitHub
  Releases marked **pre-release / not supported**. This discharges the work
  order §6 Phase 5 acceptance "release checklist executed end-to-end once".
- Stage 2 = a NEW named unit, working name **5e-1 conversation UI** (the
  Phase 4 scope item "1:1 conversation list and chat screen" that never
  landed and that the Phase 5 plan of record never scheduled — verified by
  maintainer grep 2026-09-10, zero hits). It requires its own design gate,
  red, green. `v0.1.0` proper ships only after it, against work order §9.
- No supported release exists until Stage 2; the site and SECURITY.md say so
  (RC-D8).

## RC-D1 — The INV-5 constant (FROZEN)

- Value: `wss://relay.titlan.chat`. Form: origin only — scheme and host, no
  path, no port (443 implied). The relay client appends the `/v1/` API
  prefix itself; a trailing `/v1` on the constant is a defect.
- Single-sourcing: option (a) — both existing sites flip
  (`tezca-core/src/config.rs` `DEFAULT_RELAY_URL`; `titlan-android/app/build.gradle.kts`
  `defaultConfig` `RELAY_URL`), and `scripts/check-invariants.sh` family 7
  is rewritten to assert (i) the production literal, (ii) equality between
  the two sites, (iii) no path component. Option (b) — the Android side
  reading the default from core over UniFFI — is a queued post-RC chore.
- `TEST_LOOPBACK_RELAY_URL` and the debug `titlanDebugRelayUrl` override are
  untouched.

## RC-D2 — Publication (FROZEN)

- Maintainer-by-hand for the first cycle: download the `release.yml`
  workflow artifact, verify (RC-D6), sign (RC-D3), then
  `gh release create v0.1.0-rc.1 --prerelease --verify-tag` uploading the
  signed APK, the unsigned APK, the three CycloneDX SBOMs, `repro-report.txt`,
  `SHA256SUMS`, and the attestation bundle. `release.yml` keeps
  `contents: read`; no permission widening on a tag-triggered workflow.
- CI-created draft Releases are a titlan-ops successor, after one by-hand
  cycle has run.

## RC-D3 — Signed-APK verification chain (FROZEN)

- Signing: `apksigner sign --ks ~/keys/titlan-release.p12 --ks-key-alias
  titlan-release --v1-signing-enabled false --v2-signing-enabled true
  --v3-signing-enabled true --v4-signing-enabled false --min-sdk-version 34`,
  on the titlan-dev VM, maintainer's hands only; key material never enters a
  repository, agent session, report, or evidence log.
- v1 (JAR) signing OFF is a decision: with v2/v3 only, every zip entry of
  the signed APK is byte-identical to the attested unsigned APK, so
  `scripts/repro-build.sh --diff-apks <unsigned> <signed>` reporting zero
  differing entries is the proof that links the published file to the
  provenance attestation.
- Both files publish: `titlan-<tag>.apk` (signed) and
  `titlan-<tag>-unsigned.apk` (the attestation subject). The verification
  page gains the linkage step: `gh attestation verify
  titlan-<tag>-unsigned.apk --repo Titlan-chat/titlan`, then the entry diff,
  then `apksigner verify --print-certs` against the D4 digest.

## RC-D4 — Release identity (FROZEN)

- Tag `v0.1.0-rc.1`, annotated (`git tag -a`), created by the maintainer on
  `main` after the RC branch merges. Signed tags are a named-open item (no
  maintainer GPG identity exists).
- `versionName` `0.1.0-rc.1`; `versionCode` `1`, monotonic — every tag
  increments it.
- The `applicationId` — the value single-sourced as `TITLAN_APPLICATION_ID`
  in `titlan-android/gradle.properties` (the literal is not repeated here:
  check-invariants family 2 forbids it outside that file) — is **FINAL**.
  Work order §10.4's condition (domain secured) is met by `titlan.chat`; the
  first signed install is the first permanent-identity event. §10.4 is
  words-amended in the ledger at this ratification.

## RC-D5 — Relay container image (FROZEN)

- Deferred to titlan-ops. No image is built or published by this unit; the
  Release entry publishes the attested relay binary.
- `deploy/README.md` is amended so its one-liner builds locally from
  `deploy/Dockerfile`; the unpublished `ghcr.io/titlan-chat/titlan-relay:v0.2.0`
  reference is removed.
- Droplet: the tagged relay binary is redeployed post-release (checklist
  step) so the served relay equals the published binary; the INV-3 mailbox
  flush at restart is acceptable. Skippable only if the tag's binary hash
  equals the running `86013b9956f302b1fbd33e5d364e94a2cc849dc08abf2097ee6e0494c4d461ac`.

## RC-D6 — Release checklist (FROZEN)

- New document `docs/release-checklist.md`, Apache-2.0 (checklist class),
  WHERE-labelled (`CI` / `VM titlan-dev` / `Windows` / `droplet` / `GitHub`),
  value-checked gates. Sections: (1) pre-tag — post-merge `main` green,
  ledger current and mount-verified, deny/audit clean, docs-rider bundle
  merged, site script-free; (2) tag ceremony; (3) `release.yml` run to
  success, artifact downloaded, `SHA256SUMS` checked; (4) `gh attestation
  verify` on both subjects; (5) independent rebuild on the VM at the tag,
  hashes equal `repro-report.txt`; (6) signing per RC-D3; (7) publication
  per RC-D2; (8) production-relay acceptance — two GrapheneOS devices, fresh
  installs of the SIGNED APK, pair by QR over `relay.titlan.chat`, both
  reach the pairing-complete state; the 5e anchor-string scan run against
  the `.so` extracted from the signed APK; (9) post-publish — site status
  (RC-D8), SECURITY.md wording, droplet redeploy (RC-D5), ledger entry.
- A content-assert test pins the checklist's gate literals (signing flags,
  tag form, verify commands) so document and tooling cannot drift.

## RC-D7 — Release TLS trust; the item-24 "5d-2-scoped" row (FROZEN)

- Release trust is `rustls-platform-verifier` plus Let's Encrypt, as built;
  the test-anchor path is compiled out of release builds (check-invariants
  families 5a–5e, CI-live).
- The item-24 matrix row (`p5-5b2-inv-matrix.md`, sha256
  `a12a9edbe30736f59a3a4962b133cd1431cced41d42ec9bcd3122e2052576510`,
  line 690: the release-build test-trust-anchor assertions, families 5a–5e
  and the `tls_anchor_e2e` trust-path proof, "belong to the 5d-2
  release-assertions unit") is discharged by checklist step 8: the 5e scan
  on the signed APK's `.so`, and the live production-relay pairing as the
  production analogue of `tls_anchor_e2e`.
- That matrix contains no user-facing pin-UI row; its only "pin" row is the
  debug-only `TEZCA_TEST_RELAY_PIN` bridge (family 8). No user-facing
  certificate pinning is owed at MVP; the per-conversation optional pin
  stays post-MVP, design intact.

## RC-D8 — Site and SECURITY.md truthfulness (FROZEN)

- `site/index.html` keeps "There are no supported releases yet." and adds
  one sentence stating that pre-release builds may appear on GitHub
  Releases marked pre-release and are not supported. `site/verify.html`
  gains the RC-D3 linkage step; the rule that the release entry is the
  authoritative place for per-release hashes is unchanged. `SECURITY.md`
  "Supported versions" carries the same pre-release sentence. Family 15
  gains the new literals, red first. Exact copy is drafted in the order and
  ratified by the maintainer verbatim before green.

## RC-D9 — Ordering (FROZEN)

- The docs-rider bundle lands as its own unit and merges BEFORE the RC
  branch is cut: README threat-model pointer (the stale "lands in Phase 5"
  line); the five register-pointer body sentences in `docs/threat-model.md`;
  the user-docs halves of TM-C4/C7; the §D6 one-line words-amendment to
  `docs/design/p5d-release-freeze.md` recording the deferred redirects (a
  governed amendment, words only); `<!--email_off-->` / `<!--email_on-->`
  around the security address; `deploy/README.md` per RC-D5; FLAG-2 copy
  normalization, splittable if it grows beyond copy.

## RC-D10 — Tag protection (FROZEN)

- Before the first `v*` tag: a repository ruleset on tags matching `v*` —
  restrict creation, update, and deletion; bypass list = the maintainer
  only; the Cloudflare GitHub App is not in the bypass list.
  Maintainer-by-hand in the GitHub UI; ruleset name recorded in the ledger.
- `release.yml`'s first step echoes `github.actor` so the run log records
  who pushed the tag. The ruleset is the gate; CI adds no gating logic.

## RC-D11 — Defensive registration (FROZEN)

- `titlan.app` and `titlan.net` are registered before `v0.1.0` proper (not
  gating `v0.1.0-rc.1`); the §D6 redirect design then executes as frozen.

## Sequencing (FROZEN)

1. This freeze commits to `main` (SPDX-headed, body byte-identical to the
   ratified companion).
2. Docs-rider unit (RC-D9): red/green, merge.
3. RC unit red/green: family 7 rewrite, family 15 additions, checklist
   content-asserts, then both constants flip, `versionName`,
   `docs/release-checklist.md`, site and SECURITY.md copy. No relay code,
   no wire code, no Kotlin logic — containment gate on `git diff --stat`.
4. Merge; tag ruleset (RC-D10); tag; checklist executed end to end; ledger
   entry with every hash.
5. Successors named at this freeze: `5e-1 conversation UI` (design gate
   first), RC-D1 option (b) chore, CI-created draft Releases (titlan-ops),
   container image publication (titlan-ops), signed tags, RC-D11.
