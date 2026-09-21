<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan release checklist (5d-2 / v0.1.0-rc.1)

Authority: [the release-candidate freeze](design/2026-09-release-candidate-freeze.md),
RC-D6. Executed by hand by the maintainer, top to bottom. Every step names
WHERE it runs — `CI`, `VM titlan-dev`, `Windows`, `droplet` or `GitHub` — and
every gate states the value it must show; a gate that shows anything else
stops the release. `<tag>` is `v0.1.0-rc.1`; `<rc>` is the merged RC commit on
`main`. Key material never enters a repository, agent session, report, or
evidence log (RC-D3). `scripts/check-invariants.sh` family 17 pins the gate
literals below.

## 1. Pre-tag

- WHERE: GitHub — post-merge `main` is green.
  `gh run list --branch main --commit <rc> --json name,conclusion`
  expect: every `conclusion` is `success`.
- WHERE: Windows — ledger current and mount-verified.
  expect: the ledger's last entry is the RC merge, and the sha256 of the
  ledger on the reviewer's project mount equals the sha256 of the current
  ledger.
- WHERE: CI — `cargo deny` and `cargo audit` clean: job `rust-supply-chain`
  of the `<rc>` run.
  expect: `success`.
- WHERE: GitHub — docs bundle merged. `gh pr view 61 --json state`
  expect: `"state":"MERGED"`.
- WHERE: VM titlan-dev — site script-free.
  `curl -s https://titlan.chat/ | grep -c '<script'` and
  `curl -s https://titlan.chat/verify | grep -c '<script'`
  expect: `0` and `0`.
- WHERE: CI — check-invariants families 5a–5e green: the android job of the
  `<rc>` run re-runs `scripts/check-invariants.sh` after `assembleDebug` and
  `assembleRelease`.
  expect: `All invariant checks passed`, with no `5e artifact scan skipped`
  note.

## 2. Tag ceremony

- WHERE: GitHub — tag ruleset on `v*` (RC-D10) confirmed BEFORE the push:
  creation, update and deletion restricted; bypass list = the maintainer only.
  expect: the ruleset is `Active`; its name is recorded in the ledger.
- WHERE: VM titlan-dev — `git switch main && git pull --ff-only && git rev-parse HEAD`
  expect: `<rc>`.
- WHERE: VM titlan-dev —
  `git tag -a v0.1.0-rc.1 -m "Titlan v0.1.0-rc.1 (pre-release)"`
  then `git rev-parse 'v0.1.0-rc.1^{commit}'`
  expect: `<rc>`.
- WHERE: VM titlan-dev — `git push origin v0.1.0-rc.1`
  expect: a `[new tag]` line for `v0.1.0-rc.1 -> v0.1.0-rc.1`; no rejection
  by the ruleset.

## 3. release.yml

- WHERE: CI — the `Release artifacts` run for the tag.
  expect: conclusion `success`; its first step logged
  `release.yml triggered by <the maintainer's login>`.
- WHERE: VM titlan-dev — `gh run download <run id> -n titlan-release-v0.1.0-rc.1 -D rc1 && cd rc1`
  expect: `tezca-relay`, `titlan-android-unsigned.apk`, `tezca-core.cdx.json`,
  `tezca-relay.cdx.json`, `titlan-android-app.cdx.json`, `repro-report.txt`,
  `SHA256SUMS`.
- WHERE: VM titlan-dev — `sha256sum -c SHA256SUMS`
  expect: every line ends `: OK`.
- WHERE: VM titlan-dev — `grep '^result:' repro-report.txt`
  expect: `result: PASS`.

## 4. Provenance

- WHERE: VM titlan-dev — name the attestation subject as it publishes
  (RC-D3; the attestation binds the digest, not the file name):
  `cp titlan-android-unsigned.apk titlan-<tag>-unsigned.apk`
  expect: `sha256sum` prints the same digest for both names.
- WHERE: VM titlan-dev — `gh attestation verify tezca-relay --repo Titlan-chat/titlan`
  expect: exit status `0`.
- WHERE: VM titlan-dev — `gh attestation verify titlan-<tag>-unsigned.apk --repo Titlan-chat/titlan`
  expect: exit status `0`.

## 5. Independent rebuild

- WHERE: VM titlan-dev — in the repository, at the tag, from the canonical
  build path (docs/build.md): `git switch --detach v0.1.0-rc.1 && scripts/repro-build.sh`
  expect: `result: PASS`.
- WHERE: VM titlan-dev — compare the local `repro-report.txt` with the
  downloaded one.
  expect: the `build-1 sha256` of `target/release/tezca-relay` and of
  `titlan-android/app/build/outputs/apk/release/app-release-unsigned.apk` are
  equal in both reports, and equal `sha256sum tezca-relay titlan-<tag>-unsigned.apk`
  of the downloaded files.

## 6. Signing (VM, maintainer only)

- WHERE: VM titlan-dev — the RC-D3 line, verbatim flags:
  `apksigner sign --ks ~/keys/titlan-release.p12 --ks-key-alias titlan-release --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false --min-sdk-version 34 --out titlan-<tag>.apk titlan-<tag>-unsigned.apk`
  expect: exit status `0`; `titlan-<tag>-unsigned.apk` unchanged
  (`sha256sum -c SHA256SUMS` on its CI name still `: OK`).
- WHERE: VM titlan-dev — `apksigner verify --print-certs titlan-<tag>.apk`
  expect: `Signer #1 certificate SHA-256 digest: ecdde6c17629d7447c6217137b27b0af9f915dc6c5cacf8c38ff02d0b22c8ae0`
  (the D4 digest).
- WHERE: VM titlan-dev — `zipalign -c 4 titlan-<tag>.apk`
  expect: exit status `0`.
- WHERE: VM titlan-dev — `scripts/repro-build.sh --diff-apks titlan-<tag>-unsigned.apk titlan-<tag>.apk`
  expect: under `DIFFERING ENTRIES:` the single line
  `(none — archives identical at entry level)`. The command exits `0` either
  way; the line is the gate.
- WHERE: VM titlan-dev — families 5a–5e re-run: `scripts/check-invariants.sh`
  expect: `All invariant checks passed`.
- WHERE: VM titlan-dev — the 5e anchor-string scan against the `.so`
  extracted from the SIGNED APK:
  `unzip -q -o -d signed-so titlan-<tag>.apk 'lib/*/libtezca_core.so' && grep -ac 'TEZCA_TEST_RELAY_PIN' signed-so/lib/*/libtezca_core.so`
  expect: every line ends `:0`.

## 7. Publication

- WHERE: VM titlan-dev — `gh attestation download titlan-<tag>-unsigned.apk --repo Titlan-chat/titlan`
  expect: exit status `0`; one `.jsonl` attestation bundle written.
- WHERE: VM titlan-dev — `gh release create v0.1.0-rc.1 --prerelease --verify-tag`
  with the assets `titlan-<tag>.apk`, `titlan-<tag>-unsigned.apk`, the three
  SBOMs (`tezca-core.cdx.json`, `tezca-relay.cdx.json`,
  `titlan-android-app.cdx.json`), `repro-report.txt`, `SHA256SUMS`, and the
  attestation bundle. The release notes state: pre-release; not supported;
  pairing only (no conversation UI); and the `sha256sum titlan-<tag>.apk` line.
  expect: exit status `0`; the release URL is printed.
- WHERE: GitHub — `gh release view v0.1.0-rc.1 --json isPrerelease,isDraft`
  expect: `"isPrerelease":true` and `"isDraft":false`.

## 8. Production-relay acceptance

- WHERE: VM titlan-dev — two GrapheneOS devices, fresh installs of the SIGNED
  APK: `adb -s <serial> install titlan-<tag>.apk` on each.
  expect: `Success` twice. Record each device's `ro.product.model` and
  `ro.build.fingerprint`.
- WHERE: VM titlan-dev — pair the two devices by QR over `relay.titlan.chat`
  (the release default; no override).
  expect: both devices reach the pairing-complete state. Record the start and
  completion times.

## 9. Post-publish

- WHERE: Windows — site status re-check at `https://titlan.chat/`.
  expect: the page carries "There are no supported releases yet." and
  "Pre-release builds may appear on GitHub Releases marked pre-release; they
  are not supported."
- WHERE: GitHub — SECURITY.md wording re-check on `main`.
  expect: "Supported versions" carries the same pre-release sentence.
- WHERE: droplet — redeploy the tagged relay binary (by hand, deploy/README.md).
  Skippable iff `sha256sum tezca-relay` of the downloaded binary equals
  `86013b9956f302b1fbd33e5d364e94a2cc849dc08abf2097ee6e0494c4d461ac`.
  expect: `sha256sum` of the served binary equals the published one.
- WHERE: Windows — ledger entry with every hash: `<rc>`, the tag object, the
  `release.yml` run id, each `SHA256SUMS` line, the signed APK's sha256, the
  D4 digest as printed, both `repro-report.txt` hash pairs, the relay binary
  hash, and the ruleset name.
  expect: every listed value is present in the entry.
