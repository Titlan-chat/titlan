<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan release checklist (5e-2 / v0.1.0)

Authority: [the release-candidate freeze](design/2026-09-release-candidate-freeze.md),
RC-D6. Executed by hand by the maintainer, top to bottom. Every step names
WHERE it runs — `CI`, `VM titlan-dev`, `Windows`, `droplet` or `GitHub` — and
every gate states the value it must show; a gate that shows anything else
stops the release. `<tag>` is `v0.1.0`; `<rc>` is the merged RC commit on
`main`; `<prev>` is the release published before `<tag>` (for `v0.1.0`, the
second release candidate). Key material never enters a repository, agent
session, report, or evidence log (RC-D3). `scripts/check-invariants.sh`
family 17 pins the gate literals below. On the VM, `apksigner` and `zipalign`
are `$ANDROID_HOME/build-tools/36.0.0/apksigner` and `…/zipalign`; `gh run` and
`gh release` commands run outside the repository take `-R Titlan-chat/titlan`.

Device evidence (§0 and §8 as run for v0.1.0): `adb screencap` returns a black
frame under the app's always-on FLAG_SECURE, so message alignment is read from
`uiautomator dump` bounds (sender right, receiver left) or by eye and stated in
words; Back is `adb shell input keyevent KEYCODE_BACK` (a tap on a text node
can land on a zero-bounds node); conversation rows read `Conversation <hex>`.
A literal is sent with the hardened send: focus the field, wait 1.5 s, type
it, verify the field holds the literal, tap Send from a fresh dump, verify the
field emptied — a field still holding the literal after the tap is a stop. A
pairing link is typed in chunks of at most 200 characters (one
`adb shell input text` call truncates at 1,256 characters) and the field is
verified equal to the link before "Pair from link" is tapped.

## 0. Pre-tag device smoke

The release trust path (RC-D7) is provable only on a device: the debug suites
run under the CI test anchor and never reach the platform verifier (finding
F-C, v0.1.0-rc.1). The pairing handshake is device-only for the same reason:
finding F-F (2026-09-26) — a port-less relay URL made every WebSocket
subscription fail — passed every suite because no suite uses a port-less URL.
No tag until this section passes on the exact `<rc>`, in BOTH directions.

- WHERE: VM titlan-dev — at `<rc>`:
  `git switch --detach <rc> && REPRO_KEEP_DIR="$HOME/rc-smoke" scripts/repro-build.sh`
  expect: `result: PASS`; `~/rc-smoke/app-release-unsigned.apk` present.
- WHERE: VM titlan-dev — throwaway signature. NEVER the D4 key; the keystore
  below is created and deleted in the same command:
  `SMOKE=$(mktemp -d) && keytool -genkeypair -keystore "$SMOKE/smoke.p12" -storetype PKCS12 -alias smoke -keyalg RSA -keysize 2048 -validity 1 -dname CN=smoke -storepass smokesmoke -keypass smokesmoke && "$ANDROID_HOME/build-tools/36.0.0/apksigner" sign --ks "$SMOKE/smoke.p12" --ks-pass pass:smokesmoke --ks-key-alias smoke --out "$HOME/rc-smoke/titlan-smoke.apk" "$HOME/rc-smoke/app-release-unsigned.apk"; rm -rf "$SMOKE"`
  expect: exit status `0`; `~/rc-smoke/titlan-smoke.apk` present.
- WHERE: Windows — `scp` `titlan-smoke.apk` down; on one physical GrapheneOS
  device and the AOSP emulator: uninstall any existing Titlan first
  (`adb -s <serial> uninstall <applicationId>`), then
  `adb -s <serial> install titlan-smoke.apk`.
  expect: `Success` on both.
- WHERE: devices — pairing in BOTH directions, no relay override anywhere.
  Since 5e-1 both roles land on the conversation screen: the responder's
  screen and, within 10 s of it, the offerer's (which leaves the QR on its
  own) each show `Paired — conversation established`; that line is the
  evidence each way. Grant the camera permission on the physical device
  persistently when asked (a one-time grant lapses before the next scan).
  After a host sleep, mint an offer in-app before any device step (the
  finding F-G rule: the emulator's network can look validated and be dead).
  Direction A (QR, F-D): "Show pairing offer" on the emulator; scan the QR
  with the physical device's camera — no link paste.
  expect: a QR filling the emulator's width; `Paired — conversation
  established` on the physical device within 60 s of the scan, and on the
  emulator within 10 s after that.
  Direction B (link, F-E/F-F): after Direction A both devices sit in that
  conversation — on each, Back, then "Pair a device". "Show pairing offer" on
  the physical device; the emulator's paste field appears about 20 s after
  its pairing screen opens (the scan timeout). Read the physical device's
  `titlan://pair#` link fresh from its screen (a link read earlier names a
  pairing inbox that may already be retired), type it into the emulator's
  field in chunks of at most 200 characters, verify the field equals the
  link, and tap "Pair from link".
  expect: `Paired — conversation established` on the emulator within 60 s,
  and on the physical device within 10 s after that.
  Record both serials, `ro.build.fingerprint`, and the measured times of
  each direction: a UTC stamp at the scan or the tap, and one when each
  `Paired — conversation established` line appears.
- WHERE: devices — Message exchange (5e-1), in the conversation Direction B
  created. Send the literal `titlan message A to B` from the physical device
  and the literal `titlan message B to A` from the emulator (hardened send,
  preamble).
  expect: each message appears on the other device within 30 s of Send —
  right-aligned on the sender, left-aligned on the receiver.
- WHERE: devices — Message timestamps (1.1): in that conversation, each of
  the two exchange messages carries one time under its bubble on both
  devices — the send time on the sender, the arrival time on the receiver,
  each in that device's local zone, as a time of day (a message from today).
  expect: a time under `titlan message A to B` and under `titlan message
  B to A` on both devices; no delivery tick anywhere.
- WHERE: devices — Conversation label (1.1): on the physical device, tap the
  title `Conversation <hex>` in the chat header, type the literal
  `titlan label smoke`, tap Save, then Back.
  expect: the chat header and the list row read `titlan label smoke`, with
  `Conversation <hex>` beneath the row and the time of the last message on
  it. Then `adb -s <serial> shell am force-stop <applicationId>` and open
  Titlan again: the row still reads `titlan label smoke` (the label is read
  back from the encrypted store). Long-press the row, tap Clear: the row
  reads `Conversation <hex>` again.
- WHERE: devices — Idle-socket round trip (F-L). Leave both devices in that
  conversation, screens on, untouched for 15 minutes: no sends, no network
  toggles, no app switching (the keepalive runs about sixteen rounds). Then
  send the literal `titlan message idle` from the physical device (hardened
  send).
  expect: `titlan message idle` appears on the emulator within 60 s of Send.
  A message that arrives only after a network toggle is the F-L failure.
- WHERE: devices — Airplane-mode round trip (5e-1). Airplane mode ON on the
  physical device (quick settings, or
  `adb -s <serial> shell cmd connectivity airplane-mode enable`); send the
  literal `titlan message offline` (hardened send) — it appears in the
  sender's list; then airplane mode OFF (`… airplane-mode disable`).
  expect: `titlan message offline` appears on the emulator after reconnect,
  within 5 minutes of airplane mode going off (ruling R-F; finding F-O).
- WHERE: Windows — logcat hygiene, both devices:
  `adb -s <serial> logcat -d | findstr /c:"titlan message" /c:"titlan label"`
  expect: no output on either device (INV-1: no message text and no label
  in logcat).
- WHERE: Windows — uninstall the smoke build from both devices (§8 needs fresh
  installs of the D4-signed APK).

## 1. Pre-tag

- WHERE: GitHub — post-merge `main` is green.
  `gh run list --branch main --commit <rc> --json name,conclusion`
  expect: every `conclusion` is `success`.
- WHERE: Windows — ledger current and reviewer-verified.
  expect: the ledger's last entry is the RC merge; the maintainer attaches the
  ledger file and the reviewer verifies its sha256 equals the current
  ledger's, then refreshes the Project copy from those bytes.
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

- WHERE: VM titlan-dev — RC-D11 as amended 2026-11-01, BEFORE the tag:
  `curl -sL -o /dev/null -w '%{http_code}\n' https://rdap.org/domain/titlan.app`
  and its RDAP `nameservers` compared with `titlan.chat`'s.
  expect: `200`, and the nameserver pair equal to `titlan.chat`'s (a 200
  alone proves registration, not control).
- WHERE: GitHub — tag ruleset on `v*` (RC-D10) confirmed BEFORE the push:
  creation, update and deletion restricted; bypass list = the maintainer only.
  expect: the ruleset is `Active`; its name is recorded in the ledger.
- WHERE: VM titlan-dev — `git switch main && git pull --ff-only && git rev-parse HEAD`
  expect: `<rc>`.
- WHERE: VM titlan-dev —
  `git tag -a v0.1.0 -m "Titlan v0.1.0"`
  then `git rev-parse 'v0.1.0^{commit}'`
  expect: `<rc>`.
- WHERE: VM titlan-dev — `git push origin v0.1.0`
  expect: a `[new tag]` line for `v0.1.0 -> v0.1.0`; no rejection by the
  ruleset.

## 3. release.yml

- WHERE: CI — the `Release artifacts` run for the tag.
  expect: conclusion `success`; its first step logged
  `release.yml triggered by <the maintainer's login>`.
- WHERE: VM titlan-dev — `gh run download <run id> -n titlan-release-v0.1.0 -D rel && cd rel`
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
  build path (docs/build.md): `git switch --detach v0.1.0 && scripts/repro-build.sh`
  expect: `result: PASS`.
- WHERE: VM titlan-dev — compare the local `repro-report.txt` with the
  downloaded one.
  expect: the `build-1 sha256` of `target/release/tezca-relay` and of
  `titlan-android/app/build/outputs/apk/release/app-release-unsigned.apk` are
  equal in both reports, and equal `sha256sum tezca-relay titlan-<tag>-unsigned.apk`
  of the downloaded files.
- WHERE: VM titlan-dev — `grep -E '^(ndk|cargo-ndk):' repro-report.txt`
  expect: `ndk:          28.2.13676358 (canonical /tmp/tezca-repro/ndk)` and a
  `cargo-ndk:` line; the leak gate printed `leak-gate compiler: compiler: /tmp/tezca-repro/ndk/…`.

First execution (2026-09-21) stopped here: the published artifacts were repo-root
builds, not the reported canonical ones, and canonical APKs differed across machines
by OpenSSL's recorded NDK compiler path. Both resolved by the canonical NDK path and
REPRO_KEEP_DIR (see docs/build.md). Only repro-build.sh output is evidence; cached
`target/` strings from ordinary Gradle builds carry a developer SDK path.

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
- WHERE: VM titlan-dev — `gh release create v0.1.0 --verify-tag --latest`
  with the assets `titlan-<tag>.apk`, `titlan-<tag>-unsigned.apk`, the three
  SBOMs (`tezca-core.cdx.json`, `tezca-relay.cdx.json`,
  `titlan-android-app.cdx.json`), `repro-report.txt`, `SHA256SUMS`, and the
  attestation bundle. The release notes state: the first supported release;
  what it does (pairing by QR code or link, one-to-one text conversations,
  background sync by a foreground service, Android 14 or later, GrapheneOS
  first); what it does not do (as the site lists); Known issues — after the
  network returns, delivery can take up to about 5 minutes (finding F-O), and
  a pairing that fails partway can leave an empty conversation in the list,
  so pair again (findings F-K/F-I); the `sha256sum titlan-<tag>.apk` line;
  and the link to `https://titlan.chat/verify`.
  expect: exit status `0`; the release URL is printed.
- WHERE: GitHub — `gh release view v0.1.0 --json isPrerelease,isDraft`
  expect: `"isPrerelease":false` and `"isDraft":false`.
- WHERE: GitHub — `gh api repos/Titlan-chat/titlan/releases/latest --jq .tag_name`
  expect: `v0.1.0`.

## 8. Production-relay acceptance

- WHERE: VM titlan-dev — two GrapheneOS devices, fresh installs of the SIGNED
  APK: `adb -s <serial> install titlan-<tag>.apk` on each.
  expect: `Success` twice. Record each device's `ro.product.model` and
  `ro.build.fingerprint`.
- WHERE: VM titlan-dev — pair the two devices by QR over `relay.titlan.chat`
  (the release default; no override).
  expect: both devices reach the pairing-complete state. Record the start and
  completion times.
- WHERE: devices — Message exchange (5e-1), in the conversation just paired:
  the literal `titlan message A to B` sent from the first device, the literal
  `titlan message B to A` sent from the second (hardened send, preamble).
  expect: each appears on the other device within 30 s of Send.
- WHERE: devices — Message timestamps (1.1): both exchange messages carry one
  time under the bubble on both devices (send time on the sender, arrival
  time on the receiver, local zone, a time of day).
  expect: a time under each of `titlan message A to B` and `titlan message
  B to A` on both devices; no delivery tick.
- WHERE: devices — Conversation label (1.1): on the first device, tap the
  chat header title, type the literal `titlan label release`, Save, Back.
  expect: the header and the list row read `titlan label release` with
  `Conversation <hex>` beneath; after
  `adb -s <serial> shell am force-stop <applicationId>` and a relaunch the
  row still reads `titlan label release`.
- WHERE: devices — Idle-socket round trip (F-L): both devices left in that
  conversation, screens on, untouched for 15 minutes; then the literal
  `titlan message idle` sent from the first device (hardened send).
  expect: `titlan message idle` appears on the second device within 60 s of
  Send, with no network toggle.
- WHERE: devices — Airplane-mode round trip (5e-1): airplane mode ON on one
  device, the literal `titlan message offline` sent from it (hardened send),
  airplane mode OFF.
  expect: `titlan message offline` appears on the other device after
  reconnect, within 5 minutes of airplane mode going off (ruling R-F; finding
  F-O).
- WHERE: devices — Upgrade from `<prev>` (5e-2): on the second device,
  `adb -s <serial> uninstall <applicationId>`, then
  `adb -s <serial> install titlan-<prev>.apk` (the D4-signed asset of `<prev>`,
  from `gh release download <prev> -R Titlan-chat/titlan -p 'titlan-<prev>.apk'`
  on the VM, hashed on both sides); pair it with the first device by link (the
  first device shows the pairing offer, the second types it in chunks of at
  most 200 characters, field verified equal); then
  `adb -s <serial> install -r titlan-<tag>.apk` over it and relaunch the app.
  expect: `Success` for both installs and the in-place install; the second
  device opens on the conversation list showing the one row
  `Conversation <hex>` paired under `<prev>`; open it and record which
  messages were already present — a message stored under a pre-1.1 `<prev>`
  shows no time (rows from before 1.1 are never back-filled); the literal
  `titlan message upgrade` sent from the first device in that conversation
  (hardened send) appears on the second device within 30 s of Send, with a
  time under it. Then on the second device tap the title, type the literal
  `titlan label upgrade`, Save: the pre-upgrade conversation accepts a label
  and the row reads it (the schema v3 → v4 migration, on device).
- WHERE: Windows — logcat hygiene, both devices:
  `adb -s <serial> logcat -d | findstr /c:"titlan message" /c:"titlan label"`
  expect: no output on either device (INV-1: no message text and no label
  in logcat).

## 9. Post-publish

- WHERE: Windows — site status re-check at `https://titlan.chat/`.
  expect: the page carries "Only the latest release on GitHub Releases is
  supported; pre-releases are not."
- WHERE: GitHub — SECURITY.md wording re-check on `main`.
  expect: "Supported versions" carries the same support sentence.
- WHERE: VM titlan-dev — the `titlan.app` redirect (RC-D11 as amended
  2026-11-01; set in Cloudflare 2026-11-02 as `A @ 192.0.2.1` Proxied plus
  Redirect Rule `titlan-app-latest-release`):
  `curl -sI https://titlan.app | grep -iE '^(HTTP|location)'`.
  expect: `302` with `location: https://github.com/Titlan-chat/titlan/releases/latest`.
  No other domain is checked: Titlan is `titlan.chat` and `titlan.app`.
- WHERE: droplet — redeploy the tagged relay binary (by hand, deploy/README.md).
  Skippable iff `sha256sum tezca-relay` of the downloaded binary equals the
  sha256 of the binary the droplet currently serves
  (`sha256sum /usr/local/bin/tezca-relay` on the droplet).
  expect: `sha256sum` of the served binary equals the published one, and
  `curl -s https://relay.titlan.chat/healthz` answers `ok` from the VM — the
  check runs from the VM only (a request from the droplet to its own public
  port does not cross the 443→8443 redirect).
- WHERE: Windows — ledger entry with every hash: `<rc>`, the tag object, the
  `release.yml` run id, each `SHA256SUMS` line, the signed APK's sha256, the
  D4 digest as printed, both `repro-report.txt` hash pairs, the relay binary
  hash, the ruleset name, the §8 record file's sha256, and the publish stamp
  (`gh release view <tag> --json publishedAt`).
  expect: every listed value is present in the entry.
