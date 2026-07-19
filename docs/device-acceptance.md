<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Phase 4b-2 device acceptance

Two acceptance signals cannot run on the hosted CI emulator and are executed
on a real device / local emulator at phase acceptance, with captured evidence
filed into the PR (frozen design §9). Both are scripted — free-form poking is
rejected — so a reviewer can re-run them and get comparable output.

## (e) Locked-boot — declines cleanly

Script: `scripts/device-locked-boot.sh` — sets a credential, reboots, and
invokes every plausible entry point BEFORE first unlock (foreground service,
launcher activity, synthetic `BOOT_COMPLETED`), then asserts the four
declines-cleanly properties (frozen design §2):

1. no crash
2. no retry-spin against sealed credential-encrypted storage
3. no notification
4. no INV-1-violating log output

Run (with the adopted FGS type declared):

```
scripts/device-locked-boot.sh -s <serial> -o device-evidence/locked-boot
```

Evidence: `device-evidence/locked-boot/{logcat.txt,notifications.txt,processes.txt}`
plus the PASS/FAIL summary. File the directory into the PR.

## (f) Doze latency — no-exemption posture

Script: `scripts/device-doze-latency.sh` — forces deep Doze WITHOUT a
battery-optimization exemption (the exemption prompt is out of MVP scope) and
measures delivery latency. Documents the GrapheneOS reality so users can
choose manual whitelisting.

```
scripts/device-doze-latency.sh -s <serial> -n 3 -o device-evidence/doze-latency
```

Evidence: `device-evidence/doze-latency/latencies.csv`. The delivery-marker leg
is wired in the 4b-2 GREEN commit (marked `TODO(4b-2 green)` in the script);
the RED commit lands the harness and the Doze-state capture.

## foregroundServiceType verification (frozen design §6, a–d)

`remoteMessaging` vs `specialUse` is decided by verification on emulator API
35/36 — a red-phase work item whose evidence is recorded in the frozen design
doc when produced. The manifest currently declares the conservative
`specialUse` default with its PROPERTY justification. Tasks and evidence
destinations:

| task | what to verify | evidence destination |
|---|---|---|
| (a) | `remoteMessaging` runs without a runtime cap on API 35/36 | design §6 evidence block |
| (b) | `remoteMessaging` can be STARTED from the §2 unlock/boot receiver contexts under Android 15 boot-start FGS restrictions | design §6 evidence block |
| (c) | prior-art survey: declared FGS types in current Signal (website APK), Molly, Conversations on API 34+ | design §6 evidence block |
| (d) | semantic-conformance + Play-review-risk note for `remoteMessaging` | design §6 evidence block |

Decision rule (fixed): adopt `remoteMessaging` if (a)–(b) pass and (c)–(d)
surface no disqualifying signal; else keep `specialUse` with the PROPERTY
justification already in the manifest. The locked-boot script (e) must pass
with whichever type is finally declared.
