<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Device checklist (f) — Doze delivery latency, no-exemption posture

Authority: frozen 4b-2 design §9(f). This checklist is the manual,
step-by-step form of that definition; `scripts/device-doze-latency.sh`
automates the Doze forcing, posture check, and CSV capture. Run at phase
acceptance and file the evidence into the PR.

The frozen text imposes a MEASUREMENT AND RECORDING obligation, not a
numeric latency bound: measure delivery delay under deep Doze WITHOUT any
battery-optimization exemption (the exemption prompt is out of MVP scope),
and document manual whitelisting for GrapheneOS users. There is therefore
no PASS threshold on the latency value itself; PASS means the posture was
proven (app not exempted, deep Doze reached) and a latency was measured and
recorded per run. (Flagged for maintainer confirmation in the extraction
report.)

> EXECUTION BLOCKERS AT HEAD (see Flags in the extraction report — do not
> improvise around them): the message-deposit trigger and the on-device
> delivery marker are not yet wired (`scripts/device-doze-latency.sh` marks
> them `TODO(4b-2 green)`), 4b-2 has no user-facing send surface on a peer
> device, and neither installed variant carries a relay URL reachable from
> a physical Pixel. Steps 6–8 are specified to the extent the frozen text
> and existing script define them; the unresolved mechanics are flags, not
> checklist decisions.

## Preconditions

| # | Precondition | How |
|---|---|---|
| P0 | Derive the applicationId into `$APP_ID` (single-sourced in `gradle.properties` per work-order §10.4 — never write the literal string; run this in the shell that runs every command below, from the repo root) | `APP_ID=$(grep -oP '^TITLAN_APPLICATION_ID=\K.*' titlan-android/gradle.properties)` |
| P1 | Physical GrapheneOS Pixel, USB debugging enabled, visible to adb | `adb devices`; add `-s <serial>` everywhere if multiple devices |
| P2 | Build + install the debug APK | `cd titlan-android && ./gradlew :app:assembleDebug`, then `adb install -r titlan-android/app/build/outputs/apk/debug/app-debug.apk` (variant choice flagged — release is unsigned) |
| P3 | A paired conversation with a peer that can deposit a message to this device via a relay both can reach | BLOCKED at HEAD — deposit path flagged, see extraction report |
| P4 | Sync running: the app has been opened post-unlock and the persistent "Titlan sync active" notification is present | launch the app once |
| P5 | App is NOT battery-optimization-whitelisted (the no-exemption posture) | verified in step 1; if whitelisted, remove it before proceeding |
| P6 | Evidence directory | `mkdir -p device-evidence/doze-latency`; create `device-evidence/doze-latency/latencies.csv` with header `run,deep_state,latency_ms` |

## Steps (repeat steps 2–10 for runs 1..3)

1. **Prove the no-exemption posture.**
   `adb shell dumpsys deviceidle whitelist | grep $APP_ID`
   EXPECTED: no output (app absent from the whitelist). FAIL/ABORT if the
   app appears — the measurement is only valid unexempted
   (`scripts/device-doze-latency.sh` aborts on this too).

2. **Simulate unplugged power (Doze does not engage while charging; USB
   stays attached for adb).**
   `adb shell dumpsys battery unplug`
   EXPECTED: command succeeds; device believes it is on battery.

3. **Force deep Doze.**
   ```
   adb shell dumpsys deviceidle enable
   adb shell dumpsys deviceidle force-idle
   ```
   EXPECTED: `force-idle` reports the device is now in deep idle mode.

4. **Confirm the deep-Doze step reached.**
   `adb shell dumpsys deviceidle get deep`
   EXPECTED: `IDLE`. Record the value in the `deep_state` CSV column.
   FAIL for this run if the state is not `IDLE`.

5. **Capture the deposit timestamp t0 (device clock, milliseconds — both
   timestamps come from the device clock so the latency needs no
   cross-clock correction).**
   `adb shell date +%s%3N`
   EXPECTED: an epoch-milliseconds value; record it.

6. **Deposit one message addressed to this device from the peer.**
   BLOCKED at HEAD: the deposit trigger is the `TODO(4b-2 green)` leg of
   `scripts/device-doze-latency.sh`; the frozen text does not name a
   mechanism and 4b-2 ships no user-facing send surface. Flagged — do not
   improvise a mechanism for the acceptance run.
   EXPECTED (once wired): exactly one message is deposited at the relay
   for this device's inbox at t0.

7. **Detect delivery on-device.** Delivery means the message reached
   durable persist (frozen §1: core acks the relay only after decrypt AND
   durable SQLCipher persist). BLOCKED at HEAD: no observable on-device
   delivery marker exists yet; the script plans a logcat sentinel emitted
   on durable persist, which must also satisfy §9(d) logcat hygiene.
   Flagged.
   EXPECTED (once wired): the marker for this message appears; note the
   marker's device timestamp as t1.

8. **Record the run.** Append `run,<deep_state>,<t1 − t0 in ms>` to
   `device-evidence/doze-latency/latencies.csv`.
   EXPECTED: one CSV row per run with a numeric `latency_ms` (the frozen
   recording obligation; no bound applies).

9. **Restore device state between runs.**
   ```
   adb shell dumpsys deviceidle unforce
   adb shell dumpsys battery reset
   ```
   EXPECTED: both succeed; wait ~2 s before the next run.

10. **Next run.** Repeat from step 2 until 3 runs are recorded.

11. **Documentation obligation (frozen §9(f)): document manual
    whitelisting for GrapheneOS users** — the observed latencies and the
    user-side steps to exempt Titlan from battery optimization
    (Settings → Apps → Titlan → Battery → Unrestricted), stated as a
    user choice, never an in-app prompt (out of MVP scope). Destination
    doc flagged (frozen text names the obligation, not the file).
    EXPECTED: the documentation exists and cites
    `device-evidence/doze-latency/latencies.csv`.

## Results

Run date: __________  Device/build: __________

| Run | deep state (step 4) | t0 (step 5) | t1 (step 7) | latency_ms (step 8) | notes |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

| Obligation | Result (PASS/FAIL) | Notes |
|---|---|---|
| No-exemption posture proven (step 1) | | |
| Deep Doze reached every run (step 4) | | |
| Latency measured + recorded, 3 runs (step 8) | | |
| GrapheneOS manual-whitelisting documentation (step 11) | | |

PASS = all four obligation rows PASS. File
`device-evidence/doze-latency/latencies.csv` and this table into the PR.
