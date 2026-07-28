<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Device checklist (e) — locked-boot "declines cleanly"

Authority: frozen 4b-2 design §2 (boot and storage) and §9(e) (scripted
device checklists). This checklist is the manual, step-by-step form of that
definition; `scripts/device-locked-boot.sh` automates steps 1–16 (its lock
check at step 3 is informational, not asserted; it does not probe entry
points 4–6 or perform step 17 cleanup) and is the preferred way to produce
comparable evidence for the steps it covers. Run at phase acceptance with
the adopted foregroundServiceType declared (currently `specialUse`, the §6
conservative default), and file the evidence directory into the PR.

The four decline-cleanly properties under test (frozen §2, verbatim pass
criteria):

1. no crash
2. no retry-spin against sealed storage
3. no notification
4. no INV-1-violating log output

## Preconditions

| # | Precondition | How |
|---|---|---|
| P0 | Derive the applicationId into `$APP_ID` (single-sourced in `gradle.properties` per work-order §10.4 — never write the literal string; run this in the shell that runs every command below, from the repo root) | `APP_ID=$(grep -oP '^TITLAN_APPLICATION_ID=\K.*' titlan-android/gradle.properties)` |
| P1 | Physical GrapheneOS Pixel, USB debugging enabled, visible to adb | `adb devices` lists the serial; if more than one device is attached, add `-s <serial>` to every adb command below |
| P2 | Build the debug APK (the only locally installable signed artifact; release is unsigned by design — see Flags in the extraction report) | `cd titlan-android && ./gradlew :app:assembleDebug` |
| P3 | Install it | `adb install -r titlan-android/app/build/outputs/apk/debug/app-debug.apk` |
| P4 | Confirm the app under test is installed | `adb shell pm list packages \| grep $APP_ID` shows it |
| P5 | Record the declared FGS type for the run | `specialUse` unless §6 verification has ratified `remoteMessaging` — note which in the results table |
| P6 | No device credential currently needed by the owner that PIN `123456` would disturb; the checklist sets and later clears this PIN |
| P7 | Evidence directory | `mkdir -p device-evidence/locked-boot` |

## Steps

Each step states the exact command and the EXPECTED result as a pass/fail
criterion. "The four properties hold" always means: no crash (1), no
retry-spin (2), no notification (3), no INV-1-violating log output (4) —
evaluated in steps 13–16 over the evidence captured in step 12.

1. **Set the device credential (PIN).**
   `adb shell locksettings set-pin 123456`
   EXPECTED: command succeeds. FAIL if the PIN cannot be set.

2. **Reboot and wait for boot WITHOUT unlocking.**
   `adb reboot && adb wait-for-device`
   then poll until `adb shell getprop sys.boot_completed` prints `1`.
   Do NOT touch the device; the PIN is never entered. Credential-encrypted
   (CE) storage stays sealed (frozen §2: post-reboot sync deferral until
   first unlock is a deliberate, documented property).
   EXPECTED: device boots to the locked state.

3. **Confirm the user is locked.**
   `adb shell dumpsys user | grep -E "RUNNING_LOCKED"`
   EXPECTED: user 0 reports `RUNNING_LOCKED`. FAIL (setup invalid, do not
   proceed) if the user reports unlocked.

4. **Clear all log buffers so evidence covers only the probe window.**
   `adb logcat -b all -c`
   EXPECTED: command succeeds.

5. **Entry point 1 — foreground service start (frozen §2: "service
   start"; §2: service start is GATED on isUserUnlocked, not sequenced by
   convention).**
   `adb shell am start-foreground-service $APP_ID/app.titlan.sync.SyncService`
   EXPECTED: either the OS refuses (the service is not exported —
   SecurityException from `am` is a valid decline) or the start is
   accepted and the service declines cleanly per the §2 gate at the
   service entry. Pass/fail: the four properties hold.

6. **Entry point 2 — launcher activity (frozen §2: "app launch").**
   `adb shell am start -n $APP_ID/app.titlan.MainActivity`
   EXPECTED: the command is accepted (the activity is exported/LAUNCHER);
   whatever the process does before first unlock, it declines cleanly.
   Pass/fail: the four properties hold.

7. **Entry point 3 — synthetic BOOT_COMPLETED broadcast (frozen §2:
   "every receiver"). No app receiver exists in 4b-2 (unlock retry is
   wired at the app layer in 4b-3), so this is a negative probe kept for
   parity with `scripts/device-locked-boot.sh`.**
   `adb shell am broadcast -a android.intent.action.BOOT_COMPLETED $APP_ID`
   EXPECTED: either the OS refuses the protected broadcast from shell (a
   valid decline) or it completes with no app receiver run. Pass/fail:
   the four properties hold.

8. **Entry point 4 — library-injected exported receiver
   `androidx.profileinstaller.ProfileInstallReceiver` (present in the
   merged manifest, exported, guarded by `android.permission.DUMP`,
   which the adb shell holds — so it IS invokable pre-unlock; flagged as
   absent from the frozen doc's enumeration). Probe all four declared
   actions:**
   ```
   adb shell am broadcast -a androidx.profileinstaller.action.INSTALL_PROFILE -n $APP_ID/androidx.profileinstaller.ProfileInstallReceiver
   adb shell am broadcast -a androidx.profileinstaller.action.SKIP_FILE -n $APP_ID/androidx.profileinstaller.ProfileInstallReceiver
   adb shell am broadcast -a androidx.profileinstaller.action.SAVE_PROFILE -n $APP_ID/androidx.profileinstaller.ProfileInstallReceiver
   adb shell am broadcast -a androidx.profileinstaller.action.BENCHMARK_OPERATION -n $APP_ID/androidx.profileinstaller.ProfileInstallReceiver
   ```
   EXPECTED: each broadcast either completes or is refused; the receiver
   runs androidx code only. Pass/fail: the four properties hold.

9. **Entry point 5 — library-injected service
   `androidx.camera.core.impl.MetadataHolderService` (merged manifest,
   NOT exported; flagged as absent from the frozen enumeration).**
   `adb shell am start-service $APP_ID/androidx.camera.core.impl.MetadataHolderService`
   EXPECTED: the OS refuses (not exported). Pass/fail: the refusal must
   come from the OS (`am` error), not an app crash; the four properties
   hold.

10. **Entry point 6 — `titlan://` scheme (frozen §3/§4 name the scheme;
    no merged manifest registers a VIEW handler for it in 4b-2 — flagged
    — so this is a negative probe).**
    `adb shell am start -a android.intent.action.VIEW -d "titlan://pair#AAAA"`
    EXPECTED: no activity resolves (`am` reports no activity found /
    activity not started); the app is not launched by this intent.
    Pass/fail: the four properties hold.

11. **Settle window.** Wait ~8 seconds so any crash loop, retry spin, or
    delayed notification would surface in the evidence.

12. **Capture evidence.**
    ```
    adb logcat -b all -d > device-evidence/locked-boot/logcat.txt
    adb shell dumpsys notification --noredact > device-evidence/locked-boot/notifications.txt
    adb shell dumpsys activity processes > device-evidence/locked-boot/processes.txt
    ```
    EXPECTED: three evidence files exist and are non-empty.

13. **Evaluate property 1 — no crash.**
    `grep -E "FATAL EXCEPTION|ANR in $APP_ID|$APP_ID.*died" device-evidence/locked-boot/logcat.txt`
    EXPECTED: no matches. PASS = no matches; FAIL = any match.

14. **Evaluate property 2 — no retry-spin against sealed storage.**
    `grep -c -E "database key rejected|BadDbKey|EACCES.*(files|databases)" device-evidence/locked-boot/logcat.txt`
    EXPECTED: count ≤ 3 (the threshold `scripts/device-locked-boot.sh`
    enforces; the frozen text states the property without a number —
    flagged). PASS = count ≤ 3; FAIL = count > 3.

15. **Evaluate property 3 — no notification.**
    `grep $APP_ID device-evidence/locked-boot/notifications.txt`
    EXPECTED: no matches (the app posted nothing while locked — frozen
    §2; the §7 persistent notification must not appear pre-unlock).
    PASS = no matches; FAIL = any match.

16. **Evaluate property 4 — no INV-1-violating log output.**
    `grep -E "SENTINEL_KEY|[0-9a-f]{64}" device-evidence/locked-boot/logcat.txt`
    EXPECTED: no matches (no key-shaped hex, no sentinel markers). Any
    match: inspect the line; key material or mailbox/routing identifiers
    are a FAIL, a benign 64-hex string (e.g. a system checksum outside
    the app's output) is recorded with justification.

17. **Cleanup.** Unlock the device once, then:
    `adb shell locksettings clear --old 123456`
    EXPECTED: PIN removed; device restored.

## Property → step mapping (frozen §2, all four testable)

| Decline-cleanly property | Probed by steps | Evaluated at step |
|---|---|---|
| 1. no crash | 5, 6, 7, 8, 9, 10 | 13 |
| 2. no retry-spin against sealed storage | 5, 6, 7, 8, 9, 10 | 14 |
| 3. no notification | 5, 6, 7, 8, 9, 10 | 15 |
| 4. no INV-1-violating log output | 5, 6, 7, 8, 9, 10 | 16 |

## Results

Run date: __________  Device/build: __________  Declared FGS type: __________

| Step | Result (PASS/FAIL) | Observed value / notes |
|---|---|---|
| 1 PIN set | | |
| 2 reboot, no unlock | | |
| 3 RUNNING_LOCKED confirmed | | |
| 4 logcat cleared | | |
| 5 SyncService probe | | |
| 6 MainActivity probe | | |
| 7 BOOT_COMPLETED probe | | |
| 8 ProfileInstallReceiver probe (×4 actions) | | |
| 9 MetadataHolderService probe | | |
| 10 titlan:// VIEW probe | | |
| 11 settle window | | |
| 12 evidence captured | | |
| 13 property 1: no crash | | |
| 14 property 2: no retry-spin | | (grep count: ) |
| 15 property 3: no notification | | |
| 16 property 4: no INV-1 log output | | |
| 17 cleanup | | |

Overall: PASS requires steps 13–16 all PASS. File
`device-evidence/locked-boot/` into the PR with this table completed.
