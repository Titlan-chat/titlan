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

> EXECUTION STATUS AT HEAD: fully executable — no blockers remain. The
> deposit trigger (VM-side harness, step 6), the delivery marker (debug
> logcat sentinel, step 7), the debug relay override
> (`-PtitlanDebugRelayUrl`, P2), and device-side TLS trust (debug-only pin
> bridge, P2b: `adb shell setprop debug.titlan.relay-pin …`, exported by
> TitlanApp.onCreate to the core's test anchor before any core touch —
> maintainer-ratified FLAG-A option a) are all wired. The pairing-offer
> transfer mechanic is ratified as HARNESS-AS-OFFERER with the QR rendered
> on the VM screen (FLAG-B); device-as-offerer stays documented below as a
> non-designated alternative. A sentinel TIMEOUT is a pre-ratified valid
> recorded outcome (FLAG-C deferred): record it and file the evidence —
> do not adjust the Doze recipe mid-run.

## Preconditions

| # | Precondition | How |
|---|---|---|
| P0 | Derive the applicationId into `$APP_ID` (single-sourced in `gradle.properties` per work-order §10.4 — never write the literal string; run this in the shell that runs every command below, from the repo root) | `APP_ID=$(grep -oP '^TITLAN_APPLICATION_ID=\K.*' titlan-android/gradle.properties)` |
| P1 | Physical GrapheneOS Pixel, USB debugging enabled, visible to adb | `adb devices`; add `-s <serial>` everywhere if multiple devices |
| P2 | Build + install the debug APK, pointed at the VM relay's LAN address | `cd titlan-android && ./gradlew :app:assembleDebug -PtitlanDebugRelayUrl=wss://<LAN-IP>:8443`, then `adb install -r titlan-android/app/build/outputs/apk/debug/app-debug.apk` (variant choice flagged — release is unsigned) |
| P2b | Provision the relay TLS pin on the device — must run BEFORE the app launch in P4, and AGAIN after any device reboot (`setprop` does not survive reboot) | `adb shell setprop debug.titlan.relay-pin $(cat relay-certs/pin.hex)` — pin from the harness setup below; the debug build's TitlanApp.onCreate exports it to the core's test anchor before any core touch |
| P3 | A paired conversation with the VM-side deposit harness, via the VM relay | See "VM-side harness setup (P3)" below — exact commands |
| P4 | Sync running: the app has been opened post-unlock and the persistent "Titlan sync active" notification is present | launch the app once |
| P5 | App is NOT battery-optimization-whitelisted (the no-exemption posture) | verified in step 1; if whitelisted, remove it before proceeding |
| P6 | Evidence directory | `mkdir -p device-evidence/doze-latency`; create `device-evidence/doze-latency/latencies.csv` with header `run,deep_state,latency_ms` |

## VM-side harness setup (P3)

All commands run on the build host ("VM") from the repo root; the device
side is covered by P2/P2b.

1. Generate the relay TLS certificate + client pin (the pin verifier hashes
   the leaf DER and ignores SAN names, so the stock generator serves any LAN
   address):
   `cargo run -p tezca-relay --locked --example gen_test_cert -- relay-certs`
2. Launch the relay on all interfaces:
   ```
   cargo build --release -p tezca-relay --locked
   ./target/release/tezca-relay --tls-cert relay-certs/cert.pem \
     --tls-key relay-certs/key.pem --listen 0.0.0.0:8443
   ```
3. Build + install the debug APK per P2 (same `<LAN-IP>`), set the device
   pin per P2b.
4. Pre-build the harness example so the deposit command (main steps,
   step 6) starts instantly — t0 (main steps, step 5) precedes harness
   startup, so an unbuilt harness (cargo compiling at deposit time)
   inflates the measured latency:
   `cargo build -p tezca-core --locked --features test-relay-anchor --example deposit_harness`
5. Pair the harness with the device. **Designated path (ratified FLAG-B):
   harness as offerer, QR rendered on the VM screen.**
   ```
   TEZCA_TEST_RELAY_PIN=$(cat relay-certs/pin.hex) \
     cargo run -p tezca-core --locked --features test-relay-anchor \
     --example deposit_harness -- offer --dir ~/titlan-harness \
     --relay wss://<LAN-IP>:8443
   ```
   then render the printed `titlan://pair#` link as a QR on the VM screen
   with `qrencode -t ansiutf8 '<link>'` and scan it with the device's
   pairing screen.
   (Non-designated alternative, documented only: device as offerer — show
   the offer on the device, transfer the on-screen `titlan://pair#` link
   text to the VM, then run the same command with `respond --dir
   ~/titlan-harness --relay wss://<LAN-IP>:8443 --offer 'titlan://pair#…'`
   in place of `offer …`.)

   EXPECTED: the harness prints `paired: conversation <hex>`; its session
   state persists in `--dir` for every later `send` (step 6).

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
   Wired: the VM-side harness (P3) drives tezca-core's real
   session/envelope path and deposits exactly one encrypted `chat/1`
   envelope into this device's inbox over the relay HTTP API.
   `scripts/device-doze-latency.sh` runs it in the foreground each run via
   `-d`:
   ```
   scripts/device-doze-latency.sh -d 'TEZCA_TEST_RELAY_PIN=$(cat relay-certs/pin.hex) \
     cargo run -p tezca-core --locked --features test-relay-anchor \
     --example deposit_harness -- send --dir ~/titlan-harness \
     --relay wss://<LAN-IP>:8443'
   ```
   (manual form: run the quoted command directly after step 5).
   EXPECTED: the harness prints `deposit-start epoch_ms=…` then
   `deposit-confirmed epoch_ms=…` (VM clock, informational — t0 stays the
   step-5 device-clock value) and exits 0; exactly one message is
   deposited at the relay for this device's inbox at t0.

7. **Detect delivery on-device.** Delivery means the message reached
   durable persist (frozen §1: core acks the relay only after decrypt AND
   durable SQLCipher persist). Wired: the debug build emits a fixed logcat
   sentinel — tag `TitlanDelivery`, text `chat delivery persisted`, zero
   identifiers or counts (§9(d) hygiene pinned statically by
   `scripts/check-invariants.sh` §6) — at the app-side completion of the
   ack-after-persist contract. `scripts/device-doze-latency.sh` waits for
   it and computes t1 from the sentinel's device-clock epoch-ms logcat
   timestamp; manual form:
   `adb logcat -d -v epoch -s TitlanDelivery:I` and read the first
   `chat delivery persisted` line's timestamp as t1.
   EXPECTED: the sentinel for this deposit appears; t1 recorded (device
   clock, epoch ms — same clock as t0, no cross-clock correction).

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
