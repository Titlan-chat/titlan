#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Oculux Technologies LLC
#
# Device checklist (f) — Doze delivery latency under the NO-EXEMPTION posture
# (frozen 4b-2 design §2/§9f). Measures how long a message takes to be
# delivered while the device is in deep Doze, WITHOUT requesting a
# battery-optimization exemption (that prompt is out of scope). The result
# documents the GrapheneOS reality so users can choose manual whitelisting.
#
# Repeatable and evidence-capturing; NOT a CI job (deep Doze cannot be forced
# meaningfully on the hosted emulator). Run at phase acceptance and file the
# captured evidence into the PR.
#
# Prerequisites (checklist f preconditions): a paired conversation with the
# VM-side deposit harness (tezca-core example deposit_harness — see checklist
# P3) and a relay both sides reach. -d supplies the deposit command the script
# runs in the foreground once per run, e.g.:
#   -d 'TEZCA_TEST_RELAY_PIN=$(cat certs/pin.hex) cargo run -p tezca-core \
#       --features test-relay-anchor --example deposit_harness -- send \
#       --dir /path/to/harness-state --relay wss://<LAN-host>:8443'
# The delivery marker (t1) is the debug-only logcat sentinel emitted by
# CoreClient.kt when an inbound chat completes the ack-after-persist contract;
# its tag+text literals are pinned equal to this script's by
# scripts/check-invariants.sh §6. Both t0 and t1 come from the device clock,
# so the latency needs no cross-clock correction (the harness's own printed
# epoch-ms is VM-clock, informational only).
#
# Usage: scripts/device-doze-latency.sh -d <deposit-cmd> \
#          [-s <adb-serial>] [-o <out-dir>] [-n runs] [-w <sentinel-wait-secs>]
set -euo pipefail
cd "$(dirname "$0")/.."

serial=""
out_dir="device-evidence/doze-latency"
runs=3
deposit_cmd=""
wait_secs=900
while getopts "s:o:n:d:w:" opt; do
  case "$opt" in
    s) serial="-s $OPTARG" ;;
    o) out_dir="$OPTARG" ;;
    n) runs="$OPTARG" ;;
    d) deposit_cmd="$OPTARG" ;;
    w) wait_secs="$OPTARG" ;;
    *) echo "usage: $0 -d <deposit-cmd> [-s serial] [-o out-dir] [-n runs] [-w wait-secs]"; exit 2 ;;
  esac
done
[ -n "$deposit_cmd" ] || {
  echo "usage: $0 -d <deposit-cmd> [-s serial] [-o out-dir] [-n runs] [-w wait-secs]"
  echo "-d is required: the VM-side command that deposits exactly ONE message"
  echo "   (checklist f step 6; see the header comment for the harness form)"
  exit 2
}

# On-device delivery marker (t1): fixed debug-only sentinel, single-sourced in
# CoreClient.kt and asserted identical here by scripts/check-invariants.sh §6.
sentinel_tag="TitlanDelivery"
sentinel_text="chat delivery persisted"

# shellcheck disable=SC2086
ADB() { adb $serial "$@"; }

app_id=$(grep -oP '^TITLAN_APPLICATION_ID=\K.*' titlan-android/gradle.properties)
[ -n "$app_id" ] || { echo "cannot read TITLAN_APPLICATION_ID"; exit 1; }
mkdir -p "$out_dir"

echo "== doze-latency checklist for $app_id ($runs runs) =="
ADB wait-for-device
ADB shell dumpsys deviceidle whitelist 2>/dev/null | grep -q "$app_id" \
  && { echo "ABORT: app is battery-optimization-whitelisted; no-exemption posture requires it OUT"; exit 1; } \
  || echo "confirmed: app NOT whitelisted (no-exemption posture)"

force_deep_doze() {
  ADB shell dumpsys battery unplug >/dev/null
  ADB shell dumpsys deviceidle enable >/dev/null || true
  ADB shell dumpsys deviceidle force-idle >/dev/null
  # Confirm we reached the IDLE (deep Doze) step.
  ADB shell dumpsys deviceidle get deep | tr -d '\r'
}

restore() {
  ADB shell dumpsys deviceidle unforce >/dev/null || true
  ADB shell dumpsys battery reset >/dev/null || true
}
trap restore EXIT

: > "$out_dir/latencies.csv"
echo "run,deep_state,latency_ms" >> "$out_dir/latencies.csv"
timed_out=0
for run in $(seq 1 "$runs"); do
  echo "[run $run] forcing deep Doze"
  state=$(force_deep_doze)
  echo "    deviceidle deep = $state"

  # Clear logcat so the sentinel scan below covers only this run's window,
  # then capture t0 (device clock, epoch ms — checklist step 5).
  ADB logcat -c
  start_ms=$(ADB shell date +%s%3N | tr -d '\r')

  # Deposit exactly one message from the VM-side harness (checklist step 6),
  # in the foreground; its exit status gates the run.
  echo "[run $run] depositing one message (VM-side harness)"
  bash -c "$deposit_cmd"

  # Block until the delivery sentinel appears (checklist step 7): t1 is the
  # sentinel line's device-clock logcat timestamp (-v epoch, milliseconds).
  echo "[run $run] waiting up to ${wait_secs}s for the delivery sentinel"
  latency="TIMEOUT"
  wait_deadline=$(( $(date +%s) + wait_secs ))
  while [ "$(date +%s)" -lt "$wait_deadline" ]; do
    t1_line=$(ADB logcat -d -v epoch -s "${sentinel_tag}:I" \
      | grep -F "$sentinel_text" | head -n 1 || true)
    if [ -n "$t1_line" ]; then
      t1_ms=$(printf '%s\n' "$t1_line" | awk '{ts=$1; sub(/\./, "", ts); print ts; exit}')
      latency=$(( t1_ms - start_ms ))
      break
    fi
    sleep 1
  done
  if [ "$latency" = "TIMEOUT" ]; then
    timed_out=1
    echo "    NO delivery sentinel within ${wait_secs}s — recorded TIMEOUT"
  else
    echo "    latency_ms = $latency (t0=$start_ms t1=$t1_ms, device clock)"
  fi

  echo "$run,$state,$latency" >> "$out_dir/latencies.csv"
  restore
  sleep 2
done

echo "captured: $out_dir/latencies.csv"
if [ "$timed_out" -ne 0 ]; then
  echo "DOZE-LATENCY CHECKLIST: FAILED — at least one run recorded no delivery sentinel"
  exit 1
fi
echo "DOZE-LATENCY CHECKLIST: latency measured and recorded for all runs (no-exemption posture)"
