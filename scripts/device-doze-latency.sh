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
# Prerequisite (GREEN): a paired conversation and a way to deposit a message to
# this device from a peer/relay. In the RED commit that path is unimplemented;
# this script is committed now so the measurement is scripted, not improvised,
# and its wiring points (deposit trigger, delivery marker) are marked TODO.
#
# Usage: scripts/device-doze-latency.sh [-s <adb-serial>] [-o <out-dir>] [-n runs]
set -euo pipefail
cd "$(dirname "$0")/.."

serial=""
out_dir="device-evidence/doze-latency"
runs=3
while getopts "s:o:n:" opt; do
  case "$opt" in
    s) serial="-s $OPTARG" ;;
    o) out_dir="$OPTARG" ;;
    n) runs="$OPTARG" ;;
    *) echo "usage: $0 [-s serial] [-o out-dir] [-n runs]"; exit 2 ;;
  esac
done

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
for run in $(seq 1 "$runs"); do
  echo "[run $run] forcing deep Doze"
  state=$(force_deep_doze)
  echo "    deviceidle deep = $state"
  start_ms=$(ADB shell date +%s%3N | tr -d '\r')

  # TODO(4b-2 green): deposit a message to this device (peer/relay trigger),
  # then block until the on-device delivery marker for that message appears
  # (a logcat sentinel emitted by SyncService on durable persist). Until the
  # send/deliver path exists, this records the Doze state reached only.
  latency="TODO"

  echo "$run,$state,$latency" >> "$out_dir/latencies.csv"
  restore
  sleep 2
done

echo "captured: $out_dir/latencies.csv"
echo "DOZE-LATENCY CHECKLIST: measurement harness ready (delivery leg wired in 4b-2 green)"
