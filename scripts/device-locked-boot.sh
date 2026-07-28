#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Oculux Technologies LLC
#
# Device checklist (e) — locked-boot "declines cleanly" (frozen 4b-2 design
# §2/§9e). Repeatable, scripted, evidence-capturing: set a credential, reboot,
# invoke every plausible entry point BEFORE first unlock, and assert all four
# declines-cleanly properties:
#   1. no crash
#   2. no retry-spin against sealed CE storage
#   3. no notification
#   4. no INV-1-violating log output
#
# This runs against a real device / emulator over adb; it is NOT a CI job (the
# hosted instrumented runner cannot exercise a credential-encrypted locked
# boot). Run at phase acceptance with the adopted FGS type declared, and file
# the captured evidence directory into the PR.
#
# Usage: scripts/device-locked-boot.sh [-s <adb-serial>] [-o <out-dir>]
set -euo pipefail
cd "$(dirname "$0")/.."

serial=""
out_dir="device-evidence/locked-boot"
while getopts "s:o:" opt; do
  case "$opt" in
    s) serial="-s $OPTARG" ;;
    o) out_dir="$OPTARG" ;;
    *) echo "usage: $0 [-s serial] [-o out-dir]"; exit 2 ;;
  esac
done

# shellcheck disable=SC2086
ADB() { adb $serial "$@"; }

app_id=$(grep -oP '^TITLAN_APPLICATION_ID=\K.*' titlan-android/gradle.properties)
[ -n "$app_id" ] || { echo "cannot read TITLAN_APPLICATION_ID"; exit 1; }
pin="123456"
mkdir -p "$out_dir"

echo "== locked-boot checklist for $app_id =="
ADB wait-for-device
echo "[1/6] set device credential (PIN)"
ADB shell locksettings set-pin "$pin" >/dev/null

echo "[2/6] reboot; wait for boot WITHOUT unlocking"
ADB reboot
ADB wait-for-device
# Wait until boot completes but do NOT enter the PIN (storage stays sealed).
until [ "$(ADB shell getprop sys.boot_completed | tr -d '\r')" = "1" ]; do sleep 1; done
sleep 3
locked=$(ADB shell dumpsys user | grep -c 'Running: false\|state=RUNNING_LOCKED' || true)
echo "    user-locked indicators: $locked (informational)"

echo "[3/6] clear logcat, then invoke entry points pre-unlock"
ADB logcat -b all -c || true
# a) foreground service start; b) launcher activity; c) synthetic BOOT_COMPLETED
ADB shell am start-foreground-service "$app_id/app.titlan.sync.SyncService" || true
ADB shell am start -n "$app_id/app.titlan.MainActivity" || true
ADB shell am broadcast -a android.intent.action.BOOT_COMPLETED "$app_id" || true
sleep 8

echo "[4/6] capture evidence"
ADB logcat -b all -d > "$out_dir/logcat.txt" || true
ADB shell dumpsys notification --noredact > "$out_dir/notifications.txt" 2>/dev/null || true
ADB shell dumpsys activity processes > "$out_dir/processes.txt" 2>/dev/null || true

echo "[5/6] evaluate the four declines-cleanly properties"
fail=0
# 1. no crash
if grep -Eq "FATAL EXCEPTION|ANR in $app_id|$app_id.*died" "$out_dir/logcat.txt"; then
  echo "  FAIL(1): crash/ANR observed"; fail=1
else echo "  PASS(1): no crash"; fi
# 2. no retry-spin against sealed storage (repeated CE-open failures)
spin=$(grep -c -E "database key rejected|BadDbKey|EACCES.*(files|databases)" "$out_dir/logcat.txt" || true)
if [ "$spin" -gt 3 ]; then
  echo "  FAIL(2): retry-spin against sealed storage ($spin hits)"; fail=1
else echo "  PASS(2): no storage retry-spin ($spin hits)"; fi
# 3. no notification posted by the app while locked
if grep -q "$app_id" "$out_dir/notifications.txt" 2>/dev/null; then
  echo "  FAIL(3): notification posted while locked"; fail=1
else echo "  PASS(3): no notification while locked"; fi
# 4. no INV-1-violating log output (key-shaped hex / sentinel markers)
if grep -Eq "SENTINEL_KEY|[0-9a-f]{64}" "$out_dir/logcat.txt"; then
  echo "  FAIL(4): possible key material in logcat — inspect $out_dir/logcat.txt"; fail=1
else echo "  PASS(4): no key-shaped log output"; fi

echo "[6/6] result"
if [ "$fail" -ne 0 ]; then
  echo "LOCKED-BOOT CHECKLIST: FAIL (evidence in $out_dir)"; exit 1
fi
echo "LOCKED-BOOT CHECKLIST: PASS (evidence in $out_dir)"
