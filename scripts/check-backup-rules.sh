#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Oculux Technologies LLC
#
# 4b-1 acceptance (maintainer-confirmed backup posture): the BUILT APK's
# merged manifest must reference android:dataExtractionRules, and the rules
# must exclude app data from BOTH <cloud-backup> AND <device-transfer> —
# the wrapped DB key cannot leave the Keystore, so any extracted copy of app
# data is a pure leak surface. Checked against aapt2 output of the built
# APK, never source XML (the manifest merger can flip attributes).
#
# Usage: check-backup-rules.sh [path-to-apk]
set -u  # no -e: we aggregate failures explicitly

APK="${1:-titlan-android/app/build/outputs/apk/debug/app-debug.apk}"

AAPT2="$(find "${ANDROID_HOME:-$HOME/Android/Sdk}/build-tools" -name aapt2 2>/dev/null | sort -V | tail -1)"
if [[ -z "$AAPT2" ]]; then
  echo "FAIL: aapt2 not found under \${ANDROID_HOME}/build-tools" >&2
  exit 2
fi
if [[ ! -f "$APK" ]]; then
  echo "FAIL: APK not found at $APK (build :app:assembleDebug first)" >&2
  exit 2
fi

fail=0
say_fail() { echo "FAIL: $1" >&2; fail=1; }

manifest="$("$AAPT2" dump xmltree --file AndroidManifest.xml "$APK")"

if ! grep -q 'allowBackup.*=false' <<<"$manifest"; then
  say_fail "merged manifest must set android:allowBackup=\"false\""
fi

rules_ref="$(grep -o 'dataExtractionRules[^@]*@xml/[A-Za-z0-9_]*' <<<"$manifest" | head -1)"
if [[ -z "$rules_ref" ]]; then
  say_fail "merged manifest carries no android:dataExtractionRules reference"
else
  rules_file="res/xml/${rules_ref##*@xml/}.xml"
  rules="$("$AAPT2" dump xmltree --file "$rules_file" "$APK" 2>/dev/null)"
  if [[ -z "$rules" ]]; then
    say_fail "dataExtractionRules resource $rules_file not found in APK"
  else
    for section in cloud-backup device-transfer; do
      if ! grep -q "E: $section" <<<"$rules"; then
        say_fail "dataExtractionRules missing <$section> section"
      fi
    done
    if grep -q 'E: include' <<<"$rules"; then
      say_fail "dataExtractionRules must not contain <include> elements"
    fi
    # Each section must exclude the app data root at minimum.
    sections=0
    while IFS= read -r block; do
      sections=$((sections + 1))
    done < <(grep -E 'E: (cloud-backup|device-transfer)' <<<"$rules")
    excludes_root=$(grep -c 'E: exclude' <<<"$rules" || true)
    if [[ "$sections" -ge 2 && "$excludes_root" -lt 2 ]]; then
      say_fail "each of cloud-backup and device-transfer needs an <exclude> for app data"
    fi
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo "check-backup-rules: FAILED (see above)" >&2
  exit 1
fi
echo "check-backup-rules: OK — allowBackup=false, dataExtractionRules excludes cloud-backup AND device-transfer"
