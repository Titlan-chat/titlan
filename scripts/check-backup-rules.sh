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

# In the BINARY manifest the attribute is a numeric resource reference
# (e.g. `dataExtractionRules(0x0101063e)=@0x7f0c0000`); resolve the id to
# its file path via the APK's resource table.
ref_id="$(grep -o 'dataExtractionRules([^)]*)=@0x[0-9a-f]*' <<<"$manifest" | grep -o '0x[0-9a-f]*$' | head -1)"
if [[ -z "$ref_id" ]]; then
  say_fail "merged manifest carries no android:dataExtractionRules reference"
else
  rules_file="$("$AAPT2" dump resources "$APK" | grep -A2 "resource $ref_id " \
    | grep -o 'res/[^ ]*\.xml' | head -1)"
  if [[ -z "$rules_file" ]]; then
    say_fail "resource $ref_id not resolvable to a file in the APK resource table"
    rules_file="__unresolved__"
  fi
  rules="$("$AAPT2" dump xmltree --file "$rules_file" "$APK" 2>/dev/null)"
  if [[ -z "$rules" ]]; then
    say_fail "dataExtractionRules resource $rules_file not found in APK"
  else
    # PER-SECTION verification (maintainer-directed, green checklist item 1):
    # each of <cloud-backup> and <device-transfer> must carry its OWN
    # <exclude> — a global count would accept two excludes in one section.
    for section in cloud-backup device-transfer; do
      if ! grep -q "E: $section" <<<"$rules"; then
        say_fail "dataExtractionRules missing <$section> section"
        continue
      fi
      section_excludes=$(awk -v sec="$section" '
        /E: (cloud-backup|device-transfer)/ { insec = ($0 ~ "E: " sec) }
        insec && /E: exclude/ { n++ }
        END { print n + 0 }
      ' <<<"$rules")
      if [[ "$section_excludes" -lt 1 ]]; then
        say_fail "<$section> carries no <exclude> of its own"
      fi
    done
    if grep -q 'E: include' <<<"$rules"; then
      say_fail "dataExtractionRules must not contain <include> elements"
    fi
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo "check-backup-rules: FAILED (see above)" >&2
  exit 1
fi
echo "check-backup-rules: OK — allowBackup=false, dataExtractionRules excludes cloud-backup AND device-transfer"
