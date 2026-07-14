#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Oculux Technologies LLC
#
# CI guards for locked decisions and Phase 1 acceptance criteria:
#   1. A10    — every source/config file carries an SPDX-License-Identifier header
#   2. §10.4  — the applicationId string appears ONLY in gradle.properties
#   3. A11    — reserved company/platform brand strings never appear in Android
#               user-facing resources (a future About screen is exempt via
#               resource names prefixed `about_`)
#
# Run from anywhere: ./scripts/check-invariants.sh
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

list_files() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files
  else
    find . -type f \
      -not -path './.git/*' -not -path './target/*' -not -path '*/build/*' \
      -not -path '*/.gradle/*' -not -path '*/.kotlin/*' | sed 's|^\./||'
  fi
}

# --- 1. SPDX headers (A10) --------------------------------------------------
# Exempt: license texts, generated lockfiles, and the Gradle wrapper (generated,
# third-party; regenerating it would clobber a hand-added header).
spdx_missing=0
while IFS= read -r f; do
  case "$f" in
    LICENSE*|*/LICENSE|Cargo.lock|*/gradle.lockfile|*gradle/wrapper/*|*/gradlew|*/gradlew.bat) continue ;;
  esac
  case "$f" in
    *.rs|*.kt|*.kts|*.sh|*.toml|*.yml|*.yaml|*.xml|*.md|*.properties|.gitignore|.editorconfig)
      if ! head -5 "$f" | grep -q 'SPDX-License-Identifier:'; then
        echo "MISSING SPDX header: $f"
        spdx_missing=1
      fi
      ;;
  esac
done < <(list_files)
[ "$spdx_missing" -eq 0 ] || fail=1

# --- 2. applicationId single-source (§6 Phase 1, §10.4) ----------------------
# Read the id from its one legitimate home so this script never hardcodes it.
app_id=$(grep -oP '^TITLAN_APPLICATION_ID=\K.*' titlan-android/gradle.properties)
if [ -z "$app_id" ]; then
  echo "TITLAN_APPLICATION_ID missing from titlan-android/gradle.properties"
  fail=1
else
  id_hits=$(list_files | grep -v '^titlan-android/gradle\.properties$' \
    | xargs -r grep -l -F "$app_id" 2>/dev/null || true)
  if [ -n "$id_hits" ]; then
    echo "applicationId '$app_id' referenced outside gradle.properties (must be single-sourced):"
    echo "$id_hits"
    fail=1
  fi
fi

# --- 3. A11 naming in user-facing Android resources --------------------------
# SPDX copyright lines are legal metadata, not UI, and are exempt.
naming_hits=$(grep -rniE 'oculux|tezca' \
    titlan-android/app/src/main/res \
    titlan-android/app/src/main/AndroidManifest.xml 2>/dev/null \
  | grep -v 'SPDX-FileCopyrightText' \
  | grep -vi 'name="about_' || true)
if [ -n "$naming_hits" ]; then
  echo "A11 violation: reserved brand strings in user-facing Android resources:"
  echo "$naming_hits"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "Invariant checks FAILED."
  exit 1
fi
echo "All invariant checks passed (SPDX headers, applicationId single-source, A11 naming)."
