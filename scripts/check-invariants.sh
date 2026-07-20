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

# --- 4. Relay zero-logging / no-filesystem policy (INV-2, INV-3) -------------
# The relay must not log and must not touch the filesystem. Startup-only
# stderr is allowed on ONE line in main.rs (the "listening" string and usage
# errors); everything else is forbidden in tezca-relay/src.
if [ -d tezca-relay/src ]; then
  log_hits=$(grep -rnE 'tracing::|log::(trace|debug|info|warn|error)|println!|eprint(ln)?!' \
      tezca-relay/src 2>/dev/null \
    | grep -v 'src/main.rs:' || true)
  if [ -n "$log_hits" ]; then
    echo "INV-2 violation: logging/print statements outside the relay startup path:"
    echo "$log_hits"
    fail=1
  fi
  # Filesystem access from the relay (mailboxes are RAM-only, INV-3). The
  # /proc reads live in the TEST harness, not src, so this stays clean.
  fs_hits=$(grep -rnE 'std::fs::|File::(open|create)|OpenOptions|fs::write|fs::read' \
      tezca-relay/src 2>/dev/null || true)
  if [ -n "$fs_hits" ]; then
    echo "INV-3 violation: filesystem access in relay source:"
    echo "$fs_hits"
    fail=1
  fi
fi

# --- 5. Release carries no debug test anchors (4b-2, frozen design §9) --------
# The CI relay-trust path (a network-security-config permitting cleartext /
# trusting a test CA) is DEBUG-ONLY: it must live under src/debug and must not
# be referenced by the main manifest or any release source. A release APK that
# trusted a test anchor would be a live MITM surface.
android_app=titlan-android/app
# 5a. The network-security-config resource exists ONLY under src/debug.
nsc_stray=$(list_files \
  | grep -E "^${android_app}/src/.*/res/xml/network_security_config\.xml$" \
  | grep -vE "^${android_app}/src/debug/" || true)
if [ -n "$nsc_stray" ]; then
  echo "test anchor outside src/debug (network_security_config.xml must be debug-only):"
  echo "$nsc_stray"
  fail=1
fi
# 5b. The main manifest never wires networkSecurityConfig (only the debug
#     overlay may), and cleartext permission never appears outside src/debug.
if [ -f "${android_app}/src/main/AndroidManifest.xml" ] \
   && grep -q 'networkSecurityConfig' "${android_app}/src/main/AndroidManifest.xml"; then
  echo "main manifest references networkSecurityConfig — must be a debug-only overlay"
  fail=1
fi
cleartext_stray=$(list_files \
  | grep -E "^${android_app}/src/" \
  | grep -vE "^${android_app}/src/debug/" \
  | xargs -r grep -l -F 'cleartextTrafficPermitted="true"' 2>/dev/null || true)
if [ -n "$cleartext_stray" ]; then
  echo "cleartext traffic permitted outside src/debug (test anchor leaked into release):"
  echo "$cleartext_stray"
  fail=1
fi
# 5c. The Rust-side CI relay trust anchor (tezca-core `test-relay-anchor`,
#     maintainer-ratified 4b-2) must never become a default feature — default
#     features would put the anchor code into every consumer, release included.
if grep -E '^default *=' tezca-core/Cargo.toml | grep -qF 'test-relay-anchor'; then
  echo "test-relay-anchor is a DEFAULT feature of tezca-core — release .so would carry the anchor"
  fail=1
fi
# 5d. The Android build enables the anchor feature ONLY in the debug cargo
#     task. Positive control first: if the debug task stops naming the feature
#     (rename/refactor), this check must fail loudly rather than pass vacuously.
gradle_build="${android_app}/build.gradle.kts"
debug_block=$(awk '/^val cargoNdkBuildDebug/{f=1} f{print} f&&/^\}$/{exit}' "$gradle_build")
release_block=$(awk '/^val cargoNdkBuildRelease/{f=1} f{print} f&&/^\}$/{exit}' "$gradle_build")
if ! printf '%s' "$debug_block" | grep -qF 'test-relay-anchor'; then
  echo "positive control failed: cargoNdkBuildDebug no longer enables test-relay-anchor (check 5d is blind)"
  fail=1
fi
if printf '%s' "$release_block" | grep -qF 'test-relay-anchor'; then
  echo "cargoNdkBuildRelease enables test-relay-anchor — release .so would carry the anchor"
  fail=1
fi
if [ -z "$release_block" ]; then
  echo "cargoNdkBuildRelease task not found in ${gradle_build} (check 5d cannot verify the release build)"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "Invariant checks FAILED."
  exit 1
fi
echo "All invariant checks passed (SPDX headers, applicationId single-source, A11 naming, relay zero-logging/no-fs, release no-test-anchors)."
