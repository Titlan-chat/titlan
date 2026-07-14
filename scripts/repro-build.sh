#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Oculux Technologies LLC
#
# Reproducible-build check (work order §6 Phase 1, §7).
#
# Builds the release artifacts TWICE, each time from a fresh copy of the
# source tree at a canonical absolute path, and fails if any artifact hash
# differs between the two builds:
#   - tezca-relay release binary (Rust, --locked, path prefixes remapped)
#   - unsigned release APK (Gradle, locked dependencies)
#
# Hashes are comparable across machines only when built from the same
# canonical path with the same pinned toolchains — see docs/build.md.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_ROOT="${REPRO_BUILD_ROOT:-/tmp/tezca-repro}"
REPORT="${REPRO_REPORT:-$REPO/repro-report.txt}"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

RELAY_BIN="target/release/tezca-relay"
APK="titlan-android/app/build/outputs/apk/release/app-release-unsigned.apk"

copy_tree() {
  rm -rf "$BUILD_ROOT"
  mkdir -p "$BUILD_ROOT"
  rsync -a \
    --exclude '.git' --exclude 'target' --exclude '.gradle' \
    --exclude 'build' --exclude '.kotlin' --exclude 'local.properties' \
    "$REPO"/ "$BUILD_ROOT"/
}

build_once() {
  copy_tree
  (
    cd "$BUILD_ROOT"
    export CARGO_INCREMENTAL=0
    # Remap embedded path strings to canonical roots so the binary carries no
    # host-specific paths (also see [profile.release] strip in Cargo.toml).
    export RUSTFLAGS="--remap-path-prefix=$BUILD_ROOT=/build --remap-path-prefix=$CARGO_HOME_DIR=/cargo"
    cargo build --release --locked -p tezca-relay
    cd titlan-android
    ./gradlew --no-daemon -q clean :app:assembleRelease
  )
}

hash_of() { sha256sum "$BUILD_ROOT/$1" | cut -d' ' -f1; }

echo "== Reproducible-build check: pass 1/2 =="
build_once
relay_1=$(hash_of "$RELAY_BIN")
apk_1=$(hash_of "$APK")

echo "== Reproducible-build check: pass 2/2 =="
build_once
relay_2=$(hash_of "$RELAY_BIN")
apk_2=$(hash_of "$APK")

rm -rf "$BUILD_ROOT"

status=PASS
[ "$relay_1" = "$relay_2" ] || status=FAIL
[ "$apk_1" = "$apk_2" ] || status=FAIL

{
  echo "Titlan reproducibility report"
  echo "generated-by: scripts/repro-build.sh"
  echo "build-root:   $BUILD_ROOT"
  echo "rustc:        $(rustc --version)"
  echo "cargo:        $(cargo --version)"
  echo "jdk:          $(java -version 2>&1 | head -1)"
  echo
  echo "artifact: $RELAY_BIN"
  echo "  build-1 sha256: $relay_1"
  echo "  build-2 sha256: $relay_2"
  echo "artifact: $APK"
  echo "  build-1 sha256: $apk_1"
  echo "  build-2 sha256: $apk_2"
  echo
  echo "result: $status"
} | tee "$REPORT"

[ "$status" = "PASS" ]
