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
# SOURCE_DATE_EPOCH pinned to HEAD's commit time: SQLCipher's vendored
# OpenSSL (openssl-sys under libsqlite3-sys) bakes an OPENSSL_BUILT_ON
# banner into libtezca_core.so; without this pin the two passes differ by
# wall clock (runs 29612174509/29620310696). Both passes build the same
# commit, so both get the same value. Computed here because the build tree
# copies exclude .git.
export SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct)"
BUILD_ROOT="${REPRO_BUILD_ROOT:-/tmp/tezca-repro}"
REPORT="${REPRO_REPORT:-$REPO/repro-report.txt}"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"

RELAY_BIN="target/release/tezca-relay"
APK="titlan-android/app/build/outputs/apk/release/app-release-unsigned.apk"
# Mismatch evidence (diagnostic only): both APKs are preserved here on
# failure so per-entry divergence is inspectable; removed again on PASS.
# The ci.yml repro job uploads this directory alongside the report.
PRESERVE_DIR="${REPRO_PRESERVE_DIR:-$REPO/repro-mismatch}"

copy_tree() {
  rm -rf "$BUILD_ROOT"
  mkdir -p "$BUILD_ROOT"
  rsync -a \
    --exclude '.git' --exclude 'target' --exclude '.gradle' \
    --exclude 'build' --exclude '.kotlin' --exclude 'local.properties' \
    --exclude 'repro-mismatch' \
    "$REPO"/ "$BUILD_ROOT"/
  # ^ repro-mismatch only exists mid-run (pass-1 evidence); excluding it
  #   keeps build-2's input tree identical to build-1's.
}

# Diagnostic per-entry APK comparison (python3 zipfile). Prints, for both
# archives: entry name, size, CRC-32, sha256 of decompressed content; then
# a DIFFERING ENTRIES section naming every entry whose content or metadata
# (size/CRC/mtime) differs, and entries present in only one archive.
apk_entry_report() {
  python3 - "$1" "$2" <<'PY'
import hashlib, sys, zipfile

def load(path):
    entries = {}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            entries[info.filename] = {
                "size": info.file_size,
                "crc": f"{info.CRC:08x}",
                "mtime": "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time,
                "sha256": hashlib.sha256(z.read(info.filename)).hexdigest(),
            }
    return entries

a_path, b_path = sys.argv[1], sys.argv[2]
a, b = load(a_path), load(b_path)

for label, entries in (("build-1", a), ("build-2", b)):
    print(f"per-entry listing ({label}):")
    print(f"  {'entry':60} {'size':>10} {'crc32':>8}  sha256")
    for name in sorted(entries):
        e = entries[name]
        print(f"  {name:60} {e['size']:>10} {e['crc']:>8}  {e['sha256']}")
    print()

print("DIFFERING ENTRIES:")
diffs = 0
for name in sorted(set(a) | set(b)):
    if name not in a:
        print(f"  {name} — only in build-2"); diffs += 1; continue
    if name not in b:
        print(f"  {name} — only in build-1"); diffs += 1; continue
    ea, eb = a[name], b[name]
    reasons = []
    if ea["sha256"] != eb["sha256"]:
        reasons.append(f"content sha256 {ea['sha256'][:12]}… != {eb['sha256'][:12]}…")
    if ea["size"] != eb["size"]:
        reasons.append(f"size {ea['size']} != {eb['size']}")
    if ea["crc"] != eb["crc"]:
        reasons.append(f"crc32 {ea['crc']} != {eb['crc']}")
    if ea["mtime"] != eb["mtime"]:
        reasons.append(f"mtime {ea['mtime']} != {eb['mtime']}")
    if reasons:
        print(f"  {name} — " + "; ".join(reasons)); diffs += 1
if diffs == 0:
    print("  (none — archives identical at entry level)")
PY
}

# Diagnostic-only entry point: compare two APK/zip files and exit.
if [ "${1:-}" = "--diff-apks" ]; then
  apk_entry_report "$2" "$3"
  exit 0
fi

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
# Preserve build-1's APK before copy_tree destroys $BUILD_ROOT for pass 2
# (evidence only; deleted again on PASS).
rm -rf "$PRESERVE_DIR" && mkdir -p "$PRESERVE_DIR"
cp "$BUILD_ROOT/$APK" "$PRESERVE_DIR/app-release-unsigned.build-1.apk"

echo "== Reproducible-build check: pass 2/2 =="
build_once
relay_2=$(hash_of "$RELAY_BIN")
apk_2=$(hash_of "$APK")
cp "$BUILD_ROOT/$APK" "$PRESERVE_DIR/app-release-unsigned.build-2.apk"

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
  if [ "$apk_1" != "$apk_2" ]; then
    echo
    echo "== APK mismatch diagnostics (per-entry; both APKs preserved in $PRESERVE_DIR) =="
    apk_entry_report \
      "$PRESERVE_DIR/app-release-unsigned.build-1.apk" \
      "$PRESERVE_DIR/app-release-unsigned.build-2.apk"
  fi
} | tee "$REPORT"

if [ "$apk_1" = "$apk_2" ]; then
  rm -rf "$PRESERVE_DIR"
fi

[ "$status" = "PASS" ]
