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
    # Cloudflare Pages config; comment support unspecified upstream
    site/_headers) continue ;;
  esac
  case "$f" in
    *.rs|*.kt|*.kts|*.sh|*.toml|*.yml|*.yaml|*.xml|*.md|*.properties|*.html|*.css|.gitignore|.editorconfig)
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
# 5e. Artifact-level anchor split (automated 2026-07-21, was a manual check):
#     when the per-variant .so artifacts exist — the CI android job re-runs
#     this script after assembleDebug + assembleRelease; the early
#     repo-invariants job prints the skip note because nothing is built yet —
#     the anchor env-var string must be PRESENT in every debug .so (positive
#     control: proves the scan can see it) and ABSENT from every release .so.
#     grep -a: these are binary scans by design (grep otherwise declines
#     binary payloads and would pass vacuously).
anchor_str='TEZCA_TEST_RELAY_PIN'
so_root="${android_app}/build/rustJniLibs"
scanned_debug=0
scanned_release=0
for so in "$so_root"/debug/*/libtezca_core.so; do
  [ -f "$so" ] || continue
  scanned_debug=1
  if ! grep -aq "$anchor_str" "$so"; then
    echo "positive control failed: anchor string ABSENT from debug .so ($so) — 5e cannot prove release absence"
    fail=1
  fi
done
for so in "$so_root"/release/*/libtezca_core.so; do
  [ -f "$so" ] || continue
  scanned_release=1
  if grep -aq "$anchor_str" "$so"; then
    echo "release .so carries the test-anchor string ($so) — the anchor leaked into release"
    fail=1
  fi
done
if [ "$scanned_debug" -eq 0 ] || [ "$scanned_release" -eq 0 ]; then
  echo "note: 5e artifact scan skipped (debug=$scanned_debug release=$scanned_release — .so not built in this run)"
fi

# --- 4b-2 FFI-bisect probe emissions (pinned by §10) --------------------------
# Defined ahead of §6/§9 because their stray-log filters must exclude exactly
# these pinned lines and nothing else.
decode_probe_emit='Log.i(DECODE_PROBE_TAG, "sha256=$hex len=${bytes.size}")'
ffi_probe_emit='Log.i(FFI_PROBE_TAG, "sha256=$hex len=${bytes.size}")'
ffi_error_emit='Log.i(FFI_ERROR_TAG, "variant=${t.javaClass.simpleName} msgSha256=$msgHex msgLen=${msg.length}")'

# --- 6. Debug delivery sentinel — exists, fixed-literal, debug-gated (§9d) ----
# Checklist (f) t1 marker (maintainer-ratified F1): ONE debug-only logcat line
# in CoreClient.kt at the ack-after-persist delivery point. Hygiene is proven
# statically: the emission's arguments are exactly the two pinned constants,
# both pure literals with no identifier-shaped content (no digits, no format
# specifier, no interpolation), and no other logcat call exists in the file.
# scripts/device-doze-latency.sh waits on the same literals for t1, so the
# dual-sourced pair is asserted equal here.
core_client="titlan-android/app/src/main/kotlin/app/titlan/core/CoreClient.kt"
doze_script="scripts/device-doze-latency.sh"
sentinel_tag='TitlanDelivery'
sentinel_text='chat delivery persisted'
if ! grep -qF "DELIVERY_SENTINEL_TAG = \"$sentinel_tag\"" "$core_client"; then
  echo "delivery sentinel: DELIVERY_SENTINEL_TAG literal missing/changed in $core_client"
  fail=1
fi
if ! grep -qF "DELIVERY_SENTINEL_TEXT = \"$sentinel_text\"" "$core_client"; then
  echo "delivery sentinel: DELIVERY_SENTINEL_TEXT literal missing/changed in $core_client"
  fail=1
fi
sentinel_call='if (BuildConfig.DEBUG) Log.i(DELIVERY_SENTINEL_TAG, DELIVERY_SENTINEL_TEXT)'
if ! grep -qF "$sentinel_call" "$core_client"; then
  echo "delivery sentinel: debug-gated fixed-literal emission missing from $core_client"
  fail=1
fi
stray_logs=$(grep -n 'Log\.' "$core_client" | grep -vF "$sentinel_call" \
  | grep -vF 'import android.util.Log' \
  | grep -vF "$ffi_probe_emit" | grep -vF "$ffi_error_emit" || true)
if [ -n "$stray_logs" ]; then
  echo "delivery sentinel: CoreClient.kt logs beyond the pinned sentinel + §10 probe lines:"
  echo "$stray_logs"
  fail=1
fi
case "${sentinel_tag}${sentinel_text}" in
  *[0-9\$%\{]*)
    echo "delivery sentinel: pinned literals must stay identifier-free (no digits/format/interpolation)"
    fail=1 ;;
esac
if ! grep -qF "$sentinel_tag" "$doze_script" || ! grep -qF "$sentinel_text" "$doze_script"; then
  echo "delivery sentinel: $doze_script does not wait on the pinned tag+text (t1 leg unwired)"
  fail=1
fi

# --- 7. Debug-only RELAY_URL override; release BuildConfig untouched ----------
# Checklist (f) points the DEBUG build at a LAN relay
# (-PtitlanDebugRelayUrl=wss://<host>:<port>, maintainer-ratified F3); the
# release BuildConfig must remain exactly the RFC 2606 placeholder with no
# property read anywhere near it. Positive control first: if the debug block
# stops reading the property (rename/refactor), this check must fail loudly
# rather than pass vacuously.
bt_debug=$(awk '/^        debug \{/{f=1} f{print} f&&/^        \}/{exit}' "$gradle_build")
bt_release=$(awk '/^        release \{/{f=1} f{print} f&&/^        \}/{exit}' "$gradle_build")
if [ -z "$bt_release" ]; then
  echo "release buildType block not found in ${gradle_build} (check 7 cannot verify release)"
  fail=1
fi
if ! printf '%s' "$bt_debug" | grep -qF 'titlanDebugRelayUrl'; then
  echo "positive control failed: debug buildType does not read titlanDebugRelayUrl (check 7 is blind)"
  fail=1
fi
if ! printf '%s' "$bt_debug" | grep -qF 'wss://10.0.2.2:8443'; then
  echo "debug RELAY_URL fallback changed: emulator default wss://10.0.2.2:8443 must remain"
  fail=1
fi
if printf '%s' "$bt_release" | grep -qE 'RELAY_URL|titlanDebugRelayUrl'; then
  echo "release buildType touches RELAY_URL / titlanDebugRelayUrl — release BuildConfig must stay untouched"
  fail=1
fi
if ! grep -qF 'buildConfigField("String", "RELAY_URL", "\"wss://relay.invalid\"")' "$gradle_build"; then
  echo "defaultConfig RELAY_URL is no longer the literal release placeholder (wss://relay.invalid)"
  fail=1
fi

# --- 8. Debug TLS pin bridge — exists, gated, ordered, single-sourced ---------
# Checklist (f) device-side TLS trust (maintainer-ratified FLAG-A option a):
# TitlanApp.onCreate exports the debug.titlan.relay-pin system property into
# TEZCA_TEST_RELAY_PIN BEFORE any core touch, debug builds only. Pinned like
# §6: exact literal shapes, single-file single-sourcing across src/main, and
# ordering asserted statically by line order — onCreate is a single linear
# body, so "the gate line's number precedes the first AppCore reference's
# line number" IS the execution order.
titlan_app="titlan-android/app/src/main/kotlin/app/titlan/TitlanApp.kt"
app_main="titlan-android/app/src/main"
pin_prop='debug.titlan.relay-pin'
pin_env='TEZCA_TEST_RELAY_PIN'
bridge_gate='if (BuildConfig.DEBUG) exportDebugRelayPin()'
# 8a. Single-sourced literals: the property name lives in ONE pinned const,
#     the env var name in ONE pinned Os.setenv call.
if ! grep -qF "DEBUG_RELAY_PIN_PROP = \"$pin_prop\"" "$titlan_app"; then
  echo "pin bridge: DEBUG_RELAY_PIN_PROP literal missing/changed in $titlan_app"
  fail=1
fi
if ! grep -qF "Os.setenv(\"$pin_env\", pin, true)" "$titlan_app"; then
  echo "pin bridge: Os.setenv(\"$pin_env\", ...) call missing/changed in $titlan_app"
  fail=1
fi
# 8b. The bridge is a single debug-gated statement.
if ! grep -qF "$bridge_gate" "$titlan_app"; then
  echo "pin bridge: debug-gated bridge statement missing from $titlan_app"
  fail=1
fi
# 8c. Ordering: the gate precedes any core initialization in onCreate.
gate_line=$(grep -nF "$bridge_gate" "$titlan_app" | head -n 1 | cut -d: -f1 || true)
core_line=$(grep -nF 'AppCore.init' "$titlan_app" | head -n 1 | cut -d: -f1 || true)
if [ -z "$gate_line" ] || [ -z "$core_line" ] || [ "$gate_line" -ge "$core_line" ]; then
  echo "pin bridge: bridge statement does not precede AppCore.init in $titlan_app (gate=$gate_line core=$core_line)"
  fail=1
fi
# 8d. Exactly one reader of the property and one setter of the env var in the
#     app (src/main) — TitlanApp.kt itself. (TitlanTestRunner in the
#     androidTest harness sets the same env var by design: it is the
#     instrumentation-side bridge and is never packaged in the app APK.)
prop_files=$(grep -rlF "$pin_prop" "$app_main" || true)
env_files=$(grep -rlF "$pin_env" "$app_main" || true)
if [ "$prop_files" != "$titlan_app" ]; then
  echo "pin bridge: $pin_prop must be read by exactly $titlan_app; found:"
  echo "${prop_files:-<nowhere>}"
  fail=1
fi
if [ "$env_files" != "$titlan_app" ]; then
  echo "pin bridge: $pin_env must be set by exactly $titlan_app (src/main); found:"
  echo "${env_files:-<nowhere>}"
  fail=1
fi

# --- 9. Scan-input hash probe — debug-gated at decodeLink ENTRY, hash+len ONLY (4b-2) ---
# 4b-2 measurement instrument (maintainer-ratified receipt 4b2-WO-scan-hash-probe):
# ONE debug-only logcat line at the entry of QrCodec.decodeLink — the single point
# BOTH scan transports funnel through (the camera path wraps the ZXing-decoded text
# back into a link, the link-paste path passes the trimmed field) — carrying ONLY
# the SHA-256 hex of the received string's UTF-8 bytes and its length in chars. No
# payload content and no prefix of it is ever emitted (INV-1); the hash is one-way
# and the length is a bare count. Pinned like §6/§8: fixed-literal tag + emission,
# single-file scope, and gate-before-decode asserted by line order.
qr_codec="titlan-android/app/src/main/kotlin/app/titlan/pairing/QrCodec.kt"
scan_probe_tag='TitlanScanProbe'
scan_probe_gate='if (BuildConfig.DEBUG) probeScanInput(link)'
scan_probe_emit='Log.i(SCAN_PROBE_TAG, "sha256=$hex len=${link.length}")'
# 9a. Single-sourced tag literal.
if ! grep -qF "SCAN_PROBE_TAG = \"$scan_probe_tag\"" "$qr_codec"; then
  echo "scan probe: SCAN_PROBE_TAG literal missing/changed in $qr_codec"
  fail=1
fi
# 9b. The fingerprint is SHA-256 over the FULL received string's UTF-8 bytes — the
#     whole link, so the emitted hash is of exactly what decodeLink got, never a
#     prefix. Two single-line pins: the digest algorithm and its input.
if ! grep -qF 'MessageDigest.getInstance("SHA-256")' "$qr_codec"; then
  echo "scan probe: SHA-256 digest construction missing/changed in $qr_codec"
  fail=1
fi
if ! grep -qF '.digest(link.toByteArray(Charsets.UTF_8))' "$qr_codec"; then
  echo "scan probe: hash is not taken over the full received string's UTF-8 bytes in $qr_codec"
  fail=1
fi
# 9c. The SOLE emission is the pinned hash+length line; its only dynamic parts are
#     the hash hex and link.length, so no payload byte can leak into logcat.
if ! grep -qF "$scan_probe_emit" "$qr_codec"; then
  echo "scan probe: pinned hash+length emission missing/changed in $qr_codec"
  fail=1
fi
# 9d. Debug-gated, and positioned at decodeLink ENTRY: the gate line precedes the
#     require() that begins the decode, so the probe fingerprints the input as
#     received — before any validation or transformation.
if ! grep -qF "$scan_probe_gate" "$qr_codec"; then
  echo "scan probe: debug-gated probe call missing from $qr_codec"
  fail=1
fi
scan_gate_line=$(grep -nF "$scan_probe_gate" "$qr_codec" | head -n 1 | cut -d: -f1 || true)
scan_require_line=$(grep -nF 'require(link.startsWith(LINK_PREFIX))' "$qr_codec" | head -n 1 | cut -d: -f1 || true)
if [ -z "$scan_gate_line" ] || [ -z "$scan_require_line" ] || [ "$scan_gate_line" -ge "$scan_require_line" ]; then
  echo "scan probe: gate does not precede decodeLink's require in $qr_codec (gate=$scan_gate_line require=$scan_require_line)"
  fail=1
fi
# 9e. No OTHER logcat emitter in the file — only this probe and §10a's.
scan_stray=$(grep -n 'Log\.' "$qr_codec" | grep -vF "$scan_probe_emit" \
  | grep -vF "$decode_probe_emit" | grep -vF 'import android.util.Log' || true)
if [ -n "$scan_stray" ]; then
  echo "scan probe: $qr_codec logs beyond the pinned §9/§10a hash+length lines:"
  echo "$scan_stray"
  fail=1
fi

# --- 10. FFI-bisect probes — decode result + pairing FFI seam (4b-2) ----------
# 4b-2 measurement instruments (maintainer-ratified receipt 4b2-WO-ffi-bisect).
# Given §9's proof of byte-perfect delivery INTO decodeLink, three debug-only
# probes partition the remaining on-device window:
#   10a  decode result — QrCodec.decodeLink fingerprints the DECODED offer
#        bytes between decode and return, so the on-device android.util.Base64
#        output diffs directly against the host fixture's decoded-bytes hash.
#   10b  FFI entry — CoreClient.kt fingerprints EXACTLY the bytes handed to
#        ffi.beginPairingFromOffer, immediately before the uniffi crossing.
#   10c  FFI error — on failure, the TitlanException variant (class simple
#        name) plus the SHA-256 hex and length of its message, rethrown
#        unchanged. The message itself never reaches logcat: it may embed
#        offer-derived content (INV-1); the hash matches against the closed
#        set of core error literals host-side.
# Hygiene as §6/§8/§9: fixed-literal tags and emissions whose only dynamic
# parts are hash hex, bare counts, and the variant identifier; debug-gated;
# the §6/§9e stray-log filters exclude exactly these pinned emissions.

# 10a. Decode-result probe in QrCodec.kt.
decode_probe_tag='TitlanDecodeProbe'
decode_probe_gate='if (BuildConfig.DEBUG) probeDecodedResult(bytes)'
if ! grep -qF "DECODE_PROBE_TAG = \"$decode_probe_tag\"" "$qr_codec"; then
  echo "ffi-bisect: DECODE_PROBE_TAG literal missing/changed in $qr_codec"
  fail=1
fi
if ! grep -qF "$decode_probe_emit" "$qr_codec"; then
  echo "ffi-bisect: pinned decode-result emission missing/changed in $qr_codec"
  fail=1
fi
if ! grep -qF "$decode_probe_gate" "$qr_codec"; then
  echo "ffi-bisect: debug-gated decode-result probe call missing from $qr_codec"
  fail=1
fi
# Positioned on the RESULT: after the require() that begins the decode (§9d's
# anchor) and before decodeLink's return, so it hashes what decodeLink hands
# back — the decoded binary offer, nothing earlier and nothing later.
decode_gate_line=$(grep -nF "$decode_probe_gate" "$qr_codec" | head -n 1 | cut -d: -f1 || true)
decode_return_line=$(grep -nF 'return bytes' "$qr_codec" | head -n 1 | cut -d: -f1 || true)
if [ -z "$decode_gate_line" ] || [ -z "$scan_require_line" ] || [ -z "$decode_return_line" ] \
   || [ "$decode_gate_line" -le "$scan_require_line" ] || [ "$decode_gate_line" -ge "$decode_return_line" ]; then
  echo "ffi-bisect: decode-result probe not between decode and return in $qr_codec (require=$scan_require_line gate=$decode_gate_line return=$decode_return_line)"
  fail=1
fi

# 10b. FFI-entry probe in CoreClient.kt — the last Kotlin statement before the
#      generated binding runs.
ffi_probe_tag='TitlanFfiProbe'
ffi_probe_gate='if (BuildConfig.DEBUG) probeFfiInput(offerBytes)'
ffi_call='ffi.beginPairingFromOffer(offerBytes)'
if ! grep -qF "FFI_PROBE_TAG = \"$ffi_probe_tag\"" "$core_client"; then
  echo "ffi-bisect: FFI_PROBE_TAG literal missing/changed in $core_client"
  fail=1
fi
if ! grep -qF "$ffi_probe_emit" "$core_client"; then
  echo "ffi-bisect: pinned FFI-entry emission missing/changed in $core_client"
  fail=1
fi
if ! grep -qF "$ffi_probe_gate" "$core_client"; then
  echo "ffi-bisect: debug-gated FFI-entry probe call missing from $core_client"
  fail=1
fi
ffi_gate_line=$(grep -nF "$ffi_probe_gate" "$core_client" | head -n 1 | cut -d: -f1 || true)
ffi_call_line=$(grep -nF "$ffi_call" "$core_client" | head -n 1 | cut -d: -f1 || true)
if [ -z "$ffi_gate_line" ] || [ -z "$ffi_call_line" ] || [ "$ffi_gate_line" -ge "$ffi_call_line" ]; then
  echo "ffi-bisect: FFI-entry probe does not precede the uniffi pairing call in $core_client (gate=$ffi_gate_line call=$ffi_call_line)"
  fail=1
fi

# 10c. FFI-error probe in CoreClient.kt: fires only when the crossing throws,
#      after the call site, and the exception is rethrown unchanged.
ffi_error_tag='TitlanFfiError'
ffi_error_gate='if (BuildConfig.DEBUG) probeFfiError(t)'
if ! grep -qF "FFI_ERROR_TAG = \"$ffi_error_tag\"" "$core_client"; then
  echo "ffi-bisect: FFI_ERROR_TAG literal missing/changed in $core_client"
  fail=1
fi
if ! grep -qF "$ffi_error_emit" "$core_client"; then
  echo "ffi-bisect: pinned FFI-error emission missing/changed in $core_client"
  fail=1
fi
if ! grep -qF "$ffi_error_gate" "$core_client"; then
  echo "ffi-bisect: debug-gated FFI-error probe call missing from $core_client"
  fail=1
fi
ffi_err_line=$(grep -nF "$ffi_error_gate" "$core_client" | head -n 1 | cut -d: -f1 || true)
ffi_throw_line=$(grep -nF 'throw t' "$core_client" | head -n 1 | cut -d: -f1 || true)
if [ -z "$ffi_err_line" ] || [ -z "$ffi_throw_line" ] || [ -z "$ffi_call_line" ] \
   || [ "$ffi_err_line" -le "$ffi_call_line" ] || [ "$ffi_err_line" -ge "$ffi_throw_line" ]; then
  echo "ffi-bisect: FFI-error probe must sit between the uniffi call and its rethrow in $core_client (call=$ffi_call_line probe=$ffi_err_line throw=$ffi_throw_line)"
  fail=1
fi

# --- 11. Relay semantic-blindness dep-graph (INV-8, freeze H4.1) --------------
# The relay must never acquire group, blob, directory, or any payload-semantic
# awareness (freeze H4.1); the mechanical leading indicator is dependency
# creep. tezca-relay's NORMAL dependency graph must exclude tezca-core: the
# acceptance harness may use it (dev-dependencies — exempted by `-e normal`),
# the relay binary may not. cargo being absent is a LOUD failure, not a skip —
# a silently skipped family is a blind family (the invariants CI job installs
# the pinned toolchain for exactly this).
if ! command -v cargo >/dev/null 2>&1; then
  echo "INV-8/H4.1: cargo unavailable — family 11 cannot assert tezca-relay's dependency graph (install the pinned Rust toolchain in this job)"
  fail=1
elif relay_tree=$(cargo tree -p tezca-relay -e normal --locked 2>/dev/null); then
  relay_core_hits=$(printf '%s\n' "$relay_tree" | grep -F 'tezca-core' || true)
  if [ -n "$relay_core_hits" ]; then
    echo "INV-8/H4.1 violation: tezca-core appears in tezca-relay's NORMAL dependency graph (envelope awareness is dev-scope only; the relay stays payload-blind):"
    echo "$relay_core_hits"
    fail=1
  fi
else
  echo "INV-8/H4.1: 'cargo tree -p tezca-relay -e normal --locked' failed — family 11 cannot assert tezca-relay's dependency graph (lockfile drift or toolchain breakage; failing loudly rather than skipping)"
  fail=1
fi

# --- 12. No crash-reporting SDK (INV-1) ---------------------------------------
# INV-1's "crash reports" clause: no crash-reporting/telemetry pathway may
# exist in the app. The gradle lockfile pins the full dependency universe (a
# transitive SDK cannot hide); build.gradle.kts catches a coordinate added but
# not yet locked. Token count must be ZERO in each (G1 ratified 2026-08-10).
crash_sdk_re='acra|crashlytics|sentry|bugsnag|firebase'
for f in titlan-android/app/gradle.lockfile titlan-android/app/build.gradle.kts; do
  if [ ! -f "$f" ]; then
    echo "INV-1 crash-SDK check: input $f is missing (family 12 cannot run)"
    fail=1
    continue
  fi
  crash_hits=$(grep -icE "$crash_sdk_re" "$f" || true)
  if [ "$crash_hits" -ne 0 ]; then
    echo "INV-1 violation: crash-reporting SDK token(s) in $f (matches for $crash_sdk_re):"
    grep -inE "$crash_sdk_re" "$f"
    fail=1
  fi
done

# --- 13. Relay unit hardening directives (INV-3) ------------------------------
# The relay-hardening CI job's `systemd-analyze verify` checks only that the
# unit is WELL-FORMED — deleting a hardening directive would still verify.
# Content-assert each INV-3 line verbatim (G2.i ratified 2026-08-10). TM-R8
# (5c-1, ratified 2026-08-27) extends this to EVERY hardening directive in the
# unit — all eighteen, exact values — so silent weakening of any directive
# fails here even though `systemd-analyze verify` would still pass.
relay_unit=deploy/tezca-relay.service
for directive in 'MemorySwapMax=0' 'LimitCORE=0' 'LimitMEMLOCK=infinity' \
                 'ProtectSystem=strict' 'ReadOnlyPaths=/' 'PrivateTmp=yes' \
                 'DynamicUser=yes' 'ProtectHome=yes' 'NoNewPrivileges=yes' \
                 'ProtectKernelTunables=yes' 'ProtectKernelModules=yes' \
                 'ProtectControlGroups=yes' \
                 'RestrictAddressFamilies=AF_INET AF_INET6' \
                 'RestrictNamespaces=yes' 'LockPersonality=yes' \
                 'MemoryDenyWriteExecute=yes' \
                 'SystemCallFilter=@system-service' \
                 'SystemCallArchitectures=native'; do
  if ! grep -qxF "$directive" "$relay_unit"; then
    echo "INV-3 violation: hardening directive '$directive' missing from $relay_unit"
    fail=1
  fi
done

# --- 14. Relay-URL single constant (INV-5) ------------------------------------
# The ONLY relay-URL literal in Rust lives in tezca-core/src/config.rs
# (DEFAULT_RELAY_URL); tezca-relay/src and src/main Kotlin carry none. The
# sweep matches URL-SHAPED literals only — `wss://`/`ws://` followed by an
# authority character — so the bare scheme-prefix parsing literals in
# relay_client/http.rs (`"ws://"`/`"wss://"` ahead of a closing quote) cannot
# false-positive. Comment lines are stripped (doc comments name the schemes);
# `#[cfg(test)]` modules are excluded by brace-tracking (test fixtures pin
# scratch URLs by design). Initial allowlist settled against the enumerated
# site list in report p5-5b2-inv-matrix §INV-5 (G3 ratified 2026-08-10).
url_re='wss?://[^"[:space:]]'
cfg_test_filter='
FNR == 1 { pending = 0; skip = 0; depth = 0 }
{
  if (skip) {
    depth += gsub(/{/, "{") - gsub(/}/, "}")
    if (depth <= 0) skip = 0
    next
  }
  if (pending && $0 ~ /(^|[[:space:]])mod[[:space:]]/) {
    d = gsub(/{/, "{") - gsub(/}/, "}")
    if (d > 0) { skip = 1; depth = d }
    pending = 0
    next
  }
  if ($0 ~ /^[[:space:]]*#\[cfg\(test\)\]/) { pending = 1; next }
  if (pending && $0 !~ /^[[:space:]]*#\[/ && $0 !~ /^[[:space:]]*$/) pending = 0
  printf "%s:%d:%s\n", FILENAME, FNR, $0
}'
rust_scope=$(list_files | grep -E '^(tezca-core|tezca-relay)/src/.*\.rs$' || true)
if [ -z "$rust_scope" ]; then
  echo "family 14: no Rust sources found under tezca-core/src or tezca-relay/src (sweep cannot run)"
  fail=1
else
  url_census=$(awk "$cfg_test_filter" $rust_scope \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
    | grep -E "$url_re" || true)
  # Positive control: the sweep must SEE the sanctioned constant, else the
  # pipeline itself has gone blind (awk/grep regression).
  if ! printf '%s\n' "$url_census" | grep -q '^tezca-core/src/config.rs:'; then
    echo "positive control failed: family 14 sweep cannot see DEFAULT_RELAY_URL in tezca-core/src/config.rs (check is blind)"
    fail=1
  fi
  url_hits=$(printf '%s\n' "$url_census" | grep -v '^tezca-core/src/config.rs:' || true)
  if [ -n "$url_hits" ]; then
    echo "INV-5 violation: relay-URL literal outside the single default-config constant (tezca-core/src/config.rs):"
    echo "$url_hits"
    fail=1
  fi
fi
# Kotlin (src/main only): zero URL literals — the two sanctioned Gradle
# literals (debug fallback + release placeholder) are family-7 territory.
kt_scope=$(list_files | grep -E '^titlan-android/app/src/main/.*\.kt$' || true)
if [ -n "$kt_scope" ]; then
  kt_url_hits=$(grep -nE "$url_re" $kt_scope /dev/null 2>/dev/null \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)
  if [ -n "$kt_url_hits" ]; then
    echo "INV-5 violation: relay-URL literal in src/main Kotlin (addresses come from BuildConfig/conversation config, never source literals):"
    echo "$kt_url_hits"
    fail=1
  fi
fi

# --- 15. Site invariants (5d D6) ---------------------------------------------
# The public site (site/, served by Cloudflare Pages) is frozen at the 5d D6
# gate (docs/design/p5d-release-freeze.md §D6, §Sequencing): five fixed files;
# static and self-contained (no scripts, frames, images, objects, embeds,
# javascript: URLs, CSS imports, or url() fetches); the verification page
# carries the D4 release-signing certificate SHA-256 exactly once in each of
# its two printed forms; A11 branding (Titlan-only — the publisher name only
# on SPDX lines and in the single imprint literal); the five required links;
# and no placeholder text (§Sequencing 2: a section ships only when its
# literal exists). 15a runs unconditionally; 15b–15f run once site/ exists,
# so an absent site/ fails on 15a's five lines and nothing else.
site_files='site/index.html site/verify.html site/style.css site/_headers site/404.html'
# 15a. Existence.
for f in $site_files; do
  if [ ! -f "$f" ]; then
    echo "MISSING site file: $f"
    fail=1
  fi
done
if [ -d site ]; then
  # 15b. No active or external content.
  site_active_hits=$(grep -rniE '<script|<iframe|<img|<object|<embed|javascript:|@import|url\(' site || true)
  if [ -n "$site_active_hits" ]; then
    echo "site: active/external content under site/ (D6: static, script-free, self-contained):"
    echo "$site_active_hits"
    fail=1
  fi
  # 15c. D4 certificate fingerprint pins — each printed form exactly once, in
  #      site/verify.html only (keytool colon form; apksigner lowercase hex).
  d4_fp_colon='EC:DD:E6:C1:76:29:D7:44:7C:62:17:13:7B:27:B0:AF:9F:91:5D:C6:C5:CA:CF:8C:38:FF:02:D0:B2:2C:8A:E0'
  d4_fp_hex='ecdde6c17629d7447c6217137b27b0af9f915dc6c5cacf8c38ff02d0b22c8ae0'
  if [ -f site/verify.html ]; then
    d4_colon_n=$(grep -cF "$d4_fp_colon" site/verify.html || true)
    d4_hex_n=$(grep -cF "$d4_fp_hex" site/verify.html || true)
    if [ "$d4_colon_n" -ne 1 ]; then
      echo "site: D4 certificate SHA-256 (colon form) must appear exactly once in site/verify.html (found $d4_colon_n)"
      fail=1
    fi
    if [ "$d4_hex_n" -ne 1 ]; then
      echo "site: D4 certificate SHA-256 (hex form) must appear exactly once in site/verify.html (found $d4_hex_n)"
      fail=1
    fi
  fi
  # 15d. A11 branding: no platform brand string anywhere under site/; the
  #      publisher name only on SPDX copyright lines and inside the imprint
  #      literal, which itself appears exactly once across site/*.html.
  site_tezca_hits=$(grep -rni 'tezca' site || true)
  if [ -n "$site_tezca_hits" ]; then
    echo "A11 violation: reserved platform brand string under site/:"
    echo "$site_tezca_hits"
    fail=1
  fi
  site_imprint='© 2026 Oculux Technologies LLC'
  site_oculux_hits=$(grep -rni 'oculux' site | grep -v 'SPDX-FileCopyrightText' \
    | sed "s/$site_imprint//g" | grep -i 'oculux' || true)
  if [ -n "$site_oculux_hits" ]; then
    echo "A11 violation: publisher name under site/ outside SPDX lines and the imprint literal:"
    echo "$site_oculux_hits"
    fail=1
  fi
  site_imprint_n=$(cat site/*.html 2>/dev/null | grep -oF "$site_imprint" | grep -c . || true)
  if [ "$site_imprint_n" -ne 1 ]; then
    echo "site: imprint '$site_imprint' must appear exactly once across site/*.html (found $site_imprint_n)"
    fail=1
  fi
  # 15e. Required links — each URL literal at least once across site/*.html.
  for site_url in 'https://github.com/Titlan-chat/titlan' \
                  'https://github.com/Titlan-chat/titlan/releases' \
                  'https://github.com/Titlan-chat/titlan/blob/main/proto/envelope.md' \
                  'https://github.com/Titlan-chat/titlan/blob/main/docs/threat-model.md' \
                  'https://github.com/Titlan-chat/titlan/blob/main/SECURITY.md'; do
    if ! cat site/*.html 2>/dev/null | grep -qF "$site_url"; then
      echo "site: required link missing from site/*.html: $site_url"
      fail=1
    fi
  done
  # 15f. No placeholders.
  site_placeholder_hits=$(grep -rniE 'TODO|TBD|FIXME|PLACEHOLDER|lorem ipsum' site || true)
  if [ -n "$site_placeholder_hits" ]; then
    echo "site: placeholder text under site/ (§Sequencing: no placeholders are ever committed):"
    echo "$site_placeholder_hits"
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "Invariant checks FAILED."
  exit 1
fi
echo "All invariant checks passed (SPDX headers, applicationId single-source, A11 naming, relay zero-logging/no-fs, release no-test-anchors, delivery-sentinel hygiene, debug-only relay override, debug pin bridge, scan-input hash probe, ffi-bisect probes, relay dep-graph blindness, crash-SDK absence, unit hardening directives, relay-URL single constant, site invariants (5d D6))."
