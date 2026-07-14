<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Building Titlan

## Prerequisites

| Tool | Version | Pinned by |
|------|---------|-----------|
| Rust | 1.97.0 | `rust-toolchain.toml` (rustup installs it automatically) |
| JDK | 17 | CI uses Temurin 17; any JDK 17 works |
| Android SDK | platform 36, build-tools 36 | `compileSdk` in `titlan-android/app/build.gradle.kts` |
| Gradle | 8.14.5 | wrapper (`gradle-wrapper.properties`, with distribution SHA-256) |

Optional, for supply-chain checks and SBOMs:
`cargo install cargo-deny cargo-audit cargo-cyclonedx --locked`

## Rust workspace (`tezca-core`, `tezca-relay`)

```sh
cargo build --workspace --locked
cargo test  --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check
cargo audit
```

Always build with `--locked`: `Cargo.lock` is committed and authoritative
(INV-7).

## Android app

```sh
cd titlan-android
./gradlew :app:assembleDebug          # debug APK
./gradlew :app:testDebugUnitTest      # unit tests
./gradlew :app:lintDebug              # Android lint
./gradlew :app:assembleRelease        # UNSIGNED release APK
```

Point Gradle at your SDK via `ANDROID_HOME` or
`titlan-android/local.properties` (`sdk.dir=...`, not committed).

Dependencies are locked in `app/gradle.lockfile`. To bump versions, edit
`gradle/libs.versions.toml`, then regenerate the lockfile deliberately:

```sh
./gradlew :app:assembleDebug :app:assembleRelease :app:lintDebug :app:testDebugUnitTest --write-locks
```

## Reproducible builds

```sh
./scripts/repro-build.sh
```

Builds the relay release binary and the unsigned release APK twice, each time
from a fresh copy of the tree at a canonical path (`/tmp/tezca-repro`,
override with `REPRO_BUILD_ROOT`), and fails if any SHA-256 differs. The
report is written to `repro-report.txt`.

Notes on determinism:

- Rust: `--locked`, pinned toolchain, `CARGO_INCREMENTAL=0`,
  `--remap-path-prefix` for both the build root and `CARGO_HOME`, and
  `strip = "symbols"` in the release profile. Hashes are comparable across
  machines only for the same canonical build path and toolchain.
- Android: pinned AGP/Kotlin via the version catalog, locked dependencies,
  unsigned release output (signing is external and happens offline).

## SBOMs (CycloneDX)

```sh
cargo cyclonedx --format json          # tezca-core/tezca-core.cdx.json, tezca-relay/tezca-relay.cdx.json
cd titlan-android && ./gradlew :app:cyclonedxDirectBom   # app/build/reports/
```

CI validates SBOM generation on every push and publishes SBOMs as artifacts
on every tagged build (`.github/workflows/release.yml`).

## CI overview

| Job | Enforces |
|-----|----------|
| `invariants` | SPDX headers (A10), single-source applicationId (§10.4), naming rules (A11) |
| `rust` | rustfmt, clippy `-D warnings`, build, tests — all `--locked` |
| `rust-supply-chain` | `cargo deny check`, `cargo audit` (INV-7) |
| `android` | lint, unit tests, assembleDebug |
| `reproducible-build` | double build + artifact diff |
| `sbom` | CycloneDX generation for core, relay, APK deps |
