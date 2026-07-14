<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan

Titlan is an end-to-end encrypted messenger: no phone numbers, no accounts,
and a relay server that is architecturally incapable of reading content or
logging identities. GrapheneOS first, standard Android second.

Titlan is the first module of a broader security platform, published by
Oculux Technologies LLC.

**Status: Phase 2 — core protocol implemented.** Envelope, PQXDH sessions
(libsignal), and encrypted storage are in place with full test coverage; the
relay server and Android UI are still to come.

Titlan is built with an AI-assisted, human-gated development process — see
[DEVELOPMENT.md](DEVELOPMENT.md) for exactly how, and why we publish that.

## Repository layout

| Path | What it is | License |
|------|------------|---------|
| `tezca-core/` | Shared Rust E2EE core: identity, sessions (libsignal), envelope, storage, relay client. Exposed to Kotlin via UniFFI. | Apache-2.0 |
| `tezca-relay/` | Blind, stateless Rust relay: RAM-only mailboxes with TTL expiry. No database, no disk persistence. | AGPL-3.0-only |
| `titlan-android/` | Kotlin + Jetpack Compose app. UI-only; all protocol logic lives in `tezca-core`. | AGPL-3.0-only |
| `proto/` | Wire protocol specification (versioned, typed, padded envelope). | Apache-2.0 |
| `docs/` | Developer documentation. | Apache-2.0 |
| `scripts/` | Invariant checks and the reproducible-build pipeline. | Apache-2.0 |

Every file carries an SPDX header; CI enforces this
(`scripts/check-invariants.sh`), along with two more repo rules:

- The Android `applicationId` is defined in exactly one place:
  `TITLAN_APPLICATION_ID` in `titlan-android/gradle.properties`. It is a
  placeholder until the final reverse-domain id is confirmed — the id is
  permanent once published. Source code lives under the decoupled namespace
  `app.titlan` and never needs to change with it.
- The user-visible product name is **Titlan** everywhere. Company and platform
  brand names never appear in user-facing Android resources (the future About
  screen, `about_*` resources, is the single exception).

## Building

See [docs/build.md](docs/build.md). Short version:

```sh
# Rust workspace (toolchain pinned by rust-toolchain.toml)
cargo build --workspace --locked && cargo test --workspace --locked

# Android app (JDK 17 + Android SDK 36)
cd titlan-android && ./gradlew :app:assembleDebug
```

## Reproducible builds

Toolchains are pinned (`rust-toolchain.toml`, Gradle wrapper with distribution
checksum, version catalog) and dependencies are locked (`Cargo.lock`,
`titlan-android/app/gradle.lockfile`). CI runs
[`scripts/repro-build.sh`](scripts/repro-build.sh) on every push: it builds
the relay binary and the unsigned release APK twice from fresh source copies
at a canonical path and fails on any hash difference. Tagged builds publish
the resulting reproducibility report next to the artifacts.

## SBOM and supply chain

- CycloneDX SBOMs for `tezca-core`, `tezca-relay`, and the APK dependency
  closure are generated in CI and published as artifacts on every tagged
  build, together with a SLSA-style build provenance attestation.
- `cargo deny` and `cargo audit` gate every push (advisories, license
  allowlist, unknown registries, wildcard versions).
- Dependabot proposes dependency bumps weekly; the full CI matrix (including
  the reproducibility job) gates them.

## Release signing

**Signing keys are EXTERNAL to this repository and its CI — always.**

- No keystore, key material, or signing secret is ever committed, uploaded as
  a CI secret, or otherwise placed in this repository's trust domain.
  `.gitignore` blocks common keystore file types as a last line of defense.
- CI produces **unsigned** release APKs and relay binaries, plus SBOMs,
  provenance attestations, and a reproducibility report.
- Release signing happens offline, by the release manager, on a machine that
  holds the release keystore. The documented flow (to be finalized in Phase 5
  with the release checklist): download the tagged CI artifact, verify its
  provenance attestation and reproducibility report, verify its SHA-256
  against an independent local rebuild, then sign with `apksigner` and publish
  the signed APK's SHA-256.
- Debug builds use the local, auto-generated Android debug keystore only.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability disclosure. The threat model
document lands in Phase 5.
