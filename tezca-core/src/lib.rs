// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! `tezca-core` — shared end-to-end-encryption core for the Tezca platform,
//! first consumed by the Titlan messenger.
//!
//! Phase 1 scaffold: this crate is intentionally empty-but-wired. Phase 2
//! (work order §6) lands the real modules:
//!
//! - identity: device-generated keypair (A1)
//! - session: X3DH/PQXDH + Double Ratchet via the official libsignal Rust
//!   crate — no custom cryptography anywhere (A2, INV-6)
//! - envelope: versioned, typed, padded wire format (A8, INV-4)
//! - storage: SQLCipher-encrypted persistence (A4, INV-1)
//! - relay client: address taken from conversation/team config (INV-5)
//!
//! Kotlin consumes this crate through UniFFI bindings (A3); Kotlin stays
//! UI-only.

/// Returns the crate version. Single source of truth is `Cargo.toml`.
pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_wired_from_manifest() {
        assert_eq!(core_version(), env!("CARGO_PKG_VERSION"));
        assert!(!core_version().is_empty());
    }
}
