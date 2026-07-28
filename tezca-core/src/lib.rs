// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! `tezca-core` — shared end-to-end-encryption core for the Tezca platform,
//! first consumed by the Titlan messenger.
//!
//! Module map (work order §6 Phase 2):
//! - [`identity`]: device-generated keypair, prekeys, pairing bundle (A1, A7)
//! - [`session`]: PQXDH establishment + Double Ratchet via libsignal — the
//!   ONLY source of cryptographic primitives (A2, INV-6)
//! - [`envelope`]: versioned, typed, padded wire format (A8, INV-4)
//! - [`storage`]: SQLCipher-encrypted persistence (A4, INV-1)
//! - [`config`]: padding profiles; the single default relay constant (INV-5)
//! - [`licensing`]: deferred licensing trait + `AlwaysLicensed` stub (§5)
//!
//! Kotlin consumes this crate through UniFFI bindings (A3, Phase 4); Kotlin
//! stays UI-only.

pub mod client;
pub mod config;
pub mod envelope;
pub mod error;
pub mod ffi;
pub mod identity;
pub mod licensing;
pub(crate) mod pairing;
pub(crate) mod recovery;
pub(crate) mod relay_client;
pub mod session;
pub mod storage;

pub use error::CoreError;

uniffi::setup_scaffolding!();

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, CoreError>;

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
