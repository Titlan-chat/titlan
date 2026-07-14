// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Licensing interface (work order §5: define the trait, stub the
//! implementation; blind-signature licensing is explicitly deferred).

/// Decides whether this installation is licensed for a given capability.
pub trait Licensing {
    /// `true` if the capability may be used.
    fn is_licensed(&self, capability: &str) -> bool;
}

/// MVP stub: everything is licensed.
pub struct AlwaysLicensed;

impl Licensing for AlwaysLicensed {
    fn is_licensed(&self, _capability: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_licensed_stub_licenses_everything() {
        assert!(AlwaysLicensed.is_licensed("chat"));
        assert!(AlwaysLicensed.is_licensed("anything-else"));
    }
}
