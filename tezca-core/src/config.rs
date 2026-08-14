// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Configuration: padding profiles and the single default relay constant.

/// The ONLY relay address literal in the entire codebase (INV-5). Every
/// conversation stores its own relay URL; this constant is nothing more than
/// the default filled into new conversations. Placeholder host pending the
/// Titlan domain purchase (work order §10.4).
pub const DEFAULT_RELAY_URL: &str = "wss://relay.invalid/v1";

// --- Pair-offer v3 validity constants (freeze
// `docs/design/2026-08-pair-offer-v3-freeze.md` §4/§6, V3-D2) — the SINGLE
// source for every consumer: mint path, acceptor validity rule, UI countdown,
// deposit-harness fuse, offerer-side delete timer. -------------------------

/// Default pairing-offer TTL written by the mint path (H7: 1 h).
pub const OFFER_DEFAULT_TTL_S: u32 = 3600;

/// Maximum `ttl_s` an acceptor admits; out-of-range is malformed (§4 step 2).
pub const MAX_OFFER_TTL_S: u32 = 86_400;

/// Future-skew grace: an offer with `issued_at > now + FUTURE_SKEW_S` is
/// `NotYetValid` (§4 step 3).
pub const FUTURE_SKEW_S: u64 = 300;

/// A padding profile: the set of allowed inner-frame bucket sizes.
///
/// Resolved work order §10.2 (2026-07-14): default is 512 B / 2 KiB / 8 KiB,
/// applied to the inner frame; profiles are per-conversation, and mixed
/// human+machine conversations SHOULD use a single-bucket profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingProfile {
    buckets: Vec<u32>,
}

impl PaddingProfile {
    /// The default three-bucket profile (512 / 2048 / 8192).
    ///
    /// # Panics
    ///
    /// Never panics in practice: the fixed default buckets always validate; the
    /// `expect` pins that invariant.
    #[must_use]
    pub fn default_profile() -> Self {
        Self::new(vec![512, 2048, 8192]).expect("default buckets are valid")
    }

    /// A single-bucket profile (all frames padded to `size`).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Malformed`] when `size` is below the 6-byte inner-
    /// frame header.
    pub fn single(size: u32) -> crate::Result<Self> {
        Self::new(vec![size])
    }

    /// Builds a profile from bucket sizes. Sizes are sorted and deduplicated;
    /// every bucket must be at least the inner-frame header size (6 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Malformed`] when `buckets` is empty or its smallest
    /// entry is below the 6-byte inner-frame header.
    pub fn new(mut buckets: Vec<u32>) -> crate::Result<Self> {
        buckets.sort_unstable();
        buckets.dedup();
        if buckets.is_empty() || buckets[0] < crate::envelope::INNER_HEADER_LEN_U32 {
            return Err(crate::CoreError::Malformed("invalid padding profile"));
        }
        Ok(Self { buckets })
    }

    /// The bucket sizes, ascending.
    #[must_use]
    pub fn buckets(&self) -> &[u32] {
        &self.buckets
    }

    /// Smallest bucket that holds an inner frame of `frame_len` bytes
    /// (header + payload, pre-padding), or `None` if it exceeds the largest.
    #[must_use]
    pub fn bucket_for(&self, frame_len: u32) -> Option<u32> {
        self.buckets.iter().copied().find(|&b| b >= frame_len)
    }

    /// `true` if `len` is exactly one of the configured buckets.
    #[must_use]
    pub fn is_bucket(&self, len: u32) -> bool {
        self.buckets.binary_search(&len).is_ok()
    }

    /// Maximum payload size this profile can carry.
    #[must_use]
    pub fn max_payload(&self) -> u32 {
        self.buckets[self.buckets.len() - 1] - crate::envelope::INNER_HEADER_LEN_U32
    }
}
