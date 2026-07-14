// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Configuration: padding profiles and the single default relay constant.

/// The ONLY relay address literal in the entire codebase (INV-5). Every
/// conversation stores its own relay URL; this constant is nothing more than
/// the default filled into new conversations. Placeholder host pending the
/// Titlan domain purchase (work order §10.4).
pub const DEFAULT_RELAY_URL: &str = "wss://relay.invalid/v1";

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
    pub fn default_profile() -> Self {
        Self::new(vec![512, 2048, 8192]).expect("default buckets are valid")
    }

    /// A single-bucket profile (all frames padded to `size`).
    pub fn single(size: u32) -> crate::Result<Self> {
        Self::new(vec![size])
    }

    /// Builds a profile from bucket sizes. Sizes are sorted and deduplicated;
    /// every bucket must be at least the inner-frame header size (6 bytes).
    pub fn new(mut buckets: Vec<u32>) -> crate::Result<Self> {
        buckets.sort_unstable();
        buckets.dedup();
        if buckets.is_empty() || buckets[0] < crate::envelope::INNER_HEADER_LEN as u32 {
            return Err(crate::CoreError::Malformed("invalid padding profile"));
        }
        Ok(Self { buckets })
    }

    /// The bucket sizes, ascending.
    pub fn buckets(&self) -> &[u32] {
        &self.buckets
    }

    /// Smallest bucket that holds an inner frame of `frame_len` bytes
    /// (header + payload, pre-padding), or `None` if it exceeds the largest.
    pub fn bucket_for(&self, frame_len: u32) -> Option<u32> {
        self.buckets.iter().copied().find(|&b| b >= frame_len)
    }

    /// `true` if `len` is exactly one of the configured buckets.
    pub fn is_bucket(&self, len: u32) -> bool {
        self.buckets.binary_search(&len).is_ok()
    }

    /// Maximum payload size this profile can carry.
    pub fn max_payload(&self) -> u32 {
        self.buckets[self.buckets.len() - 1] - crate::envelope::INNER_HEADER_LEN as u32
    }
}
