// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Configuration: padding profiles and the single default relay constant.

/// The ONLY relay address literal in the entire codebase (INV-5): the default
/// filled into new conversations; each conversation's own relay config
/// overrides it. Origin-only form — no path, no port: the relay client appends
/// `/v1/` itself, so a trailing path here is a defect (freeze RC-D1).
pub const DEFAULT_RELAY_URL: &str = "wss://relay.titlan.chat";

/// Loopback relay URL pinned by test fixtures. Test scratch URLs are exempt
/// from the INV-5 sweep by design (family 14), but the sweep's
/// `#[cfg(test)]`-module tracking is per-file and cannot see a module gated
/// at its `lib.rs` declaration — so file-level test modules take the literal
/// from here, the sanctioned single source, instead of pinning their own.
#[cfg(test)]
pub(crate) const TEST_LOOPBACK_RELAY_URL: &str = "wss://127.0.0.1:8443";

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

// --- Transport keepalive and bounded relay I/O (unit 5e-1b, finding F-L;
// freeze `docs/design/2026-10-transport-keepalive-freeze.md` KA-D2 / KA-D4)
// — the SINGLE source for every subscription and every relay HTTP call. A
// relay subscription that nobody exercises dies silently on real networks
// (NAT, carrier, emulator) while the client keeps reporting `Online`; the
// client therefore pings after KEEPALIVE_INTERVAL_S of silence and treats a
// Pong missing after KEEPALIVE_GRACE_S as a dead socket. ---------------------

/// Silence on a relay subscription before the client sends a WebSocket Ping.
pub const KEEPALIVE_INTERVAL_S: u64 = 55;

/// Pong deadline after a client Ping; a miss is a dead subscription.
pub const KEEPALIVE_GRACE_S: u64 = 10;

/// TCP/TLS connect timeout for relay HTTP calls (mailbox create, deposit,
/// retire).
pub const HTTP_CONNECT_TIMEOUT_S: u64 = 10;

/// Whole-request timeout for relay HTTP calls; bounds `send_chat`'s inline
/// deposit attempt and every pairing-flow HTTP step.
pub const HTTP_REQUEST_TIMEOUT_S: u64 = 30;

/// Keepalive timing handed to every subscription. Production is the two
/// constants above; integration tests inject short values through the
/// dev-scope constructor (see `TitlanClient::open_with_timing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveTiming {
    /// Silence before a Ping.
    pub interval: std::time::Duration,
    /// Pong deadline after a Ping.
    pub grace: std::time::Duration,
}

impl KeepaliveTiming {
    /// The production timing (`KEEPALIVE_INTERVAL_S` / `KEEPALIVE_GRACE_S`).
    #[must_use]
    pub const fn production() -> Self {
        Self {
            interval: std::time::Duration::from_secs(KEEPALIVE_INTERVAL_S),
            grace: std::time::Duration::from_secs(KEEPALIVE_GRACE_S),
        }
    }
}

/// Relay HTTP client timeouts. Production is the two constants above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTimeouts {
    /// Connect timeout.
    pub connect: std::time::Duration,
    /// Whole-request timeout.
    pub request: std::time::Duration,
}

impl HttpTimeouts {
    /// The production timeouts (`HTTP_CONNECT_TIMEOUT_S` /
    /// `HTTP_REQUEST_TIMEOUT_S`).
    #[must_use]
    pub const fn production() -> Self {
        Self {
            connect: std::time::Duration::from_secs(HTTP_CONNECT_TIMEOUT_S),
            request: std::time::Duration::from_secs(HTTP_REQUEST_TIMEOUT_S),
        }
    }
}

/// Everything the relay engine needs to bound its I/O: keepalive timing for
/// subscriptions and timeouts for HTTP. One value per `TitlanClient`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportTiming {
    /// Subscription keepalive.
    pub keepalive: KeepaliveTiming,
    /// Relay HTTP timeouts.
    pub http: HttpTimeouts,
}

impl TransportTiming {
    /// The production timing.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            keepalive: KeepaliveTiming::production(),
            http: HttpTimeouts::production(),
        }
    }
}

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
