// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Typed errors for `tezca-core`. INV-4 demands clean rejection — every
//! malformed or unexpected wire input maps to a variant here, never a panic.

use crate::envelope::PayloadType;

/// Why a pairing offer fell outside its embedded validity window (freeze
/// `docs/design/2026-08-pair-offer-v3-freeze.md` §4/§5). The user surface is
/// one message for both details (V3-D2); this enum stays distinct for
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferExpiryDetail {
    /// `now >= issued_at + ttl_s` — the offer's lifetime has elapsed.
    Expired,
    /// `issued_at > now + FUTURE_SKEW_S` — dated beyond the future-skew grace.
    NotYetValid,
}

/// Errors produced by `tezca-core`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// A versioned payload (outer envelope, or a pairing offer — the v3-only
    /// acceptor rejects v1/v2 here) carries a version this client does not
    /// speak.
    #[error("unsupported version {got}")]
    UnsupportedVersion {
        /// The version byte received.
        got: u8,
    },
    /// Outer envelope kind byte is not a known kind.
    #[error("unknown envelope kind {got}")]
    UnknownEnvelopeKind {
        /// The kind byte received.
        got: u8,
    },
    /// Reserved header bytes were non-zero (must be zero in v1).
    #[error("reserved envelope bytes must be zero in v1")]
    ReservedMustBeZero,
    /// Structurally invalid input (truncated, bad magic, bad lengths).
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    /// Inner frame payload type byte is outside the registry.
    #[error("unknown payload type {got}")]
    UnknownPayloadType {
        /// The payload type byte received.
        got: u8,
    },
    /// A registry-valid payload type/version this build does not implement
    /// (e.g. `posture/1` on an MVP chat client). Application-level
    /// "not my job", NOT a protocol violation.
    #[error("recognized but unsupported payload {payload_type:?}/{type_version}")]
    RecognizedButUnsupported {
        /// The recognized payload type.
        payload_type: PayloadType,
        /// The version of that payload type.
        type_version: u8,
    },
    /// Inner frame padding contained non-zero bytes.
    #[error("invalid padding")]
    InvalidPadding,
    /// Inner frame length is not exactly a configured bucket size.
    #[error("frame length {frame_len} is not a configured bucket")]
    InvalidBucket {
        /// The decrypted frame length.
        frame_len: u32,
    },
    /// Payload exceeds the largest configured bucket. Raised BEFORE any
    /// cryptographic operation runs.
    #[error("payload of {len} bytes exceeds maximum {max}")]
    PayloadTooLarge {
        /// Requested payload length.
        len: u32,
        /// Maximum payload length for the active padding profile.
        max: u32,
    },
    /// Duplicate delivery of an already-decrypted message.
    #[error("replayed message rejected")]
    Replay,
    /// The database could not be opened with the supplied key.
    #[error("database key rejected")]
    BadDbKey,
    /// Underlying storage failure.
    #[error("storage error: {0}")]
    Storage(String),
    /// The relay could not be reached (transport/connection failure — distinct
    /// from a 404, which is a clean "mailbox gone" signal).
    #[error("network error: {0}")]
    Network(String),
    /// The pairing target is gone: the single-use pairing inbox referenced by
    /// a scanned payload has been consumed (retired after a successful pairing)
    /// or expired — a deposit to it returned 404. This is the "stale-QR-dead"
    /// condition (`proto/pairing.md`): a captured QR cannot re-pair.
    #[error("pairing inbox unavailable (consumed or expired)")]
    PairingUnavailable,
    /// A scanned v3 offer is outside its embedded validity window (freeze §4,
    /// the H7 distinct expired-offer error). Raised at decode, BEFORE any
    /// network I/O. Timestamps only — no INV-1 exposure.
    #[error(
        "pairing offer outside validity (issued_at {issued_at}, ttl {ttl_s} s, now {now}, {detail:?})"
    )]
    OfferExpired {
        /// The offer's embedded mint time (Unix seconds, offerer clock).
        issued_at: u64,
        /// The offer's embedded time-to-live in seconds.
        ttl_s: u32,
        /// The acceptor clock at evaluation (Unix seconds).
        now: u64,
        /// Which validity bound failed (§4 steps 3-4).
        detail: OfferExpiryDetail,
    },
    /// A v3 offer's trailing `offer_sig` did not verify over the wire prefix
    /// with the identity key inside the offer's own bundle (freeze §3) — a
    /// crypto-class rejection, distinct from [`CoreError::ProofOfScanFailed`].
    #[error("pairing offer signature invalid")]
    OfferSignatureInvalid,
    /// The responder's first sealed message failed proof-of-scan: the MAC over
    /// its bundle, keyed by the offer's pairing secret, did not verify. The
    /// return is rejected — possession-of-offer is the trust root
    /// (`proto/pairing.md` §3, 4b-2). Raised only after decryption succeeds.
    #[error("proof-of-scan verification failed")]
    ProofOfScanFailed,
    /// §10.7 recovery has exhausted its generation window (relative offset ≥ W)
    /// or run out of probe cycles: routing to the peer cannot be re-established
    /// in-band. Surfaced to the UI as the `conversation-needs-repair` event;
    /// re-pair is the last resort (frozen design §8, 4b-2).
    #[error("conversation needs repair (recovery exhausted)")]
    ConversationNeedsRepair,
    /// Underlying libsignal protocol failure.
    #[error("protocol error: {0}")]
    Signal(String),
}
