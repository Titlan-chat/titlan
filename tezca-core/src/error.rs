// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Typed errors for `tezca-core`. INV-4 demands clean rejection — every
//! malformed or unexpected wire input maps to a variant here, never a panic.

use crate::envelope::PayloadType;

/// Errors produced by `tezca-core`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// Outer envelope carries a protocol version this client does not speak.
    #[error("unsupported envelope version {got}")]
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
    /// Underlying libsignal protocol failure.
    #[error("protocol error: {0}")]
    Signal(String),
}
