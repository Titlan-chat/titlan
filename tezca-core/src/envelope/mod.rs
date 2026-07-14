// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Outer envelope: the only bytes a relay or wire observer ever sees
//! (besides the mailbox ID). Normative layout: `proto/envelope.md`.
//!
//! ```text
//! magic "TZCA" (4) | version (1) | kind (1) | reserved 0x0000 (2) | ciphertext (..)
//! ```

mod inner;

pub use inner::{INNER_HEADER_LEN, InnerFrame, PayloadType};

use crate::{CoreError, Result};

/// Envelope magic bytes: `"TZCA"`.
pub const MAGIC: [u8; 4] = *b"TZCA";
/// Protocol version implemented by this build. v1 accepts exactly {1} (INV-4).
pub const VERSION: u8 = 1;
/// Outer header length in bytes.
pub const OUTER_HEADER_LEN: usize = 8;

/// What the ciphertext is, mirroring what the libsignal blob itself reveals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeKind {
    /// A session-setup message (libsignal `PreKeySignalMessage`).
    SessionSetup = 0x01,
    /// An established-session ratchet message (libsignal `SignalMessage`).
    Ratchet = 0x02,
}

/// A parsed (or to-be-encoded) outer envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Ciphertext kind.
    pub kind: EnvelopeKind,
    /// The libsignal message bytes.
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Encodes the envelope to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OUTER_HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&[0x00, 0x00]);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses wire bytes. Every failure is a typed, clean rejection (INV-4);
    /// this function must never panic on any input (fuzz target).
    pub fn parse(bytes: &[u8]) -> Result<Envelope> {
        // Header plus at least one ciphertext byte.
        if bytes.len() <= OUTER_HEADER_LEN {
            return Err(CoreError::Malformed("envelope too short"));
        }
        if bytes[..4] != MAGIC {
            return Err(CoreError::Malformed("bad envelope magic"));
        }
        if bytes[4] != VERSION {
            return Err(CoreError::UnsupportedVersion { got: bytes[4] });
        }
        let kind = EnvelopeKind::try_from(bytes[5])?;
        if bytes[6] != 0 || bytes[7] != 0 {
            return Err(CoreError::ReservedMustBeZero);
        }
        Ok(Envelope {
            kind,
            ciphertext: bytes[OUTER_HEADER_LEN..].to_vec(),
        })
    }
}

impl TryFrom<u8> for EnvelopeKind {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(EnvelopeKind::SessionSetup),
            0x02 => Ok(EnvelopeKind::Ratchet),
            got => Err(CoreError::UnknownEnvelopeKind { got }),
        }
    }
}
