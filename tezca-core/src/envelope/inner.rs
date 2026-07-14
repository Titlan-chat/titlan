// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Inner frame: typed, versioned, padded plaintext fed into the ratchet.
//! Exists ONLY as plaintext inside libsignal encryption — the relay never
//! sees these fields. Normative layout: `proto/envelope.md`.
//!
//! ```text
//! payload_type (1) | type_version (1) | payload_len u32 BE (4) | payload | 0x00 padding to bucket
//! ```

use crate::config::PaddingProfile;
use crate::{CoreError, Result};

/// Inner-frame header length in bytes.
pub const INNER_HEADER_LEN: usize = 6;

/// Payload type registry (normative registry lives in `proto/envelope.md`).
///
/// `Posture`, `Policy`, and `Alert` are FIRST-CLASS platform variants: they
/// encode, decode, and round-trip today. The MVP chat client recognizes them
/// and declines to handle them (`RecognizedButUnsupported`) — which is an
/// application decision, not a protocol error. Bytes `0x05–0x7F` are
/// unassigned (registry-controlled); `0x80–0xFF` are private/experimental.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    /// Human chat. `chat/1` payload is UTF-8 text.
    Chat = 0x01,
    /// Device posture report (Tezca suite; reserved, first-class).
    Posture = 0x02,
    /// Policy push (Tezca suite; reserved, first-class).
    Policy = 0x03,
    /// Appliance alert (Tezca suite; reserved, first-class).
    Alert = 0x04,
}

/// A typed, versioned payload frame (pre-padding representation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerFrame {
    /// Payload type from the registry.
    pub payload_type: PayloadType,
    /// Version of that payload type (`chat/1` ⇒ 1).
    pub type_version: u8,
    /// The payload bytes.
    pub payload: Vec<u8>,
}

impl InnerFrame {
    /// Convenience constructor for `chat/1` frames.
    pub fn chat_v1(text: &str) -> Self {
        Self {
            payload_type: PayloadType::Chat,
            type_version: 1,
            payload: text.as_bytes().to_vec(),
        }
    }

    /// Encodes and pads to the smallest fitting bucket of `profile`.
    ///
    /// Fails with [`CoreError::PayloadTooLarge`] BEFORE any cryptographic
    /// operation if the payload exceeds the largest bucket.
    pub fn encode(&self, profile: &PaddingProfile) -> Result<Vec<u8>> {
        let len = u32::try_from(self.payload.len())
            .map_err(|_| CoreError::Malformed("payload exceeds u32"))?;
        let max = profile.max_payload();
        if len > max {
            return Err(CoreError::PayloadTooLarge { len, max });
        }
        let frame_len = INNER_HEADER_LEN as u32 + len;
        let bucket = profile
            .bucket_for(frame_len)
            .ok_or(CoreError::Malformed("no bucket fits frame"))?;
        let mut out = Vec::with_capacity(bucket as usize);
        out.push(self.payload_type as u8);
        out.push(self.type_version);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.resize(bucket as usize, 0x00);
        Ok(out)
    }

    /// Parses a decrypted frame. Strict: total length must be exactly one
    /// configured bucket, declared length must fit, and every padding byte
    /// must be zero. Never panics on any input (fuzz target).
    pub fn parse(bytes: &[u8], profile: &PaddingProfile) -> Result<InnerFrame> {
        let frame_len =
            u32::try_from(bytes.len()).map_err(|_| CoreError::Malformed("frame exceeds u32"))?;
        if !profile.is_bucket(frame_len) {
            return Err(CoreError::InvalidBucket { frame_len });
        }
        // Profile construction guarantees every bucket ≥ INNER_HEADER_LEN.
        let payload_type = PayloadType::try_from(bytes[0])?;
        let type_version = bytes[1];
        let declared = u32::from_be_bytes(
            bytes[2..6]
                .try_into()
                .expect("slice of statically valid length"),
        ) as usize;
        let end = INNER_HEADER_LEN
            .checked_add(declared)
            .ok_or(CoreError::Malformed("payload length overflow"))?;
        if end > bytes.len() {
            return Err(CoreError::Malformed("payload length exceeds frame"));
        }
        if bytes[end..].iter().any(|&b| b != 0x00) {
            return Err(CoreError::InvalidPadding);
        }
        Ok(InnerFrame {
            payload_type,
            type_version,
            payload: bytes[INNER_HEADER_LEN..end].to_vec(),
        })
    }

    /// Extracts the UTF-8 text of a `chat/1` frame.
    ///
    /// Registry-valid non-chat types yield
    /// [`CoreError::RecognizedButUnsupported`] — ack-and-drop material, not a
    /// protocol violation.
    pub fn into_chat_v1(self) -> Result<String> {
        match (self.payload_type, self.type_version) {
            (PayloadType::Chat, 1) => String::from_utf8(self.payload)
                .map_err(|_| CoreError::Malformed("chat payload is not valid UTF-8")),
            (payload_type, type_version) => Err(CoreError::RecognizedButUnsupported {
                payload_type,
                type_version,
            }),
        }
    }
}

impl TryFrom<u8> for PayloadType {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(PayloadType::Chat),
            0x02 => Ok(PayloadType::Posture),
            0x03 => Ok(PayloadType::Policy),
            0x04 => Ok(PayloadType::Alert),
            got => Err(CoreError::UnknownPayloadType { got }),
        }
    }
}
