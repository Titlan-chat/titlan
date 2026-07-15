// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! The only two parsers in the relay that touch client-controlled bytes.
//! Pure functions, unit-tested and fuzzed (INV-4: reject cleanly, never
//! panic).

/// Envelope magic per proto/envelope.md. The relay validates ONLY these
/// five bytes (magic + version) — deliberately nothing beyond offset 4
/// (INV-2 blindness; the kind byte and ciphertext are opaque here).
const MAGIC: &[u8; 4] = b"TZCA";
const VERSION: u8 = 0x01;
/// Minimum well-formed envelope: 8-byte header + ≥1 ciphertext byte.
const MIN_ENVELOPE: usize = 9;

/// Deposit admission check: magic, version, and minimum length only.
pub fn deposit_admissible(blob: &[u8]) -> bool {
    blob.len() >= MIN_ENVELOPE && &blob[..4] == MAGIC && blob[4] == VERSION
}

/// Client→server WS ack frame: `0x02 || message_id(16)`. Returns the acked
/// message id, or `None` for anything else (ignored, never an error path —
/// a blind relay has nothing useful to say about garbage).
pub fn parse_ack_frame(frame: &[u8]) -> Option<[u8; 16]> {
    if frame.len() != 17 || frame[0] != 0x02 {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&frame[1..17]);
    Some(id)
}

/// Server→client WS delivery frame: `0x01 || message_id(16) || envelope`.
pub fn delivery_frame(message_id: &[u8; 16], envelope: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + envelope.len());
    out.push(0x01);
    out.extend_from_slice(message_id);
    out.extend_from_slice(envelope);
    out
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url of 32 bytes → 43 chars (mailbox id encoding).
pub fn encode_mailbox_id(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(43);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[(n >> 18) as usize & 63] as char);
        out.push(B64URL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 63] as char);
        }
    }
    out
}

/// Shape check for a mailbox id path segment. Anything malformed is treated
/// as an unknown mailbox (404) — never a distinct error (indistinguishable
/// from expired/deleted by design).
pub fn mailbox_id_shape_ok(id: &str) -> bool {
    id.len() == 43 && id.bytes().all(|b| B64URL.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_checks_magic_version_and_length_only() {
        assert!(deposit_admissible(b"TZCA\x01\x02\x00\x00\xAA"));
        // Kind byte and everything after are NOT validated (blindness).
        assert!(deposit_admissible(b"TZCA\x01\x7F\xFF\xFF garbage"));
        assert!(!deposit_admissible(b"TZCB\x01\x02\x00\x00\xAA")); // magic
        assert!(!deposit_admissible(b"TZCA\x02\x02\x00\x00\xAA")); // version
        assert!(!deposit_admissible(b"TZCA\x01\x02\x00\x00")); // too short
        assert!(!deposit_admissible(b""));
    }

    #[test]
    fn ack_frame_roundtrip_and_rejection() {
        let id = [7u8; 16];
        let mut frame = vec![0x02];
        frame.extend_from_slice(&id);
        assert_eq!(parse_ack_frame(&frame), Some(id));
        assert_eq!(parse_ack_frame(&frame[..16]), None);
        assert_eq!(parse_ack_frame(&[0x01; 17]), None);
        assert_eq!(parse_ack_frame(&[]), None);
    }

    #[test]
    fn mailbox_id_encoding_is_43_chars_and_shape_checked() {
        let id = encode_mailbox_id(&[0u8; 32]);
        assert_eq!(id.len(), 43);
        assert!(mailbox_id_shape_ok(&id));
        let id = encode_mailbox_id(&[0xFF; 32]);
        assert_eq!(id.len(), 43);
        assert!(mailbox_id_shape_ok(&id));
        assert!(!mailbox_id_shape_ok("short"));
        assert!(!mailbox_id_shape_ok(&"+".repeat(43)));
    }
}
