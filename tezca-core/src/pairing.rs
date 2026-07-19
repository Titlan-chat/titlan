// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Pairing bundle framing per `proto/pairing.md` (v1). Pure serialization —
//! all key material inside is produced and validated by libsignal (INV-6).

use crate::{CoreError, Result};

pub(crate) const FORMAT_VERSION: u8 = 1;
const ABSENT_ID: u32 = 0xFFFF_FFFF;

/// Decoded pairing bundle fields (bytes are libsignal-serialized keys).
pub(crate) struct BundleData {
    pub address_name: String,
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key: Vec<u8>,
    pub signed_prekey_id: u32,
    pub signed_prekey_pub: Vec<u8>,
    pub signed_prekey_sig: Vec<u8>,
    pub kyber_prekey_id: u32,
    pub kyber_prekey_pub: Vec<u8>,
    pub kyber_prekey_sig: Vec<u8>,
    pub onetime_prekey: Option<(u32, Vec<u8>)>,
}

pub(crate) fn serialize(data: &BundleData) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.push(FORMAT_VERSION);
    put_bytes(&mut out, data.address_name.as_bytes());
    out.extend_from_slice(&data.registration_id.to_be_bytes());
    out.extend_from_slice(&data.device_id.to_be_bytes());
    put_bytes(&mut out, &data.identity_key);
    out.extend_from_slice(&data.signed_prekey_id.to_be_bytes());
    put_bytes(&mut out, &data.signed_prekey_pub);
    put_bytes(&mut out, &data.signed_prekey_sig);
    out.extend_from_slice(&data.kyber_prekey_id.to_be_bytes());
    put_bytes(&mut out, &data.kyber_prekey_pub);
    put_bytes(&mut out, &data.kyber_prekey_sig);
    match &data.onetime_prekey {
        Some((id, key)) => {
            out.extend_from_slice(&id.to_be_bytes());
            put_bytes(&mut out, key);
        }
        None => {
            out.extend_from_slice(&ABSENT_ID.to_be_bytes());
            put_bytes(&mut out, &[]);
        }
    }
    out
}

pub(crate) fn parse(bytes: &[u8]) -> Result<BundleData> {
    let mut cursor = Cursor { bytes, pos: 0 };
    let version = cursor.u8()?;
    if version != FORMAT_VERSION {
        return Err(CoreError::Malformed("unknown pairing bundle version"));
    }
    let address_name = String::from_utf8(cursor.bytes_field()?.to_vec())
        .map_err(|_| CoreError::Malformed("bundle address is not UTF-8"))?;
    let registration_id = cursor.u32()?;
    let device_id = cursor.u32()?;
    let identity_key = cursor.bytes_field()?.to_vec();
    let signed_prekey_id = cursor.u32()?;
    let signed_prekey_pub = cursor.bytes_field()?.to_vec();
    let signed_prekey_sig = cursor.bytes_field()?.to_vec();
    let kyber_prekey_id = cursor.u32()?;
    let kyber_prekey_pub = cursor.bytes_field()?.to_vec();
    let kyber_prekey_sig = cursor.bytes_field()?.to_vec();
    if kyber_prekey_pub.is_empty() {
        // A2: PQXDH is mandatory; a classical-only bundle is invalid.
        return Err(CoreError::Malformed("bundle lacks post-quantum prekey"));
    }
    let onetime_id = cursor.u32()?;
    let onetime_pub = cursor.bytes_field()?.to_vec();
    if cursor.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in pairing bundle"));
    }
    let onetime_prekey = if onetime_id == ABSENT_ID {
        None
    } else {
        Some((onetime_id, onetime_pub))
    };
    Ok(BundleData {
        address_name,
        registration_id,
        device_id,
        identity_key,
        signed_prekey_id,
        signed_prekey_pub,
        signed_prekey_sig,
        kyber_prekey_id,
        kyber_prekey_pub,
        kyber_prekey_sig,
        onetime_prekey,
    })
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("bundle field exceeds u16");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

const CONTROL_VERSION: u8 = 1;
const MAILBOX_ID_LEN: usize = 43;

/// Encodes a `mailbox-update/1` inner-frame payload (relay + new inbox).
pub(crate) fn encode_mailbox_update(relay_url: &str, inbox_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CONTROL_VERSION);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(inbox_id.as_bytes());
    out
}

/// Parses a `mailbox-update/1` payload. Returns (relay url, inbox id).
pub(crate) fn parse_mailbox_update(bytes: &[u8]) -> Result<(String, String)> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.u8()? != CONTROL_VERSION {
        return Err(CoreError::Malformed("unknown mailbox-update version"));
    }
    let relay_url = utf8(c.bytes_field()?)?;
    let inbox_id = utf8(c.take(MAILBOX_ID_LEN)?)?;
    Ok((relay_url, inbox_id))
}

// --- 4b-2: asymmetric offer + proof-of-scan (frozen design §3; specs amended
// 2026-07-19, maintainer-ratified B1/B2) --------------------------------------
// The offer extends the v1 payload with a random 256-bit pairing secret carried
// OUTSIDE the key bundle. The responder's first sealed frame (`pair-ack/2`)
// carries its own bundle, routing coords, a 32-byte recovery-root contribution,
// and a MAC over its bundle keyed by that secret. The offerer rejects any return
// whose MAC does not verify (`CoreError::ProofOfScanFailed`) and burns the offer.
// All MAC bytes come from libsignal's signal-crypto (INV-6). Normative:
// `proto/pairing.md`, `proto/inner-frame.md`.

/// Length of the random pairing secret carried in an offer (256-bit).
pub(crate) const PAIRING_SECRET_LEN: usize = 32;
/// Length of a recovery-root contribution / proof-of-scan MAC (256-bit).
pub(crate) const RECOVERY_CONTRIB_LEN: usize = 32;
/// Offer payload version (v2 asymmetric offer). A v1 scanner rejects it.
pub(crate) const OFFER_VERSION: u8 = 2;
/// `pair-ack` type_version for the v2 pairing response (rides byte 0x05).
pub(crate) const PAIR_ACK_V2: u8 = 2;
/// `mailbox-update` type_version for the v2 pairing inbox-handoff (rides 0x06).
pub(crate) const MAILBOX_UPDATE_V2: u8 = 2;
/// `mailbox-update` type_version for the v3 recovery-rotation handoff (rides
/// 0x06; NO contribution field — the recovery root already exists both ends).
pub(crate) const MAILBOX_UPDATE_V3: u8 = 3;

/// Builds a `mailbox-update/3` rotation handoff (relay + fresh inbox; no
/// contribution). Announces a fresh relay-generated inbox during §8 rotation.
pub(crate) fn encode_mailbox_update_v3(relay_url: &str, inbox_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(relay_url.len() + 64);
    out.push(MAILBOX_UPDATE_V3);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(inbox_id.as_bytes());
    out
}

/// Parses a `mailbox-update/3` → (relay, inbox). Rejects trailing bytes.
pub(crate) fn parse_mailbox_update_v3(bytes: &[u8]) -> Result<(String, String)> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.u8()? != MAILBOX_UPDATE_V3 {
        return Err(CoreError::Malformed("unknown mailbox-update version"));
    }
    let relay_url = utf8(c.bytes_field()?)?;
    let inbox_id = utf8(c.take(MAILBOX_ID_LEN)?)?;
    if c.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in mailbox-update/3"));
    }
    Ok((relay_url, inbox_id))
}

/// HMAC-SHA256 via libsignal's signal-crypto (INV-6). `key` may be any length.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = signal_crypto::CryptographicMac::new("HmacSha256", key)
        .expect("HmacSha256 is a supported signal-crypto algorithm");
    mac.update(data);
    let out = mac.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out[..32]);
    arr
}

/// Encodes a v2 pairing offer (`OFFER_VERSION`, bundle, relay, pairing inbox,
/// then the 32-byte pairing secret). QR and `titlan://pair#…` carry these
/// BYTE-IDENTICAL bytes. The recovery-root contribution is NOT in the offer
/// (B2: the root is never in the offer).
pub(crate) fn encode_pairing_offer(
    bundle: &[u8],
    relay_url: &str,
    pairing_inbox_id: &str,
    pairing_secret: &[u8; PAIRING_SECRET_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(bundle.len() + relay_url.len() + 96);
    out.push(OFFER_VERSION);
    put_bytes(&mut out, bundle);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(pairing_inbox_id.as_bytes()); // fixed 43 bytes
    out.extend_from_slice(pairing_secret);
    out
}

/// Parses a v2 offer → (bundle, relay, pairing inbox, pairing secret). Rejects
/// unknown version, truncation, and trailing bytes.
pub(crate) fn parse_pairing_offer(
    bytes: &[u8],
) -> Result<(Vec<u8>, String, String, [u8; PAIRING_SECRET_LEN])> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.u8()? != OFFER_VERSION {
        return Err(CoreError::Malformed("unknown pairing offer version"));
    }
    let bundle = c.bytes_field()?.to_vec();
    let relay = utf8(c.bytes_field()?)?;
    let inbox = utf8(c.take(MAILBOX_ID_LEN)?)?;
    let secret: [u8; PAIRING_SECRET_LEN] = c
        .take(PAIRING_SECRET_LEN)?
        .try_into()
        .expect("slice of fixed length");
    if c.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in pairing offer"));
    }
    Ok((bundle, relay, inbox, secret))
}

/// Proof-of-scan MAC over `responder_bundle ‖ recovery_root_contribution`,
/// keyed by the offer's `pairing_secret` (HMAC-SHA256, INV-6; F2). Binding the
/// contribution into the MAC means an off-path party cannot substitute a
/// recovery-root contribution without failing proof-of-scan.
pub(crate) fn compute_proof_of_scan(
    pairing_secret: &[u8; PAIRING_SECRET_LEN],
    responder_bundle: &[u8],
    root_contribution: &[u8; RECOVERY_CONTRIB_LEN],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(responder_bundle.len() + RECOVERY_CONTRIB_LEN);
    input.extend_from_slice(responder_bundle);
    input.extend_from_slice(root_contribution);
    hmac_sha256(pairing_secret, &input)
}

/// Verifies a proof-of-scan MAC in CONSTANT TIME. `ProofOfScanFailed` on any
/// mismatch (the offerer then burns the offer, `proto/pairing.md`).
pub(crate) fn verify_proof_of_scan(
    pairing_secret: &[u8; PAIRING_SECRET_LEN],
    responder_bundle: &[u8],
    root_contribution: &[u8; RECOVERY_CONTRIB_LEN],
    mac: &[u8],
) -> Result<()> {
    use subtle::ConstantTimeEq;
    let expected = compute_proof_of_scan(pairing_secret, responder_bundle, root_contribution);
    if expected.ct_eq(mac).into() {
        Ok(())
    } else {
        Err(CoreError::ProofOfScanFailed)
    }
}

/// Fields of a decoded `pair-ack/2` (responder → offerer): B's bundle, routing
/// coords, B's recovery-root contribution, and the proof-of-scan MAC.
pub(crate) struct PairAckV2 {
    pub responder_bundle: Vec<u8>,
    pub relay_url: String,
    pub inbox_id: String,
    pub root_contribution: [u8; RECOVERY_CONTRIB_LEN],
    pub proof: [u8; 32],
}

/// Builds a `pair-ack/2` inner payload, computing the proof over
/// `responder_bundle` with `pairing_secret`.
pub(crate) fn encode_pair_ack_v2(
    responder_bundle: &[u8],
    relay_url: &str,
    inbox_id: &str,
    root_contribution: &[u8; RECOVERY_CONTRIB_LEN],
    pairing_secret: &[u8; PAIRING_SECRET_LEN],
) -> Vec<u8> {
    let proof = compute_proof_of_scan(pairing_secret, responder_bundle, root_contribution);
    let mut out = Vec::with_capacity(responder_bundle.len() + relay_url.len() + 128);
    out.push(PAIR_ACK_V2);
    put_bytes(&mut out, responder_bundle);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(inbox_id.as_bytes()); // fixed 43 bytes
    out.extend_from_slice(root_contribution);
    out.extend_from_slice(&proof);
    out
}

/// Parses a `pair-ack/2` payload (does NOT verify the proof — caller does).
pub(crate) fn parse_pair_ack_v2(bytes: &[u8]) -> Result<PairAckV2> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.u8()? != PAIR_ACK_V2 {
        return Err(CoreError::Malformed("unknown pair-ack version"));
    }
    let responder_bundle = c.bytes_field()?.to_vec();
    let relay_url = utf8(c.bytes_field()?)?;
    let inbox_id = utf8(c.take(MAILBOX_ID_LEN)?)?;
    let root_contribution: [u8; RECOVERY_CONTRIB_LEN] = c
        .take(RECOVERY_CONTRIB_LEN)?
        .try_into()
        .expect("slice of fixed length");
    let proof: [u8; 32] = c.take(32)?.try_into().expect("slice of fixed length");
    if c.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in pair-ack/2"));
    }
    Ok(PairAckV2 {
        responder_bundle,
        relay_url,
        inbox_id,
        root_contribution,
        proof,
    })
}

/// Builds a `mailbox-update/2` inner payload (inbox-handoff / rotation). The
/// contribution is present (all-32 bytes) at the pairing handoff (carries A's
/// recovery-root contribution) and ALL-ZERO for a recovery-time rotation, which
/// re-uses the existing root rather than re-deriving it.
pub(crate) fn encode_mailbox_update_v2(
    relay_url: &str,
    inbox_id: &str,
    root_contribution: &[u8; RECOVERY_CONTRIB_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(relay_url.len() + 96);
    out.push(MAILBOX_UPDATE_V2);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(inbox_id.as_bytes());
    out.extend_from_slice(root_contribution);
    out
}

/// Parses a `mailbox-update/2` payload → (relay, inbox, contribution). An
/// all-zero contribution means "rotation, no root re-derivation".
pub(crate) fn parse_mailbox_update_v2(
    bytes: &[u8],
) -> Result<(String, String, [u8; RECOVERY_CONTRIB_LEN])> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.u8()? != MAILBOX_UPDATE_V2 {
        return Err(CoreError::Malformed("unknown mailbox-update version"));
    }
    let relay_url = utf8(c.bytes_field()?)?;
    let inbox_id = utf8(c.take(MAILBOX_ID_LEN)?)?;
    let contribution: [u8; RECOVERY_CONTRIB_LEN] = c
        .take(RECOVERY_CONTRIB_LEN)?
        .try_into()
        .expect("slice of fixed length");
    if c.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in mailbox-update/2"));
    }
    Ok((relay_url, inbox_id, contribution))
}

fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| CoreError::Malformed("field is not UTF-8"))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(CoreError::Malformed("bundle length overflow"))?;
        if end > self.bytes.len() {
            return Err(CoreError::Malformed("truncated pairing bundle"));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn bytes_field(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    fn secret(seed: u8) -> [u8; PAIRING_SECRET_LEN] {
        [seed; PAIRING_SECRET_LEN]
    }

    #[test]
    fn proof_verifies_with_matching_secret_bundle_and_contribution() {
        let s = secret(0x11);
        let bundle = b"responder-prekey-bundle-bytes";
        let contrib = [0x99u8; RECOVERY_CONTRIB_LEN];
        let proof = compute_proof_of_scan(&s, bundle, &contrib);
        assert!(verify_proof_of_scan(&s, bundle, &contrib, &proof).is_ok());
    }

    #[test]
    fn proof_fails_on_wrong_secret_bundle_contribution_or_mac() {
        let s = secret(0x11);
        let bundle = b"responder-bundle";
        let contrib = [0x99u8; RECOVERY_CONTRIB_LEN];
        let proof = compute_proof_of_scan(&s, bundle, &contrib);
        // wrong secret → burn
        assert!(matches!(
            verify_proof_of_scan(&secret(0x22), bundle, &contrib, &proof),
            Err(CoreError::ProofOfScanFailed)
        ));
        // tampered bundle → burn
        assert!(matches!(
            verify_proof_of_scan(&s, b"tampered-bundle", &contrib, &proof),
            Err(CoreError::ProofOfScanFailed)
        ));
        // tampered contribution → burn (F2: contribution is in the MAC input)
        assert!(matches!(
            verify_proof_of_scan(&s, bundle, &[0x00u8; RECOVERY_CONTRIB_LEN], &proof),
            Err(CoreError::ProofOfScanFailed)
        ));
        // truncated / wrong-length mac → burn (constant-time ct_eq handles it)
        assert!(matches!(
            verify_proof_of_scan(&s, bundle, &contrib, &proof[..16]),
            Err(CoreError::ProofOfScanFailed)
        ));
    }

    #[test]
    fn offer_roundtrips_byte_exact() {
        let bundle = vec![1u8, 2, 3, 4, 5];
        let relay = "wss://relay.example/v1";
        let inbox = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
        let s = secret(0x33);
        let enc = encode_pairing_offer(&bundle, relay, inbox, &s);
        let (b2, r2, i2, s2) = parse_pairing_offer(&enc).unwrap();
        assert_eq!(b2, bundle);
        assert_eq!(r2, relay);
        assert_eq!(i2, inbox);
        assert_eq!(s2, s);
        // v1 payload version (0x01) must be rejected by the v2 parser.
        let mut v1 = enc.clone();
        v1[0] = 0x01;
        assert!(parse_pairing_offer(&v1).is_err());
    }

    #[test]
    fn pair_ack_v2_roundtrips_and_carries_verifiable_proof() {
        let bundle = b"B-bundle".to_vec();
        let contrib = [0x55u8; RECOVERY_CONTRIB_LEN];
        let s = secret(0x44);
        let enc = encode_pair_ack_v2(
            &bundle,
            "wss://b/v1",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            &contrib,
            &s,
        );
        let ack = parse_pair_ack_v2(&enc).unwrap();
        assert_eq!(ack.responder_bundle, bundle);
        assert_eq!(ack.root_contribution, contrib);
        // The offerer verifies B's proof with the pairing secret it minted.
        assert!(
            verify_proof_of_scan(
                &s,
                &ack.responder_bundle,
                &ack.root_contribution,
                &ack.proof
            )
            .is_ok()
        );
    }

    #[test]
    fn mailbox_update_v2_roundtrips_contribution() {
        let contrib = [0x77u8; RECOVERY_CONTRIB_LEN];
        let enc = encode_mailbox_update_v2(
            "wss://a/v1",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            &contrib,
        );
        let (r, i, c) = parse_mailbox_update_v2(&enc).unwrap();
        assert_eq!(r, "wss://a/v1");
        assert_eq!(i.len(), 43);
        assert_eq!(c, contrib);
    }
}
