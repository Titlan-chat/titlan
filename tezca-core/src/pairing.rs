// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Pairing bundle framing per `proto/pairing.md` (v1). Pure serialization —
//! all key material inside is produced and validated by libsignal (INV-6).

use rand::TryRngCore;

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
    if let Some((id, key)) = &data.onetime_prekey {
        out.extend_from_slice(&id.to_be_bytes());
        put_bytes(&mut out, key);
    } else {
        out.extend_from_slice(&ABSENT_ID.to_be_bytes());
        put_bytes(&mut out, &[]);
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
    if device_id != 1 {
        // v1 conformance (freeze §H2.2): the u32 field is wire headroom, but
        // protocol v1 admits exactly device_id 1 — anything else is rejected
        // at parse time, fail-closed, before any session state is touched.
        return Err(CoreError::Malformed("unsupported device id in v1"));
    }
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
    if c.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in mailbox-update/1"));
    }
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
/// `pair-ack` `type_version` for the v2 pairing response (rides byte 0x05).
pub(crate) const PAIR_ACK_V2: u8 = 2;
/// `mailbox-update` `type_version` for the v2 pairing inbox-handoff (rides 0x06).
pub(crate) const MAILBOX_UPDATE_V2: u8 = 2;
/// `mailbox-update` `type_version` for the v3 recovery-rotation handoff (rides
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

// The v2 offer codec (`encode_pairing_offer`/`parse_pairing_offer`) is
// RETIRED per freeze §7 (V3-D4: v3-only acceptor, no compatibility window).
// The committed v2 fixture corpus remains as the R7 rejection input and the
// Kotlin-side QR-codec conformance vector.

// --- 5a-1: pair-offer v3 (freeze `docs/design/2026-08-pair-offer-v3-freeze.md`
// §2-§4, V3-D1/D2/D3). The offer gains an authenticated validity window:
// issued_at (u64 BE seconds) + ttl_s (u32 BE), then a fixed 64 B XEd25519
// `offer_sig` by the offer's identity key over ALL preceding wire bytes.
// Sign-the-wire-bytes / verify-the-wire-bytes: the signed region is the exact
// serialized prefix — no canonicalization layer exists to get wrong. ---------

/// Offer payload version (v3 authenticated-validity offer). The acceptor is
/// v3-only (V3-D4): `0x01`/`0x02` are unsupported-version rejects.
pub(crate) const OFFER_VERSION_V3: u8 = 3;
/// Fixed length of the trailing `XEd25519` `offer_sig` (freeze §2).
pub(crate) const OFFER_SIG_LEN: usize = 64;

/// Decoded v3 offer fields (freeze §2), yielded only after the full §4
/// validity rule has passed.
pub(crate) struct OfferV3 {
    pub bundle: Vec<u8>,
    pub relay_url: String,
    pub pairing_inbox_id: String,
    pub pairing_secret: [u8; PAIRING_SECRET_LEN],
    pub issued_at: u64,
    pub ttl_s: u32,
}

/// The validity window an offer embeds at mint — the single value the UI
/// countdown and deposit-harness fuse read (freeze §6).
pub(crate) struct OfferValidity {
    pub issued_at: u64,
    pub ttl_s: u32,
}

/// Encodes a v3 pairing offer (freeze §2): version, bundle, relay, pairing
/// inbox, pairing secret, `issued_at`, `ttl_s`, then `offer_sig` — a fixed
/// 64 B `XEd25519` signature by the offer's identity private key over the
/// entire preceding prefix. Sign-the-wire-bytes: the signed region is the
/// exact serialized prefix, no canonicalization layer.
pub(crate) fn encode_pairing_offer_v3(
    bundle: &[u8],
    relay_url: &str,
    pairing_inbox_id: &str,
    pairing_secret: &[u8; PAIRING_SECRET_LEN],
    issued_at: u64,
    ttl_s: u32,
    identity_private: &libsignal_protocol::PrivateKey,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(bundle.len() + relay_url.len() + 176);
    out.push(OFFER_VERSION_V3);
    put_bytes(&mut out, bundle);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(pairing_inbox_id.as_bytes()); // fixed 43 bytes
    out.extend_from_slice(pairing_secret);
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&ttl_s.to_be_bytes());
    // The same libsignal primitive the signed-prekey mint uses (INV-6; the
    // V3-V1 obligation of freeze §9, discharged at the 5a-1 order's T0).
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let sig = identity_private
        .calculate_signature(&out, &mut rng)
        .map_err(crate::identity::signal_err)?;
    if sig.len() != OFFER_SIG_LEN {
        return Err(CoreError::Signal(
            "unexpected offer signature length".into(),
        ));
    }
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Structural parse of a v3 offer (freeze §2): version byte, field
/// extraction, trailing-byte reject. NO signature or clock evaluation — that
/// is [`parse_pairing_offer_v3`]. This is the read behind the offerer-side
/// peeks (relay confirmation, countdown/fuse), which make no accept decision.
pub(crate) fn parse_offer_v3_structure(bytes: &[u8]) -> Result<OfferV3> {
    let mut c = Cursor { bytes, pos: 0 };
    let version = c.u8()?;
    if version != OFFER_VERSION_V3 {
        // v3-only acceptor (V3-D4): v1/v2 — and anything unknown — rejects.
        return Err(CoreError::UnsupportedVersion { got: version });
    }
    let bundle = c.bytes_field()?.to_vec();
    let relay_url = utf8(c.bytes_field()?)?;
    let pairing_inbox_id = utf8(c.take(MAILBOX_ID_LEN)?)?;
    let pairing_secret: [u8; PAIRING_SECRET_LEN] = c
        .take(PAIRING_SECRET_LEN)?
        .try_into()
        .expect("slice of fixed length");
    let issued_at = c.u64()?;
    let ttl_s = c.u32()?;
    let _sig = c.take(OFFER_SIG_LEN)?;
    if c.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in pairing offer"));
    }
    Ok(OfferV3 {
        bundle,
        relay_url,
        pairing_inbox_id,
        pairing_secret,
        issued_at,
        ttl_s,
    })
}

/// Parses and validates a v3 offer at acceptor clock `now` (Unix seconds) —
/// the full freeze §4 rule, evaluated at decode BEFORE any network I/O. `now`
/// is an explicit parameter (the 5a-1 time seam): production callers pass the
/// system clock at the call site; tests inject a deterministic instant.
pub(crate) fn parse_pairing_offer_v3(bytes: &[u8], now: u64) -> Result<OfferV3> {
    // §4 step 1: structure + version (structural errors / unsupported-version)…
    let offer = parse_offer_v3_structure(bytes)?;
    // …then signature: the identity key inside the offer's OWN bundle verifies
    // the trailing 64 B over the entire preceding prefix (§3; INV-6). The
    // structural parse above proved exact length, so the suffix split is safe.
    let bundle_data = parse(&offer.bundle)?;
    let identity_key = libsignal_protocol::PublicKey::deserialize(&bundle_data.identity_key)
        .map_err(crate::identity::signal_err)?;
    let (prefix, sig) = bytes.split_at(bytes.len() - OFFER_SIG_LEN);
    if !identity_key.verify_signature(prefix, sig) {
        return Err(CoreError::OfferSignatureInvalid);
    }
    // §4 step 2: TTL bounds.
    if offer.ttl_s == 0 || offer.ttl_s > crate::config::MAX_OFFER_TTL_S {
        return Err(CoreError::Malformed("offer ttl_s out of range"));
    }
    // §4 step 3: future-skew grace (also catches issued_at values whose
    // step-4 sum would saturate).
    if offer.issued_at > now.saturating_add(crate::config::FUTURE_SKEW_S) {
        return Err(CoreError::OfferExpired {
            issued_at: offer.issued_at,
            ttl_s: offer.ttl_s,
            now,
            detail: crate::error::OfferExpiryDetail::NotYetValid,
        });
    }
    // §4 step 4: expired iff now >= issued_at + ttl_s; valid strictly before.
    if now >= offer.issued_at.saturating_add(u64::from(offer.ttl_s)) {
        return Err(CoreError::OfferExpired {
            issued_at: offer.issued_at,
            ttl_s: offer.ttl_s,
            now,
            detail: crate::error::OfferExpiryDetail::Expired,
        });
    }
    Ok(offer)
}

/// Reads the embedded validity window from an offer without accepting it —
/// the offerer-side read behind the UI countdown and the deposit-harness fuse
/// (freeze §6: ONE governing value; no signature or clock evaluation, no
/// network).
pub(crate) fn peek_offer_validity(bytes: &[u8]) -> Result<OfferValidity> {
    let offer = parse_offer_v3_structure(bytes)?;
    Ok(OfferValidity {
        issued_at: offer.issued_at,
        ttl_s: offer.ttl_s,
    })
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

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
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

#[cfg(test)]
mod v1_conformance_tests {
    use super::*;

    fn bundle_with_device_id(device_id: u32) -> BundleData {
        let mut identity_key = vec![0x11u8; 33];
        identity_key[0] = 0x05; // libsignal EC point type byte — shape realism only
        BundleData {
            address_name: "a".repeat(66),
            registration_id: 0x1234,
            device_id,
            identity_key,
            signed_prekey_id: 7,
            signed_prekey_pub: vec![0x22; 33],
            signed_prekey_sig: vec![0x33; 64],
            kyber_prekey_id: 9,
            kyber_prekey_pub: vec![0x44; 1569],
            kyber_prekey_sig: vec![0x55; 64],
            onetime_prekey: Some((2, vec![0x66; 33])),
        }
    }

    // 18a (freeze §H2.2, proto/pairing.md receiver rule): in protocol v1 the
    // bundle's device_id MUST be 1; parsers MUST reject any other value as
    // malformed.
    #[test]
    fn bundle_with_device_id_other_than_1_is_malformed() {
        match parse(&serialize(&bundle_with_device_id(2))) {
            Err(CoreError::Malformed(_)) => {}
            Err(other) => panic!("expected Malformed, got Err({other:?})"),
            Ok(_) => panic!("expected Malformed, got Ok(..)"),
        }
    }

    // 18d: a mailbox-update/1 payload with trailing bytes after the fixed
    // 43-char inbox id must be rejected, symmetric with /2 and /3.
    #[test]
    fn mailbox_update_v1_with_trailing_bytes_is_malformed() {
        let inbox = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
        let mut payload = encode_mailbox_update("wss://relay.example/v1", inbox);
        payload.extend_from_slice(&[0xDE, 0xAD]);
        match parse_mailbox_update(&payload) {
            Err(CoreError::Malformed(_)) => {}
            Err(other) => panic!("expected Malformed, got Err({other:?})"),
            Ok(ok) => panic!("expected Malformed, got Ok({ok:?})"),
        }
    }
}

// ---- committed QR-codec conformance vector (4b2-WO-codec-fixture-tests; ----
// v3 vector per the pair-offer v3 freeze, unit 5a-1). The QrCodec
// dual-sourcing ledger item, a permanent guard: ONE committed pairing-offer
// vector (proto/fixtures/pairing-offer-v3.*) is decoded and parsed by BOTH
// stacks — this module (Rust) and the app's plain-JVM QrCodecConformanceTest
// (Kotlin) — so the link wire encoding cannot drift on either side without a
// red build. The v2 vector remains committed as the acceptance R7
// rejection input (v3-only acceptor, freeze §7).
//
// Unlike the retired v2 vector, the v3 vector is not regenerable from source
// alone: `offer_sig` is a randomized XEd25519 signature by a generated
// identity key. It IS fully deterministic to VERIFY: the §2 prefix (all bytes
// before `offer_sig`) rebuilds exactly from this file plus the pinned
// `identity_pub`, and signature verification is deterministic. Regeneration
// is the manual ignored test below.
#[cfg(test)]
mod v3_conformance_tests {
    use super::*;

    const CONFORMANCE_RELAY: &str = crate::config::TEST_LOOPBACK_RELAY_URL;
    const CONFORMANCE_INBOX: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const CONFORMANCE_SECRET: [u8; PAIRING_SECRET_LEN] = [0x42; PAIRING_SECRET_LEN];
    /// Fixed mint instant (2026-08-12T12:40:00Z); the parse below injects
    /// `issued_at + 1` through the 5a-1 time seam, so validity is
    /// deterministic regardless of the wall clock.
    const CONFORMANCE_ISSUED_AT: u64 = 1_755_000_000;
    const CONFORMANCE_TTL_S: u32 = crate::config::OFFER_DEFAULT_TTL_S;

    const CONFORMANCE_LINK: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../proto/fixtures/pairing-offer-v3.link.txt"
    ));
    const CONFORMANCE_EXPECTED: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../proto/fixtures/pairing-offer-v3.expected.txt"
    ));

    /// Offer-shaped bundle: production field SIZES (66-char address, 33-byte
    /// EC keys, 64-byte sigs, 1569-byte Kyber-1024 pub, per-offer onetime
    /// id 2), synthetic prekey CONTENT (fixed fills; the codec verifies no
    /// prekey cryptography — INV-6), but the REAL pinned identity public key:
    /// `offer_sig` must verify against the key inside this bundle (§3).
    fn conformance_bundle(identity_pub: &[u8]) -> BundleData {
        BundleData {
            address_name: "a".repeat(66),
            registration_id: 0x1234,
            device_id: 1,
            identity_key: identity_pub.to_vec(),
            signed_prekey_id: 7,
            signed_prekey_pub: vec![0x22; 33],
            signed_prekey_sig: vec![0x33; 64],
            kyber_prekey_id: 9,
            kyber_prekey_pub: vec![0x44; 1569],
            kyber_prekey_sig: vec![0x55; 64],
            onetime_prekey: Some((2, vec![0x66; 33])),
        }
    }

    /// The freeze-§2 signed region, rebuilt independently of
    /// [`encode_pairing_offer_v3`] — a layout drift between the encoder and
    /// the frozen field order reddens this test.
    fn conformance_prefix(identity_pub: &[u8]) -> Vec<u8> {
        let bundle = serialize(&conformance_bundle(identity_pub));
        let mut out = Vec::with_capacity(bundle.len() + 128);
        out.push(OFFER_VERSION_V3);
        put_bytes(&mut out, &bundle);
        put_bytes(&mut out, CONFORMANCE_RELAY.as_bytes());
        out.extend_from_slice(CONFORMANCE_INBOX.as_bytes());
        out.extend_from_slice(&CONFORMANCE_SECRET);
        out.extend_from_slice(&CONFORMANCE_ISSUED_AT.to_be_bytes());
        out.extend_from_slice(&CONFORMANCE_TTL_S.to_be_bytes());
        out
    }

    fn conformance_expected(key: &str) -> String {
        CONFORMANCE_EXPECTED
            .lines()
            .find_map(|l| {
                l.strip_prefix(key)
                    .and_then(|r| r.strip_prefix('='))
                    .map(str::to_string)
            })
            .unwrap_or_else(|| panic!("missing {key} in expected fixture"))
    }

    #[test]
    fn committed_conformance_vector_link_round_trips_and_parses() {
        let fragment = CONFORMANCE_LINK
            .strip_prefix("titlan://pair#")
            .expect("committed link carries the titlan://pair# prefix");

        // Decode the committed link; the encode direction must reproduce the
        // committed fragment byte-for-byte (link-encode → decode round-trip).
        let payload = b64url_decode(fragment);
        assert_eq!(
            b64url_encode(&payload),
            fragment,
            "b64url re-encode mismatch"
        );

        // Pinned decoded-bytes hash + length (single-sourced with the Kotlin
        // side via proto/fixtures/pairing-offer-v3.expected.txt). SHA-256 via
        // signal-crypto — the ratified crypto source (INV-6), no new crates.
        let mut hasher = signal_crypto::CryptographicHash::new("Sha256")
            .expect("Sha256 is a supported signal-crypto digest");
        hasher.update(&payload);
        assert_eq!(
            hex::encode(hasher.finalize()),
            conformance_expected("decoded_sha256"),
            "pinned decoded-bytes sha256"
        );
        assert_eq!(
            payload.len().to_string(),
            conformance_expected("decoded_len"),
            "pinned decoded-bytes length"
        );

        // The §2 prefix is deterministic from the pinned identity key: the
        // committed bytes before `offer_sig` must equal the in-repo
        // construction exactly.
        let identity_pub =
            hex::decode(conformance_expected("identity_pub")).expect("identity_pub hex");
        assert_eq!(
            payload[..payload.len() - OFFER_SIG_LEN],
            conformance_prefix(&identity_pub)[..],
            "committed prefix != deterministic freeze-§2 construction"
        );

        // The real acceptor path takes the vector: structure, SIGNATURE
        // VERIFICATION with the bundle's pinned identity key, and the §4
        // validity rule at an injected instant inside the window.
        let offer = parse_pairing_offer_v3(&payload, CONFORMANCE_ISSUED_AT + 1)
            .expect("committed vector parses, verifies, and is valid at issued_at + 1");
        assert_eq!(
            offer.relay_url,
            conformance_expected("relay"),
            "pinned relay"
        );
        assert_eq!(
            offer.pairing_inbox_id,
            conformance_expected("inbox"),
            "pinned inbox"
        );
        assert_eq!(
            offer.pairing_secret, CONFORMANCE_SECRET,
            "pinned pairing secret"
        );
        assert_eq!(
            offer.issued_at.to_string(),
            conformance_expected("issued_at"),
            "pinned issued_at"
        );
        assert_eq!(
            offer.ttl_s.to_string(),
            conformance_expected("ttl_s"),
            "pinned ttl_s"
        );
        assert_eq!(
            offer.bundle.len().to_string(),
            conformance_expected("bundle_len"),
            "pinned bundle length"
        );
        let data = parse(&offer.bundle).expect("committed bundle parses");
        assert_eq!(data.identity_key, identity_pub, "pinned identity key");
        let onetime_id = data
            .onetime_prekey
            .as_ref()
            .map(|(id, _)| *id)
            .expect("onetime prekey present");
        assert_eq!(
            onetime_id.to_string(),
            conformance_expected("onetime_id"),
            "pinned onetime id"
        );
        assert_eq!(data.kyber_prekey_pub.len(), 1569, "kyber pub length");
    }

    /// One-shot fixture mint. `offer_sig` is randomized, so regeneration is
    /// manual: `cargo test -p tezca-core regen_committed_v3_vector --
    /// --ignored --nocapture`, then commit BOTH printed file bodies together
    /// (the link file with NO trailing newline).
    #[test]
    #[ignore = "prints new proto/fixtures/pairing-offer-v3.* bodies; run manually"]
    fn regen_committed_v3_vector() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let identity = libsignal_protocol::KeyPair::generate(&mut rng);
        let identity_pub = identity.public_key.serialize();
        let bundle = serialize(&conformance_bundle(&identity_pub));
        let payload = encode_pairing_offer_v3(
            &bundle,
            CONFORMANCE_RELAY,
            CONFORMANCE_INBOX,
            &CONFORMANCE_SECRET,
            CONFORMANCE_ISSUED_AT,
            CONFORMANCE_TTL_S,
            &identity.private_key,
        )
        .expect("mint v3 conformance offer");
        let mut hasher = signal_crypto::CryptographicHash::new("Sha256")
            .expect("Sha256 is a supported signal-crypto digest");
        hasher.update(&payload);
        println!("--- pairing-offer-v3.link.txt (no trailing newline) ---");
        println!("titlan://pair#{}", b64url_encode(&payload));
        println!("--- pairing-offer-v3.expected.txt ---");
        println!("decoded_sha256={}", hex::encode(hasher.finalize()));
        println!("decoded_len={}", payload.len());
        println!("relay={CONFORMANCE_RELAY}");
        println!("inbox={CONFORMANCE_INBOX}");
        println!("onetime_id=2");
        println!("bundle_len={}", bundle.len());
        println!("identity_pub={}", hex::encode(&identity_pub));
        println!("issued_at={CONFORMANCE_ISSUED_AT}");
        println!("ttl_s={CONFORMANCE_TTL_S}");
    }

    // base64url (no padding), mirroring examples/deposit_harness.rs and the
    // 5a-1 acceptance suite: hand-rolled to stay dependency-free — an
    // encoding, not cryptography (INV-6 untouched).
    const B64URL_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn b64url_encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
            let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(B64URL_ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(B64URL_ALPHABET[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(B64URL_ALPHABET[(n >> 6) as usize & 63] as char);
            }
            if chunk.len() > 2 {
                out.push(B64URL_ALPHABET[n as usize & 63] as char);
            }
        }
        out
    }

    /// Strict RFC 4648 url-safe decode: url alphabet only, no padding, no
    /// whitespace — anything else panics (this is test-side tooling).
    fn b64url_decode(s: &str) -> Vec<u8> {
        let val = |c: u8| -> u32 {
            let pos = B64URL_ALPHABET
                .iter()
                .position(|&a| a == c)
                .unwrap_or_else(|| panic!("non-b64url byte {c:#04x}"));
            u32::try_from(pos).expect("alphabet index < 64")
        };
        let bytes = s.as_bytes();
        assert!(bytes.len() % 4 != 1, "invalid b64url length");
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
        for chunk in bytes.chunks(4) {
            let n = chunk.iter().fold(0u32, |acc, &c| (acc << 6) | val(c));
            // Byte extraction via to_be_bytes: for a k-chunk, the decoded
            // 6k-bit group is left-aligned to bit 23 and the top full bytes
            // are taken.
            match chunk.len() {
                4 => out.extend_from_slice(&n.to_be_bytes()[1..4]),
                3 => out.extend_from_slice(&(n << 6).to_be_bytes()[1..3]),
                2 => out.push((n << 4).to_be_bytes()[2]),
                _ => unreachable!("length % 4 == 1 rejected above"),
            }
        }
        out
    }
}
