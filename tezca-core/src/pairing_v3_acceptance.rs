// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Pair-offer v3 acceptance tests R1-R10 (freeze
//! `docs/design/2026-08-pair-offer-v3-freeze.md` §8; unit 5a-1 red phase).
//!
//! In-crate on purpose: the offer codec is `pub(crate)` (precedent:
//! `pairing::v2_tests`), and minting a signed offer with a controlled
//! `issued_at`/`ttl_s` needs the crate-internal encode path plus a real
//! libsignal identity keypair — no store, no relay, no network. The validity
//! clock is an explicit `now` parameter on the parse path (the 5a-1 time
//! seam): production passes the system clock, these tests inject fixed
//! instants.

use libsignal_protocol::KeyPair;
use rand::TryRngCore;

use crate::CoreError;
use crate::client::TitlanClient;
use crate::config::{FUTURE_SKEW_S, MAX_OFFER_TTL_S, OFFER_DEFAULT_TTL_S};
use crate::error::OfferExpiryDetail;
use crate::pairing::{self, BundleData, OFFER_SIG_LEN, PAIRING_SECRET_LEN};
use crate::storage::DbKey;

/// Fixed deterministic acceptor instant for the codec-level tests
/// (2026-08-12T12:40:00Z; bit 30 is set — R4 relies on that).
const T0: u64 = 1_755_000_000;

// Same loopback value the retired literal pinned; single-sourced in config
// because the INV-5 sweep cannot see this file's lib.rs `#[cfg(test)]` gate.
const RELAY: &str = crate::config::TEST_LOOPBACK_RELAY_URL;
const INBOX: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars
const SECRET: [u8; PAIRING_SECRET_LEN] = [0x42; PAIRING_SECRET_LEN];

fn test_identity() -> KeyPair {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    KeyPair::generate(&mut rng)
}

/// Offer-shaped bundle: production field sizes, synthetic prekey fill (the
/// codec verifies no prekey cryptography — INV-6), but a REAL identity public
/// key: the v3 `offer_sig` must verify against the key inside this bundle.
fn bundle_for(identity: &KeyPair) -> Vec<u8> {
    pairing::serialize(&BundleData {
        address_name: "a".repeat(66),
        registration_id: 0x1234,
        device_id: 1,
        identity_key: identity.public_key.serialize().to_vec(),
        signed_prekey_id: 7,
        signed_prekey_pub: vec![0x22; 33],
        signed_prekey_sig: vec![0x33; 64],
        kyber_prekey_id: 9,
        kyber_prekey_pub: vec![0x44; 1569],
        kyber_prekey_sig: vec![0x55; 64],
        onetime_prekey: Some((2, vec![0x66; 33])),
    })
}

/// Mints a v3 offer signed by `identity` with the given validity window.
fn mint(identity: &KeyPair, relay: &str, issued_at: u64, ttl_s: u32) -> Vec<u8> {
    pairing::encode_pairing_offer_v3(
        &bundle_for(identity),
        relay,
        INBOX,
        &SECRET,
        issued_at,
        ttl_s,
        &identity.private_key,
    )
    .expect("mint v3 offer")
}

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

// R1: fresh mint round-trips and accepts (freeze §8 R1).
#[test]
fn r1_fresh_mint_round_trips_and_accepts() {
    let id = test_identity();
    let enc = mint(&id, RELAY, T0, OFFER_DEFAULT_TTL_S);
    let offer = pairing::parse_pairing_offer_v3(&enc, T0 + 1).expect("fresh offer accepts");
    assert_eq!(offer.bundle, bundle_for(&id), "bundle round-trips");
    assert_eq!(offer.relay_url, RELAY, "relay round-trips");
    assert_eq!(offer.pairing_inbox_id, INBOX, "inbox round-trips");
    assert_eq!(offer.pairing_secret, SECRET, "secret round-trips");
    assert_eq!(offer.issued_at, T0, "issued_at round-trips");
    assert_eq!(offer.ttl_s, OFFER_DEFAULT_TTL_S, "ttl_s round-trips");
    // The mint path must SIGN: independent verification of the trailing 64 B
    // over the entire preceding prefix with the bundle's identity key (§2/§3).
    let (prefix, sig) = enc.split_at(enc.len() - OFFER_SIG_LEN);
    assert!(
        id.public_key.verify_signature(prefix, sig),
        "offer_sig must verify over the wire prefix with the bundle identity key"
    );
}

// R2: expired offer => OfferExpired{Expired} with ZERO network I/O attempted
// (freeze §4: evaluated at decode BEFORE any network I/O).
#[test]
fn r2_expired_offer_is_offer_expired_with_zero_network_io() {
    // Dead relay: bind-then-drop reserves a local port with nothing listening.
    // ANY attempted network I/O against it fails fast as CoreError::Network —
    // so observing OfferExpired proves the verdict was reached with zero
    // network I/O attempted.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe port");
        listener.local_addr().expect("probe addr").port()
    };
    let dead_relay = format!("https://127.0.0.1:{port}");

    let dir = tempfile::tempdir().expect("tempdir");
    let client = TitlanClient::open(
        &dir.path().join("titlan.db"),
        &DbKey::generate(),
        &dead_relay,
    )
    .expect("open client");
    client.initialize_identity().expect("initialize identity");

    // Offer from a peer identity, expired one full TTL ago (real clock: the
    // margin makes the verdict independent of test-run timing).
    let now = real_now();
    let peer = test_identity();
    let enc = mint(&peer, &dead_relay, now - 7200, 3600);

    match client.begin_pairing_from_offer(&enc) {
        Err(CoreError::OfferExpired {
            issued_at,
            ttl_s,
            now: seen,
            detail: OfferExpiryDetail::Expired,
        }) => {
            assert_eq!(
                issued_at,
                now - 7200,
                "error carries the embedded issued_at"
            );
            assert_eq!(ttl_s, 3600, "error carries the embedded ttl_s");
            assert!(
                seen >= issued_at + u64::from(ttl_s),
                "error carries a coherent now"
            );
        }
        Err(other) => {
            panic!("expected OfferExpired{{Expired}} with zero network I/O, got Err({other})")
        }
        Ok(_) => panic!("expected OfferExpired{{Expired}}, got Ok(..)"),
    }
}

// R3: boundary now == issued_at + ttl_s => expired; valid strictly before
// that instant (freeze §4 step 4).
#[test]
fn r3_boundary_now_equals_issued_plus_ttl_is_expired() {
    let id = test_identity();
    let enc = mint(&id, RELAY, T0, 3600);
    match pairing::parse_pairing_offer_v3(&enc, T0 + 3600) {
        Err(CoreError::OfferExpired {
            issued_at,
            ttl_s,
            now,
            detail: OfferExpiryDetail::Expired,
        }) => {
            assert_eq!(issued_at, T0);
            assert_eq!(ttl_s, 3600);
            assert_eq!(now, T0 + 3600);
        }
        Err(other) => panic!("expected OfferExpired{{Expired}} at the boundary, got Err({other})"),
        Ok(_) => panic!("expected OfferExpired{{Expired}} at the boundary, got Ok(..)"),
    }
    assert!(
        pairing::parse_pairing_offer_v3(&enc, T0 + 3599).is_ok(),
        "one second before the boundary must still accept"
    );
}

// R4: bit-flipped issued_at => OfferSignatureInvalid, NOT expired (freeze §4
// step 1 runs the signature check before any validity evaluation — the
// timestamp-resurrection defense of §3).
#[test]
fn r4_bit_flipped_issued_at_is_signature_invalid_not_expired() {
    let id = test_identity();
    let mut enc = mint(&id, RELAY, T0, 3600);
    // issued_at occupies the 8 bytes before ttl_s (4) + offer_sig (64).
    let issued_at_off = enc.len() - OFFER_SIG_LEN - 4 - 8;
    // Flip bit 30 (byte 4 of the big-endian u64, mask 0x40): set at T0, so
    // the flip re-dates the offer ~34 years into the past — an expiry-looking
    // tamper that must be reported as a signature failure, never as expiry.
    assert_eq!(
        enc[issued_at_off + 4] & 0x40,
        0x40,
        "bit 30 of issued_at is set at T0"
    );
    enc[issued_at_off + 4] ^= 0x40;
    match pairing::parse_pairing_offer_v3(&enc, T0 + 1) {
        Err(CoreError::OfferSignatureInvalid) => {}
        Err(other) => panic!(
            "expected OfferSignatureInvalid (never OfferExpired) for tampered issued_at, \
             got Err({other})"
        ),
        Ok(_) => panic!("expected OfferSignatureInvalid for tampered issued_at, got Ok(..)"),
    }
}

// R5: ttl_s == 0 and ttl_s > MAX_OFFER_TTL_S => malformed (freeze §4 step 2),
// even under a valid signature over those bytes.
#[test]
fn r5_ttl_zero_and_over_max_are_malformed() {
    let id = test_identity();
    for ttl in [0u32, MAX_OFFER_TTL_S + 1] {
        let enc = mint(&id, RELAY, T0, ttl);
        match pairing::parse_pairing_offer_v3(&enc, T0 + 1) {
            Err(CoreError::Malformed(_)) => {}
            Err(other) => panic!("expected Malformed for ttl_s {ttl}, got Err({other})"),
            Ok(_) => panic!("expected Malformed for ttl_s {ttl}, got Ok(..)"),
        }
    }
}

// R6: future-dated beyond the 300 s grace => OfferExpired{NotYetValid};
// exactly AT the grace bound is still admitted (freeze §4 step 3).
#[test]
fn r6_future_dated_beyond_grace_is_not_yet_valid() {
    let id = test_identity();
    let enc = mint(&id, RELAY, T0 + FUTURE_SKEW_S + 1, 3600);
    match pairing::parse_pairing_offer_v3(&enc, T0) {
        Err(CoreError::OfferExpired {
            detail: OfferExpiryDetail::NotYetValid,
            issued_at,
            now,
            ..
        }) => {
            assert_eq!(issued_at, T0 + FUTURE_SKEW_S + 1);
            assert_eq!(now, T0);
        }
        Err(other) => {
            panic!("expected OfferExpired{{NotYetValid}} beyond the skew grace, got Err({other})")
        }
        Ok(_) => panic!("expected OfferExpired{{NotYetValid}} beyond the skew grace, got Ok(..)"),
    }
    let at_grace = mint(&id, RELAY, T0 + FUTURE_SKEW_S, 3600);
    assert!(
        pairing::parse_pairing_offer_v3(&at_grace, T0).is_ok(),
        "issued_at == now + FUTURE_SKEW_S must still be admitted"
    );
}

// R7: the committed v2 fixture corpus (4b2-codec-fixture-tests) is the
// rejection input: v2 bytes => unsupported-version (freeze §7, V3-D4 — no
// compatibility window).
#[test]
fn r7_v2_fixture_bytes_are_unsupported_version() {
    let fragment = V2_FIXTURE_LINK
        .strip_prefix("titlan://pair#")
        .expect("committed v2 link carries the titlan://pair# prefix");
    let payload = b64url_decode(fragment);
    match pairing::parse_pairing_offer_v3(&payload, T0) {
        Err(CoreError::UnsupportedVersion { got: 2 }) => {}
        Err(other) => {
            panic!("expected UnsupportedVersion{{got: 2}} for the v2 corpus, got Err({other})")
        }
        Ok(_) => panic!("expected UnsupportedVersion{{got: 2}} for the v2 corpus, got Ok(..)"),
    }
}

// R8: trailing bytes after offer_sig => reject (freeze §2, symmetry per
// work-order item 18d).
#[test]
fn r8_trailing_bytes_after_offer_sig_reject() {
    let id = test_identity();
    let mut enc = mint(&id, RELAY, T0, 3600);
    enc.extend_from_slice(&[0xDE, 0xAD]);
    match pairing::parse_pairing_offer_v3(&enc, T0 + 1) {
        Err(CoreError::Malformed(_)) => {}
        Err(other) => panic!("expected Malformed for trailing bytes, got Err({other})"),
        Ok(_) => panic!("expected Malformed for trailing bytes, got Ok(..)"),
    }
}

// R9: the deposit-harness fuse == the embedded ttl_s (freeze §6). The fuse
// (and the UI countdown) read the window through this one public surface:
// TitlanClient::peek_offer_validity on the minted offer's bytes.
#[test]
fn r9_harness_fuse_equals_embedded_ttl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let client = TitlanClient::open(
        &dir.path().join("titlan.db"),
        &DbKey::generate(),
        crate::config::DEFAULT_RELAY_URL,
    )
    .expect("open client");
    let id = test_identity();
    let enc = mint(&id, RELAY, T0, 7200);
    let validity = client.peek_offer_validity(&enc).expect("peek validity");
    assert_eq!(
        validity.ttl_s, 7200,
        "the harness-fuse source must equal the embedded ttl_s"
    );
    assert_eq!(
        validity.issued_at, T0,
        "the countdown anchor must equal the embedded issued_at"
    );
}

// R10: QR/link byte-identity round-trip holds for v3 bytes (freeze §2: QR and
// titlan://pair# remain byte-identical carriers), and the carried signature
// stays live — the +76 B v3 tail rides the carrier intact.
#[test]
fn r10_qr_link_byte_identity_round_trip_v3() {
    let id = test_identity();
    let enc = mint(&id, RELAY, T0, OFFER_DEFAULT_TTL_S);
    let link = format!("titlan://pair#{}", b64url_encode(&enc));
    let decoded = b64url_decode(link.strip_prefix("titlan://pair#").expect("link prefix"));
    assert_eq!(
        decoded, enc,
        "QR/link carrier must be byte-identical for v3 bytes"
    );
    let offer = pairing::parse_pairing_offer_v3(&decoded, T0 + 1).expect("carried offer accepts");
    assert_eq!(offer.issued_at, T0, "carried issued_at intact");
    assert_eq!(offer.ttl_s, OFFER_DEFAULT_TTL_S, "carried ttl_s intact");
    let (prefix, sig) = decoded.split_at(decoded.len() - OFFER_SIG_LEN);
    assert!(
        id.public_key.verify_signature(prefix, sig),
        "round-tripped offer_sig must still verify with the bundle identity key"
    );
}

// ---- committed v2 corpus + base64url link codec (test-side tooling) --------
// The b64url helpers mirror pairing::v2_tests / examples/deposit_harness.rs:
// hand-rolled to stay dependency-free — an encoding, not cryptography (INV-6
// untouched).

const V2_FIXTURE_LINK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../proto/fixtures/pairing-offer-v2.link.txt"
));

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
        // Byte extraction via to_be_bytes: for a k-chunk, the decoded 6k-bit
        // group is left-aligned to bit 23 and the top full bytes are taken.
        match chunk.len() {
            4 => out.extend_from_slice(&n.to_be_bytes()[1..4]),
            3 => out.extend_from_slice(&(n << 6).to_be_bytes()[1..3]),
            2 => out.push((n << 4).to_be_bytes()[2]),
            _ => unreachable!("length % 4 == 1 rejected above"),
        }
    }
    out
}
