// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Envelope specification tests: golden vectors (normative copies live in
//! proto/envelope.md), first-class platform payload types, and §8 negative
//! tests. All parse failures must be typed errors — never panics.

use proptest::prelude::*;
use tezca_core::CoreError;
use tezca_core::config::PaddingProfile;
use tezca_core::envelope::{Envelope, EnvelopeKind, InnerFrame, PayloadType};

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Golden vectors — NORMATIVE (proto/envelope.md §Test vectors)
// ---------------------------------------------------------------------------

#[test]
fn golden_outer_ratchet() {
    let env = Envelope {
        kind: EnvelopeKind::Ratchet,
        ciphertext: vec![0xAA; 16],
    };
    let wire = env.encode();
    assert_eq!(
        hex_of(&wire),
        "545a434101020000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(Envelope::parse(&wire).unwrap(), env);
}

#[test]
fn golden_outer_session_setup() {
    let env = Envelope {
        kind: EnvelopeKind::SessionSetup,
        ciphertext: vec![0x01, 0x02, 0x03],
    };
    assert_eq!(hex_of(&env.encode()), "545a434101010000010203");
    assert_eq!(Envelope::parse(&env.encode()).unwrap(), env);
}

#[test]
fn golden_inner_chat_v1() {
    let profile = PaddingProfile::default_profile();
    let frame = InnerFrame::chat_v1("hi titlan");
    let encoded = frame.encode(&profile).unwrap();
    assert_eq!(encoded.len(), 512, "9-byte chat pads to the 512 bucket");
    assert_eq!(hex_of(&encoded[..15]), "0101000000096869207469746c616e");
    assert!(encoded[15..].iter().all(|&b| b == 0), "padding is all zero");
    assert_eq!(InnerFrame::parse(&encoded, &profile).unwrap(), frame);
}

#[test]
fn golden_inner_posture_v1_empty() {
    let profile = PaddingProfile::default_profile();
    let frame = InnerFrame {
        payload_type: PayloadType::Posture,
        type_version: 1,
        payload: vec![],
    };
    let encoded = frame.encode(&profile).unwrap();
    assert_eq!(encoded.len(), 512);
    assert_eq!(hex_of(&encoded[..6]), "020100000000");
    assert!(encoded[6..].iter().all(|&b| b == 0));
    assert_eq!(InnerFrame::parse(&encoded, &profile).unwrap(), frame);
}

#[test]
fn golden_inner_alert_v1() {
    let profile = PaddingProfile::default_profile();
    let frame = InnerFrame {
        payload_type: PayloadType::Alert,
        type_version: 1,
        payload: vec![0xDE, 0xAD],
    };
    let encoded = frame.encode(&profile).unwrap();
    assert_eq!(encoded.len(), 512);
    assert_eq!(hex_of(&encoded[..8]), "040100000002dead");
    assert_eq!(InnerFrame::parse(&encoded, &profile).unwrap(), frame);
}

// ---------------------------------------------------------------------------
// Platform payload types are FIRST-CLASS: they round-trip today; only the
// application-level chat extraction declines them.
// ---------------------------------------------------------------------------

#[test]
fn reserved_types_round_trip_as_first_class_frames() {
    let profile = PaddingProfile::default_profile();
    for (pt, version) in [
        (PayloadType::Posture, 1u8),
        (PayloadType::Policy, 1),
        (PayloadType::Alert, 1),
        (PayloadType::Posture, 2), // future posture/2 still frames cleanly
    ] {
        let frame = InnerFrame {
            payload_type: pt,
            type_version: version,
            payload: b"machine payload".to_vec(),
        };
        let encoded = frame.encode(&profile).unwrap();
        let parsed = InnerFrame::parse(&encoded, &profile).unwrap();
        assert_eq!(parsed, frame, "{pt:?}/{version} must round-trip");
    }
}

#[test]
fn chat_extraction_declines_machine_payloads_gracefully() {
    let frame = InnerFrame {
        payload_type: PayloadType::Posture,
        type_version: 1,
        payload: vec![1, 2, 3],
    };
    match frame.into_chat_v1() {
        Err(CoreError::RecognizedButUnsupported {
            payload_type: PayloadType::Posture,
            type_version: 1,
        }) => {}
        other => panic!("expected RecognizedButUnsupported, got {other:?}"),
    }
}

#[test]
fn unknown_type_is_a_protocol_error_not_a_recognized_one() {
    let profile = PaddingProfile::default_profile();
    // Valid 512-byte frame except payload_type = 0x4A (unassigned).
    let mut bytes = vec![0u8; 512];
    bytes[0] = 0x4A;
    bytes[1] = 0x01;
    match InnerFrame::parse(&bytes, &profile) {
        Err(CoreError::UnknownPayloadType { got: 0x4A }) => {}
        other => panic!("expected UnknownPayloadType, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Bucket arithmetic and oversize behavior
// ---------------------------------------------------------------------------

#[test]
fn bucket_boundaries() {
    let profile = PaddingProfile::default_profile();
    // 506-byte payload → 512 exactly.
    let f = InnerFrame {
        payload_type: PayloadType::Chat,
        type_version: 1,
        payload: vec![7; 506],
    };
    assert_eq!(f.encode(&profile).unwrap().len(), 512);
    // 507-byte payload → next bucket (2048).
    let f = InnerFrame {
        payload: vec![7; 507],
        ..f
    };
    assert_eq!(f.encode(&profile).unwrap().len(), 2048);
    // Maximum payload → 8192 exactly.
    let f = InnerFrame {
        payload: vec![7; 8186],
        ..f
    };
    assert_eq!(f.encode(&profile).unwrap().len(), 8192);
}

#[test]
fn oversize_fails_before_any_crypto() {
    let profile = PaddingProfile::default_profile();
    let f = InnerFrame {
        payload_type: PayloadType::Chat,
        type_version: 1,
        payload: vec![7; 8187],
    };
    match f.encode(&profile) {
        Err(CoreError::PayloadTooLarge {
            len: 8187,
            max: 8186,
        }) => {}
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
}

#[test]
fn single_bucket_profile_pads_everything_to_one_size() {
    let profile = PaddingProfile::single(8192).unwrap();
    let small = InnerFrame::chat_v1("x").encode(&profile).unwrap();
    let large = InnerFrame {
        payload_type: PayloadType::Chat,
        type_version: 1,
        payload: vec![7; 4000],
    }
    .encode(&profile)
    .unwrap();
    assert_eq!(small.len(), 8192);
    assert_eq!(large.len(), 8192);
}

// ---------------------------------------------------------------------------
// §8 negative tests: outer envelope
// ---------------------------------------------------------------------------

#[test]
fn outer_negatives() {
    // Truncated inputs.
    assert!(matches!(Envelope::parse(&[]), Err(CoreError::Malformed(_))));
    assert!(matches!(
        Envelope::parse(&[0x54, 0x5A, 0x43, 0x41, 0x01, 0x02, 0x00]),
        Err(CoreError::Malformed(_))
    ));
    // Header only, no ciphertext.
    assert!(matches!(
        Envelope::parse(&[0x54, 0x5A, 0x43, 0x41, 0x01, 0x02, 0x00, 0x00]),
        Err(CoreError::Malformed(_))
    ));
    // Bad magic.
    assert!(matches!(
        Envelope::parse(&[0x54, 0x5A, 0x43, 0x42, 0x01, 0x02, 0x00, 0x00, 0xFF]),
        Err(CoreError::Malformed(_))
    ));
    // Wrong version.
    assert!(matches!(
        Envelope::parse(&[0x54, 0x5A, 0x43, 0x41, 0x02, 0x02, 0x00, 0x00, 0xFF]),
        Err(CoreError::UnsupportedVersion { got: 2 })
    ));
    // Unknown kind.
    assert!(matches!(
        Envelope::parse(&[0x54, 0x5A, 0x43, 0x41, 0x01, 0x03, 0x00, 0x00, 0xFF]),
        Err(CoreError::UnknownEnvelopeKind { got: 3 })
    ));
    // Reserved bytes non-zero.
    assert!(matches!(
        Envelope::parse(&[0x54, 0x5A, 0x43, 0x41, 0x01, 0x02, 0x00, 0x01, 0xFF]),
        Err(CoreError::ReservedMustBeZero)
    ));
}

// ---------------------------------------------------------------------------
// §8 negative tests: inner frame
// ---------------------------------------------------------------------------

#[test]
fn inner_negatives() {
    let profile = PaddingProfile::default_profile();

    // Length not exactly a bucket.
    assert!(matches!(
        InnerFrame::parse(&vec![0u8; 513], &profile),
        Err(CoreError::InvalidBucket { frame_len: 513 })
    ));
    assert!(matches!(
        InnerFrame::parse(&[0x01, 0x01, 0, 0, 0, 0], &profile),
        Err(CoreError::InvalidBucket { frame_len: 6 })
    ));

    // Declared payload length exceeding frame capacity.
    let mut bytes = vec![0u8; 512];
    bytes[0] = 0x01;
    bytes[1] = 0x01;
    bytes[2..6].copy_from_slice(&507u32.to_be_bytes()); // 6 + 507 > 512
    assert!(matches!(
        InnerFrame::parse(&bytes, &profile),
        Err(CoreError::Malformed(_))
    ));

    // Non-zero padding byte.
    let mut bytes = InnerFrame::chat_v1("hello").encode(&profile).unwrap();
    let last = bytes.len() - 1;
    bytes[last] = 0x01;
    assert!(matches!(
        InnerFrame::parse(&bytes, &profile),
        Err(CoreError::InvalidPadding)
    ));

    // Non-UTF-8 chat payload is rejected at extraction.
    let frame = InnerFrame {
        payload_type: PayloadType::Chat,
        type_version: 1,
        payload: vec![0xFF, 0xFE],
    };
    assert!(matches!(frame.into_chat_v1(), Err(CoreError::Malformed(_))));
}

// ---------------------------------------------------------------------------
// Property tests: round-trip over the whole registry
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_inner_roundtrip(
        type_byte in 1u8..=4,
        version in 1u8..=3,
        payload in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let profile = PaddingProfile::default_profile();
        let frame = InnerFrame {
            payload_type: PayloadType::try_from(type_byte).unwrap(),
            type_version: version,
            payload,
        };
        let encoded = frame.encode(&profile).unwrap();
        prop_assert!(profile.is_bucket(encoded.len() as u32));
        prop_assert_eq!(InnerFrame::parse(&encoded, &profile).unwrap(), frame);
    }

    #[test]
    fn prop_outer_roundtrip(
        kind_byte in 1u8..=2,
        ciphertext in proptest::collection::vec(any::<u8>(), 1..4096),
    ) {
        let env = Envelope {
            kind: EnvelopeKind::try_from(kind_byte).unwrap(),
            ciphertext,
        };
        prop_assert_eq!(Envelope::parse(&env.encode()).unwrap(), env);
    }

    #[test]
    fn prop_outer_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = Envelope::parse(&bytes); // must return, never panic
    }

    #[test]
    fn prop_inner_parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let profile = PaddingProfile::default_profile();
        let _ = InnerFrame::parse(&bytes, &profile); // must return, never panic
    }
}
