// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §6 Phase 2 acceptance: two in-process identities complete X3DH/PQXDH and
//! ratchet across 100+ messages including out-of-order delivery. All crypto
//! is libsignal's; these tests exercise it through the tezca-core API only.

use rand::SeedableRng;
use rand::seq::SliceRandom;
use tezca_core::config::PaddingProfile;
use tezca_core::envelope::{Envelope, EnvelopeKind, InnerFrame};
use tezca_core::storage::{DbKey, Store};
use tezca_core::{CoreError, identity, session};

fn new_store(dir: &tempfile::TempDir, name: &str) -> Store {
    // Key lives in RAM only — never written to disk (INV-1).
    let key = DbKey::generate();
    let store = Store::open(&dir.path().join(name), &key).unwrap();
    identity::initialize(&store).unwrap();
    store
}

#[test]
fn pqxdh_establishment_and_first_roundtrip() {
    let dir = tempfile::TempDir::new().unwrap();
    let alice = new_store(&dir, "alice.db");
    let bob = new_store(&dir, "bob.db");
    let profile = PaddingProfile::default_profile();

    let alice_addr = identity::local_address(&alice).unwrap();
    let bob_bundle = identity::export_prekey_bundle(&bob).unwrap();

    // Alice (scanner/initiator) processes Bob's QR bundle → PQXDH.
    let bob_addr = session::establish_session(&alice, &bob_bundle).unwrap();

    // First message travels as a session-setup envelope.
    let wire = session::encrypt_message(
        &alice,
        &bob_addr,
        &InnerFrame::chat_v1("hello bob"),
        &profile,
    )
    .unwrap();
    assert_eq!(
        Envelope::parse(&wire).unwrap().kind,
        EnvelopeKind::SessionSetup
    );

    // Bob decrypts (this establishes his side of the session).
    let frame = session::decrypt_message(&bob, &alice_addr, &wire, &profile).unwrap();
    assert_eq!(frame.into_chat_v1().unwrap(), "hello bob");

    // Bob replies over the established ratchet.
    let wire = session::encrypt_message(
        &bob,
        &alice_addr,
        &InnerFrame::chat_v1("hello alice"),
        &profile,
    )
    .unwrap();
    assert_eq!(Envelope::parse(&wire).unwrap().kind, EnvelopeKind::Ratchet);
    let frame = session::decrypt_message(&alice, &bob_addr, &wire, &profile).unwrap();
    assert_eq!(frame.into_chat_v1().unwrap(), "hello alice");

    // Once Alice has processed a reply, her side ratchets too.
    let wire =
        session::encrypt_message(&alice, &bob_addr, &InnerFrame::chat_v1("ack"), &profile).unwrap();
    assert_eq!(Envelope::parse(&wire).unwrap().kind, EnvelopeKind::Ratchet);
    assert_eq!(
        session::decrypt_message(&bob, &alice_addr, &wire, &profile)
            .unwrap()
            .into_chat_v1()
            .unwrap(),
        "ack"
    );
}

#[test]
fn ratchet_150_messages_with_out_of_order_delivery() {
    let dir = tempfile::TempDir::new().unwrap();
    let alice = new_store(&dir, "alice.db");
    let bob = new_store(&dir, "bob.db");
    let profile = PaddingProfile::default_profile();

    let alice_addr = identity::local_address(&alice).unwrap();
    let bob_bundle = identity::export_prekey_bundle(&bob).unwrap();
    let bob_addr = session::establish_session(&alice, &bob_bundle).unwrap();

    // Deterministic shuffle — no wall-clock seeding.
    let mut shuffle_rng = rand::rngs::StdRng::from_seed([7u8; 32]);
    let mut delivered = 0u32;

    // 3 rounds × (25 A→B + 25 B→A) = 150 messages, each batch delivered
    // out of order within a 25-message window.
    for round in 0..3 {
        let mut batch: Vec<(String, Vec<u8>)> = (0..25)
            .map(|i| {
                let text = format!("a->b r{round} m{i}");
                let wire = session::encrypt_message(
                    &alice,
                    &bob_addr,
                    &InnerFrame::chat_v1(&text),
                    &profile,
                )
                .unwrap();
                (text, wire)
            })
            .collect();
        batch.shuffle(&mut shuffle_rng);
        for (text, wire) in batch {
            let got = session::decrypt_message(&bob, &alice_addr, &wire, &profile)
                .unwrap()
                .into_chat_v1()
                .unwrap();
            assert_eq!(got, text);
            delivered += 1;
        }

        let mut batch: Vec<(String, Vec<u8>)> = (0..25)
            .map(|i| {
                let text = format!("b->a r{round} m{i}");
                let wire = session::encrypt_message(
                    &bob,
                    &alice_addr,
                    &InnerFrame::chat_v1(&text),
                    &profile,
                )
                .unwrap();
                (text, wire)
            })
            .collect();
        batch.shuffle(&mut shuffle_rng);
        for (text, wire) in batch {
            let got = session::decrypt_message(&alice, &bob_addr, &wire, &profile)
                .unwrap()
                .into_chat_v1()
                .unwrap();
            assert_eq!(got, text);
            delivered += 1;
        }
    }
    assert_eq!(delivered, 150);
}

#[test]
fn duplicate_delivery_is_rejected_as_replay() {
    let dir = tempfile::TempDir::new().unwrap();
    let alice = new_store(&dir, "alice.db");
    let bob = new_store(&dir, "bob.db");
    let profile = PaddingProfile::default_profile();

    let alice_addr = identity::local_address(&alice).unwrap();
    let bob_bundle = identity::export_prekey_bundle(&bob).unwrap();
    let bob_addr = session::establish_session(&alice, &bob_bundle).unwrap();

    let wire = session::encrypt_message(
        &alice,
        &bob_addr,
        &InnerFrame::chat_v1("once only"),
        &profile,
    )
    .unwrap();

    assert!(session::decrypt_message(&bob, &alice_addr, &wire, &profile).is_ok());
    match session::decrypt_message(&bob, &alice_addr, &wire, &profile) {
        Err(CoreError::Replay) => {}
        other => panic!("expected Replay, got {other:?}"),
    }
}

#[test]
fn bundles_carry_post_quantum_material() {
    let dir = tempfile::TempDir::new().unwrap();
    let bob = new_store(&dir, "bob.db");
    let bundle = identity::export_prekey_bundle(&bob).unwrap();
    // Kyber/ML-KEM public keys are ≥ 1500 bytes; a classical-only bundle
    // (~200 bytes) cannot reach this size. Guards against silently shipping
    // X3DH-without-PQ (A2 requires the post-quantum hybrid).
    assert!(
        bundle.len() > 1500,
        "bundle too small to contain kyber prekey: {} bytes",
        bundle.len()
    );
}
