// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §6 Phase 2 acceptance: sessions survive process restart via the encrypted
//! DB. Plus §8 storage/migration tests and INV-1 at-rest checks.

use tezca_core::config::PaddingProfile;
use tezca_core::envelope::InnerFrame;
use tezca_core::storage::{DbKey, Direction, Store};
use tezca_core::{CoreError, identity, session};

#[test]
fn sessions_survive_process_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let alice_path = dir.path().join("alice.db");
    let bob_path = dir.path().join("bob.db");
    // Keys survive in RAM across the simulated restart — on Android they'd be
    // re-unwrapped from the Keystore-wrapped blob. Never on disk here.
    let alice_key = DbKey::generate();
    let bob_key = DbKey::generate();
    let profile = PaddingProfile::default_profile();

    let (alice_addr, bob_addr);
    {
        let alice = Store::open(&alice_path, &alice_key).unwrap();
        let bob = Store::open(&bob_path, &bob_key).unwrap();
        identity::initialize(&alice).unwrap();
        identity::initialize(&bob).unwrap();

        alice_addr = identity::local_address(&alice).unwrap();
        let bundle = identity::export_prekey_bundle(&bob).unwrap();
        bob_addr = session::establish_session(&alice, &bundle).unwrap();

        for i in 0..10 {
            let wire = session::encrypt_message(
                &alice,
                &bob_addr,
                &InnerFrame::chat_v1(&format!("pre-restart {i}")),
                &profile,
            )
            .unwrap();
            session::decrypt_message(&bob, &alice_addr, &wire, &profile).unwrap();
        }
        // Stores dropped here: the "process" dies.
    }

    // "Restart": reopen the same files with the same keys.
    let alice = Store::open(&alice_path, &alice_key).unwrap();
    let bob = Store::open(&bob_path, &bob_key).unwrap();

    // Ratchet continues in BOTH directions without re-pairing.
    for i in 0..10 {
        let wire = session::encrypt_message(
            &alice,
            &bob_addr,
            &InnerFrame::chat_v1(&format!("post-restart a{i}")),
            &profile,
        )
        .unwrap();
        assert_eq!(
            session::decrypt_message(&bob, &alice_addr, &wire, &profile)
                .unwrap()
                .into_chat_v1()
                .unwrap(),
            format!("post-restart a{i}")
        );

        let wire = session::encrypt_message(
            &bob,
            &alice_addr,
            &InnerFrame::chat_v1(&format!("post-restart b{i}")),
            &profile,
        )
        .unwrap();
        assert_eq!(
            session::decrypt_message(&alice, &bob_addr, &wire, &profile)
                .unwrap()
                .into_chat_v1()
                .unwrap(),
            format!("post-restart b{i}")
        );
    }
}

#[test]
fn wrong_key_is_rejected_cleanly() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let key = DbKey::generate();
    {
        let store = Store::open(&path, &key).unwrap();
        identity::initialize(&store).unwrap();
    }
    match Store::open(&path, &DbKey::generate()) {
        Err(CoreError::BadDbKey) => {}
        other => panic!("expected BadDbKey, got {:?}", other.err()),
    }
}

#[test]
fn migrations_apply_once_and_are_idempotent() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let key = DbKey::generate();
    {
        let store = Store::open(&path, &key).unwrap();
        // Latest schema version (v1 Phase 2 + v2 Phase 4a relay_pin + v3 4b-2
        // recovery columns).
        assert_eq!(store.schema_version().unwrap(), 3);
    }
    let store = Store::open(&path, &key).unwrap();
    assert_eq!(store.schema_version().unwrap(), 3);
}

#[test]
fn conversations_and_messages_persist_and_relay_url_is_per_conversation() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let key = DbKey::generate();

    let (conv_default, conv_custom);
    {
        let store = Store::open(&path, &key).unwrap();
        identity::initialize(&store).unwrap();

        conv_default = store.create_conversation("peer-a", None).unwrap();
        conv_custom = store
            .create_conversation("peer-b", Some("wss://relay.example.org/v1"))
            .unwrap();

        store
            .save_message(
                &conv_default,
                Direction::Outgoing,
                &InnerFrame::chat_v1("m1"),
            )
            .unwrap();
        store
            .save_message(
                &conv_default,
                Direction::Incoming,
                &InnerFrame::chat_v1("m2"),
            )
            .unwrap();
    }

    let store = Store::open(&path, &key).unwrap();
    // INV-5: per-conversation relay; None filled the single default constant.
    assert_eq!(
        store.conversation_relay_url(&conv_default).unwrap(),
        tezca_core::config::DEFAULT_RELAY_URL
    );
    assert_eq!(
        store.conversation_relay_url(&conv_custom).unwrap(),
        "wss://relay.example.org/v1"
    );

    let messages = store.list_messages(&conv_default).unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].body, b"m1");
    assert_eq!(messages[0].direction, Direction::Outgoing);
    assert_eq!(messages[1].body, b"m2");
    assert_eq!(messages[1].direction, Direction::Incoming);
}

#[test]
fn no_plaintext_at_rest_smoke_check() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("store.db");
    let key = DbKey::generate();
    let marker = "INV1-CANARY-plaintext-must-not-touch-disk";
    {
        let store = Store::open(&path, &key).unwrap();
        identity::initialize(&store).unwrap();
        let conv = store.create_conversation("peer", None).unwrap();
        store
            .save_message(&conv, Direction::Outgoing, &InnerFrame::chat_v1(marker))
            .unwrap();
    }
    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(marker.len()).any(|w| w == marker.as_bytes()),
        "INV-1 violated: message plaintext found in the database file"
    );
    // SQLCipher files must not carry the cleartext SQLite magic either.
    assert!(
        !raw.starts_with(b"SQLite format 3"),
        "INV-1 violated: database file is not encrypted"
    );
}
