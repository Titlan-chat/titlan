// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Phase 4a acceptance: tezca-core's `TitlanClient` relay client driven
//! end-to-end against the real relay server (Phase 3 harness). Lives in
//! tezca-relay because both halves are here — the relay binary
//! (CARGO_BIN_EXE) and tezca-core (dev-dependency).
//!
//! RED state: the pairing/sync/send/recovery/pin surface is `todo!()` in
//! tezca-core, so these fail at runtime (not at build). The green
//! implementation turns them green.

mod common;

use std::sync::{Arc, Mutex};

use common::{GENEROUS_LIMITS, free_port, spawn_relay_at};
use tempfile::TempDir;
use tezca_core::client::{
    ConnectionObserver, ConnectionState, ConversationId, MessageReceiver, TitlanClient,
};
use tezca_core::config::PaddingProfile;
use tezca_core::envelope::InnerFrame;
use tezca_core::storage::{DbKey, Store, StoredMessage};
use tezca_core::{CoreError, identity, session};

/// Collects delivered messages per conversation.
#[derive(Default)]
struct Inbox(Mutex<Vec<(ConversationId, StoredMessage)>>);
impl MessageReceiver for Inbox {
    fn on_message(&self, id: ConversationId, m: StoredMessage) {
        self.0.lock().expect("inbox").push((id, m));
    }
}
impl Inbox {
    fn texts(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("inbox")
            .iter()
            .map(|(_, m)| String::from_utf8_lossy(&m.body).into_owned())
            .collect()
    }
}

/// Records connection-state transitions + the frozen-§1 event vocabulary.
#[derive(Default)]
struct States {
    states: Mutex<Vec<ConnectionState>>,
}
impl ConnectionObserver for States {
    fn on_state(&self, _id: ConversationId, s: ConnectionState) {
        self.states.lock().expect("states").push(s);
    }
}
impl States {
    fn saw(&self, want: &ConnectionState) -> bool {
        self.states
            .lock()
            .expect("states")
            .iter()
            .any(|s| s == want)
    }
}

fn new_client(dir: &TempDir, name: &str, relay_url: &str) -> TitlanClient {
    // DB key lives in RAM only (INV-1); never written to disk in tests.
    let key = DbKey::generate();
    let client =
        TitlanClient::open(&dir.path().join(name), &key, relay_url).expect("open TitlanClient");
    client.initialize_identity().expect("init identity");
    client
}

/// v2 asymmetric offer + proof-of-scan: Alice (offerer) shows a v2 offer, Bob
/// (responder) scans it, sends `pair-ack/2` with the proof-of-scan MAC, Alice
/// verifies and hands off her inbox + recovery contribution; both then exchange
/// chat over the paired conversation (frozen §3, B1/B2).
#[test]
fn pair_v2_offer_proof_and_exchange() {
    let dir = TempDir::new().unwrap();
    let (relay, _d) = {
        let d = TempDir::new().unwrap();
        let p = free_port();
        (spawn_relay_at(p, GENEROUS_LIMITS, d.path()), d)
    };
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url); // offerer
    let bob = new_client(&dir, "bob.db", &url); // responder
    let alice_rx = Arc::new(Inbox::default());
    let bob_rx = Arc::new(Inbox::default());
    alice
        .start_sync(Arc::new(States::default()), alice_rx.clone())
        .unwrap();
    bob.start_sync(Arc::new(States::default()), bob_rx.clone())
        .unwrap();

    // Alice shows a v2 offer; Bob scans it (proof-of-scan handshake).
    let offer = alice.export_pairing_offer().unwrap();
    let conv_b = bob.begin_pairing_from_offer(offer.as_bytes()).unwrap();

    // Bob → Alice, then Alice → Bob, over the paired conversation.
    bob.send_chat(&conv_b, "hi alice v2").unwrap();
    wait_until(|| alice_rx.texts().contains(&"hi alice v2".to_string()));
    let conv_a = alice.list_conversations().unwrap()[0];
    alice.send_chat(&conv_a, "hi bob v2").unwrap();
    wait_until(|| bob_rx.texts().contains(&"hi bob v2".to_string()));
}

/// v2 §10.7 single total loss: a shared relay restart kills BOTH inboxes at
/// once. A v2 conversation (recovery root established at pairing) recovers via
/// DERIVED mailboxes — both sides bump generation, PUT-create + route through
/// their derived inboxes — and messages flow again (no re-pair, unlike v1).
#[test]
fn v2_single_total_loss_recovers_via_derived_mailboxes() {
    let dir = TempDir::new().unwrap();
    let d = TempDir::new().unwrap();
    let port = free_port();
    let mut relay = spawn_relay_at(port, GENEROUS_LIMITS, d.path());
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url); // offerer
    let bob = new_client(&dir, "bob.db", &url); // responder
    let alice_rx = Arc::new(Inbox::default());
    let alice_st = Arc::new(States::default());
    let bob_rx = Arc::new(Inbox::default());
    alice
        .start_sync(alice_st.clone(), alice_rx.clone())
        .unwrap();
    bob.start_sync(Arc::new(States::default()), bob_rx.clone())
        .unwrap();

    let offer = alice.export_pairing_offer().unwrap();
    let conv_b = bob.begin_pairing_from_offer(offer.as_bytes()).unwrap();
    let conv_a = alice.list_conversations().unwrap()[0];

    // Pairing works before loss.
    bob.send_chat(&conv_b, "before loss").unwrap();
    wait_until(|| alice_rx.texts().contains(&"before loss".to_string()));

    // Shared relay restarts → both inboxes gone at once (total loss).
    relay.kill();
    relay = spawn_relay_at(port, GENEROUS_LIMITS, d.path());

    // Both recover via derived mailboxes; the message flows.
    alice.send_chat(&conv_a, "after total loss").unwrap();
    wait_until(|| bob_rx.texts().contains(&"after total loss".to_string()));
    assert!(alice_st.saw(&ConnectionState::Recovering));
    assert!(!alice_st.saw(&ConnectionState::RePairRequired));
    drop(relay);
}

/// v2 §10.7 recovery across TWO consecutive total losses: after the first
/// recovery rotates both sides onto fresh relay-generated inboxes, a second
/// relay restart must recover AGAIN (generation advances; rotation repeats).
#[test]
fn v2_two_consecutive_total_losses_each_recover() {
    let dir = TempDir::new().unwrap();
    let d = TempDir::new().unwrap();
    let port = free_port();
    let mut relay = spawn_relay_at(port, GENEROUS_LIMITS, d.path());
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url); // offerer
    let bob = new_client(&dir, "bob.db", &url); // responder
    let alice_rx = Arc::new(Inbox::default());
    let bob_rx = Arc::new(Inbox::default());
    alice
        .start_sync(Arc::new(States::default()), alice_rx.clone())
        .unwrap();
    bob.start_sync(Arc::new(States::default()), bob_rx.clone())
        .unwrap();

    let offer = alice.export_pairing_offer().unwrap();
    let conv_b = bob.begin_pairing_from_offer(offer.as_bytes()).unwrap();
    let conv_a = alice.list_conversations().unwrap()[0];
    bob.send_chat(&conv_b, "before").unwrap();
    wait_until(|| alice_rx.texts().contains(&"before".to_string()));

    // First total loss → recover.
    relay.kill();
    relay = spawn_relay_at(port, GENEROUS_LIMITS, d.path());
    alice.send_chat(&conv_a, "after loss 1").unwrap();
    wait_until(|| bob_rx.texts().contains(&"after loss 1".to_string()));
    // Let the offerer-initiated rotation settle onto fresh relay-generated
    // inboxes before inducing the next loss.
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Second total loss (on the rotated, relay-generated inboxes) → recover again.
    relay.kill();
    relay = spawn_relay_at(port, GENEROUS_LIMITS, d.path());
    bob.send_chat(&conv_b, "after loss 2").unwrap();
    wait_until(|| alice_rx.texts().contains(&"after loss 2".to_string()));
    drop(relay);
}

/// (iv) ack-after-persist: a delivered message is written to the encrypted
/// SQLCipher store BEFORE the relay is acked and before the UI callback, so a
/// process death between persist and callback loses nothing — the message is
/// already durable and rehydrates on restart. Here we assert the message is in
/// the store (`messages()`), independent of the transient callback.
#[test]
fn delivered_message_is_durably_persisted() {
    let dir = TempDir::new().unwrap();
    let d = TempDir::new().unwrap();
    let relay = spawn_relay_at(free_port(), GENEROUS_LIMITS, d.path());
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url);
    let bob = new_client(&dir, "bob.db", &url);
    let alice_rx = Arc::new(Inbox::default());
    alice
        .start_sync(Arc::new(States::default()), alice_rx.clone())
        .unwrap();
    bob.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();

    let offer = alice.export_pairing_offer().unwrap();
    let conv_b = bob.begin_pairing_from_offer(offer.as_bytes()).unwrap();
    let conv_a = alice.list_conversations().unwrap()[0];
    bob.send_chat(&conv_b, "durable").unwrap();
    wait_until(|| alice_rx.texts().contains(&"durable".to_string()));

    // Persisted in the encrypted store, not merely delivered to the callback.
    assert!(
        alice
            .messages(&conv_a)
            .unwrap()
            .iter()
            .any(|m| m.body == b"durable"),
        "the delivered message must be durable in SQLCipher (ack-after-persist)",
    );
    drop(relay);
}

/// Schema v2 adds a nullable `relay_pin`; the pin round-trips on a real
/// conversation (per-conversation cert pinning, optional-but-designed).
#[test]
fn schema_v2_relay_pin_migration() {
    let dir = TempDir::new().unwrap();
    let d = TempDir::new().unwrap();
    let relay = spawn_relay_at(free_port(), GENEROUS_LIMITS, d.path());
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url);
    assert_eq!(
        alice.schema_version().unwrap(),
        3,
        "migrations through v3 applied (relay_pin is v2; recovery state is v3)",
    );

    // Need a conversation to pin: pair with Bob.
    let bob = new_client(&dir, "bob.db", &url);
    bob.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();
    alice
        .start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();
    let offer = alice.export_pairing_offer().unwrap();
    let _ = bob.begin_pairing_from_offer(offer.as_bytes()).unwrap();
    let conv = alice.list_conversations().unwrap()[0];

    assert_eq!(alice.conversation_pin(&conv).unwrap(), None);
    alice.set_conversation_pin(&conv, Some([0xAB; 32])).unwrap();
    assert_eq!(alice.conversation_pin(&conv).unwrap(), Some([0xAB; 32]));
    drop(relay);
}

/// A captured QR is consumed after the legitimate pairing retires its
/// single-use pairing inbox (stale-QR-dead). The re-use must fail with the
/// SPECIFIC `PairingUnavailable` error (a 404 on the retired inbox), not merely
/// some error — so the assertion can't pass on an unrelated failure.
#[test]
fn photographed_qr_is_consumed_after_pairing() {
    let dir = TempDir::new().unwrap();
    let d = TempDir::new().unwrap();
    let relay = spawn_relay_at(free_port(), GENEROUS_LIMITS, d.path());
    let url = format!("ws://{}", relay.base());

    let bob = new_client(&dir, "bob.db", &url);
    bob.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();
    let offer = bob.export_pairing_offer().unwrap();

    // Legitimate peer pairs first; the pairing inbox is retired.
    let alice = new_client(&dir, "alice.db", &url);
    alice.begin_pairing_from_offer(offer.as_bytes()).unwrap();

    // A photographer re-uses the SAME captured offer afterwards.
    let mallory = new_client(&dir, "mallory.db", &url);
    let result = mallory.begin_pairing_from_offer(offer.as_bytes());
    assert!(
        matches!(result, Err(CoreError::PairingUnavailable)),
        "a captured QR must fail with PairingUnavailable once the pairing inbox \
         is retired, got {result:?}"
    );
    drop(relay);
}

/// Session isolation — the crypto guarantee under the QR threat model: a
/// scanner who pairs into their OWN session cannot decrypt a ciphertext blob
/// from a different (Bob↔Alice) conversation. Built on the Phase-2 session
/// primitives (no relay client), so it is fully REACHABLE and executes in the
/// red state rather than dying at a `todo!()`.
#[test]
fn scanner_session_cannot_decrypt_third_party_blob() {
    let dir = TempDir::new().unwrap();
    let profile = PaddingProfile::default_profile();

    let alice = open_store(&dir, "iso_alice.db");
    let bob = open_store(&dir, "iso_bob.db");
    let mallory = open_store(&dir, "iso_mallory.db");
    let bob_addr = identity::local_address(&bob).unwrap();

    // Bob pairs with Alice and sends a secret → a genuine Bob→Alice blob.
    let alice_addr_for_bob =
        session::establish_session(&bob, &identity::export_prekey_bundle(&alice).unwrap()).unwrap();
    let blob = session::encrypt_message(
        &bob,
        &alice_addr_for_bob,
        &InnerFrame::chat_v1("top secret"),
        &profile,
    )
    .unwrap();
    // Sanity: the intended recipient can read it.
    assert_eq!(
        session::decrypt_message(&alice, &bob_addr, &blob, &profile)
            .unwrap()
            .into_chat_v1()
            .unwrap(),
        "top secret"
    );

    // Mallory pairs into her OWN session (here with Bob — Alice's one-time
    // prekey is already consumed by her decrypt above), captures the Bob→Alice
    // blob, and attempts to decrypt it — it must fail (no shared ratchet keys).
    session::establish_session(&mallory, &identity::export_prekey_bundle(&bob).unwrap()).unwrap();
    assert!(
        session::decrypt_message(&mallory, &bob_addr, &blob, &profile).is_err(),
        "a scanner's own session must not decrypt a third party's ciphertext"
    );
}

/// Opens + initializes a bare tezca-core store (Phase-2 crypto only).
fn open_store(dir: &TempDir, name: &str) -> Store {
    let key = DbKey::generate();
    let store = Store::open(&dir.path().join(name), &key).expect("open store");
    identity::initialize(&store).expect("init identity");
    store
}

/// Polls a condition for up to ~10s (green implementation delivers async).
fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("condition not met within timeout");
}
