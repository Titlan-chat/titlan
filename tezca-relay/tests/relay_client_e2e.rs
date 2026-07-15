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

/// Records connection-state transitions per conversation.
#[derive(Default)]
struct States(Mutex<Vec<ConnectionState>>);
impl ConnectionObserver for States {
    fn on_state(&self, _id: ConversationId, s: ConnectionState) {
        self.0.lock().expect("states").push(s);
    }
}
impl States {
    fn saw(&self, want: &ConnectionState) -> bool {
        self.0.lock().expect("states").iter().any(|s| s == want)
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

/// Alice scans Bob's QR; both exchange chat through a real relay.
#[test]
fn pair_and_exchange_through_relay() {
    let dir = TempDir::new().unwrap();
    let (relay, _d) = {
        let d = TempDir::new().unwrap();
        let p = free_port();
        (spawn_relay_at(p, GENEROUS_LIMITS, d.path()), d)
    };
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url);
    let bob = new_client(&dir, "bob.db", &url);

    let alice_rx = Arc::new(Inbox::default());
    let alice_st = Arc::new(States::default());
    let bob_rx = Arc::new(Inbox::default());
    let bob_st = Arc::new(States::default());
    alice
        .start_sync(alice_st.clone(), alice_rx.clone())
        .unwrap();
    bob.start_sync(bob_st.clone(), bob_rx.clone()).unwrap();

    // Bob shows a QR; Alice scans it.
    let payload = bob.export_pairing_payload().unwrap();
    let conv_a = alice.begin_pairing_from_scan(payload.as_bytes()).unwrap();

    alice.send_chat(&conv_a, "hello bob").unwrap();
    wait_until(|| bob_rx.texts().contains(&"hello bob".to_string()));

    // Bob replies on the conversation Alice's pairing created for him.
    let conv_b = bob.list_conversations().unwrap()[0];
    bob.send_chat(&conv_b, "hello alice").unwrap();
    wait_until(|| alice_rx.texts().contains(&"hello alice".to_string()));

    assert!(alice_st.saw(&ConnectionState::Online));
    assert!(bob_st.saw(&ConnectionState::Online));
}

/// A message alice sends while she can't reach the send target is HELD as
/// pending (not lost, INV-3 client side) and redelivered once the route
/// recovers. Two relays: killing bob's relay makes alice's deposit fail
/// (send target unreachable) while alice's own inbox survives, so recovery is
/// one-sided (bob re-announces a fresh inbox) rather than total loss — the
/// scenario §10.7 option (ii) actually supports for redelivery. (A single
/// shared relay restarting is total loss → re-pair, covered separately.)
#[test]
fn pending_messages_deliver_after_reconnect() {
    let dir = TempDir::new().unwrap();
    let da = TempDir::new().unwrap();
    let db = TempDir::new().unwrap();
    let relay_a = spawn_relay_at(free_port(), GENEROUS_LIMITS, da.path());
    let pb = free_port();
    let mut relay_b = spawn_relay_at(pb, GENEROUS_LIMITS, db.path());
    let url_a = format!("ws://{}", relay_a.base());
    let url_b = format!("ws://{}", relay_b.base());

    let alice = new_client(&dir, "alice.db", &url_a);
    let bob = new_client(&dir, "bob.db", &url_b);
    let bob_rx = Arc::new(Inbox::default());
    let bob_st = Arc::new(States::default());
    bob.start_sync(bob_st.clone(), bob_rx.clone()).unwrap();
    alice
        .start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();

    let payload = bob.export_pairing_payload().unwrap();
    let conv_a = alice.begin_pairing_from_scan(payload.as_bytes()).unwrap();

    // Bob's relay down: alice's deposit to his inbox fails → held pending.
    relay_b.kill();
    alice.send_chat(&conv_a, "queued while offline").unwrap();
    assert!(
        alice
            .messages(&conv_a)
            .unwrap()
            .iter()
            .any(|m| m.body == b"queued while offline"),
        "the message must be held locally, not lost"
    );

    // Bob's relay back: his inbox recovery re-announces to alice's surviving
    // inbox, and alice flushes the pending message.
    relay_b = spawn_relay_at(pb, GENEROUS_LIMITS, db.path());
    wait_until(|| bob_rx.texts().contains(&"queued while offline".to_string()));
    drop((relay_a, relay_b));
}

/// §10.7 one-sided loss: only one party's relay restarts; the recovered side
/// announces a fresh inbox in-band via `mailbox-update/1` — no re-pair.
#[test]
fn one_sided_mailbox_loss_recovers_in_band() {
    let dir = TempDir::new().unwrap();
    // Two relays so a restart kills only one side's inbox.
    let da = TempDir::new().unwrap();
    let db = TempDir::new().unwrap();
    let pa = free_port();
    let mut relay_a = spawn_relay_at(pa, GENEROUS_LIMITS, da.path());
    let relay_b = spawn_relay_at(free_port(), GENEROUS_LIMITS, db.path());
    let url_a = format!("ws://{}", relay_a.base());
    let url_b = format!("ws://{}", relay_b.base());

    let alice = new_client(&dir, "alice.db", &url_a);
    let bob = new_client(&dir, "bob.db", &url_b);
    let alice_rx = Arc::new(Inbox::default());
    let alice_st = Arc::new(States::default());
    alice
        .start_sync(alice_st.clone(), alice_rx.clone())
        .unwrap();
    bob.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();

    let payload = bob.export_pairing_payload().unwrap();
    let conv_a = alice.begin_pairing_from_scan(payload.as_bytes()).unwrap();
    alice.send_chat(&conv_a, "before loss").unwrap();

    // Alice's relay restarts → Alice's inbox dies; Bob's (relay_b) survives.
    relay_a.kill();
    relay_a = spawn_relay_at(pa, GENEROUS_LIMITS, da.path());

    // Bob keeps sending; Alice recovers in-band and receives.
    let conv_b = bob.list_conversations().unwrap()[0];
    bob.send_chat(&conv_b, "after one-sided loss").unwrap();
    wait_until(|| {
        alice_rx
            .texts()
            .contains(&"after one-sided loss".to_string())
    });
    assert!(alice_st.saw(&ConnectionState::Recovering));
    assert!(!alice_st.saw(&ConnectionState::RePairRequired));
    drop((relay_a, relay_b));
}

/// §10.7 total loss (option ii): both inboxes die at once → RePairRequired,
/// pending held (not lost), no rendezvous mailbox.
#[test]
fn total_mailbox_loss_surfaces_re_pair_required() {
    let dir = TempDir::new().unwrap();
    let d = TempDir::new().unwrap();
    let port = free_port();
    let mut relay = spawn_relay_at(port, GENEROUS_LIMITS, d.path());
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url);
    let bob = new_client(&dir, "bob.db", &url);
    let alice_st = Arc::new(States::default());
    alice
        .start_sync(alice_st.clone(), Arc::new(Inbox::default()))
        .unwrap();
    bob.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();

    let payload = bob.export_pairing_payload().unwrap();
    let conv_a = alice.begin_pairing_from_scan(payload.as_bytes()).unwrap();

    // Same relay restarts → both inboxes gone at once.
    relay.kill();
    relay = spawn_relay_at(port, GENEROUS_LIMITS, d.path());
    alice.send_chat(&conv_a, "held for re-pair").unwrap();

    wait_until(|| alice_st.saw(&ConnectionState::RePairRequired));
    // Pending is held, not dropped.
    let stored = alice.messages(&conv_a).unwrap();
    assert!(stored.iter().any(|m| m.body == b"held for re-pair"));
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
    assert_eq!(alice.schema_version().unwrap(), 2, "migration v2 applied");

    // Need a conversation to pin: pair with Bob.
    let bob = new_client(&dir, "bob.db", &url);
    bob.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();
    alice
        .start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();
    let payload = bob.export_pairing_payload().unwrap();
    let conv = alice.begin_pairing_from_scan(payload.as_bytes()).unwrap();

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
    let payload = bob.export_pairing_payload().unwrap();

    // Legitimate peer pairs first; the pairing inbox is retired.
    let alice = new_client(&dir, "alice.db", &url);
    alice.begin_pairing_from_scan(payload.as_bytes()).unwrap();

    // A photographer re-uses the SAME captured payload afterwards.
    let mallory = new_client(&dir, "mallory.db", &url);
    let result = mallory.begin_pairing_from_scan(payload.as_bytes());
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
