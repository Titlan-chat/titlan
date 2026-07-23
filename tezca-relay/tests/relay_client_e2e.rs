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
    needs_repair: std::sync::atomic::AtomicBool,
}
impl ConnectionObserver for States {
    fn on_state(&self, _id: ConversationId, s: ConnectionState) {
        self.states.lock().expect("states").push(s);
    }
    fn on_conversation_needs_repair(&self, _id: ConversationId) {
        self.needs_repair
            .store(true, std::sync::atomic::Ordering::SeqCst);
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
    fn saw_needs_repair(&self) -> bool {
        self.needs_repair.load(std::sync::atomic::Ordering::SeqCst)
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

/// Per-offer one-time prekey (4b2-WO-otpk-per-offer): a device must be able to
/// show a pairing offer more than once per identity. Today the offer advertises
/// the single fixed `ONETIME_PREKEY_ID`, which libsignal's `remove_pre_key`
/// deletes when the offerer processes the responder's `pair-ack/2`; the next
/// `export_pairing_offer` then reads that removed id via a strict `query_row`.
///
/// RED signature: after Alice is paired into once, her second
/// `export_pairing_offer()` fails with `CoreError::Storage("Query returned no
/// rows")` (Display `storage error: Query returned no rows`), thrown from
/// `identity::export_prekey_bundle` before any relay call. GREEN: a fresh
/// per-offer prekey makes the re-export succeed.
#[test]
fn offerer_can_export_again_after_being_paired_into() {
    let dir = TempDir::new().unwrap();
    let d = TempDir::new().unwrap();
    let relay = spawn_relay_at(free_port(), GENEROUS_LIMITS, d.path());
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url); // offerer
    let bob = new_client(&dir, "bob.db", &url); // responder
    alice
        .start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();
    bob.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();

    // First offer, fully paired: Bob's pairing returns only after Alice has
    // handed off, i.e. after Alice processed Bob's pair-ack and libsignal
    // removed Alice's advertised one-time prekey.
    let offer1 = alice.export_pairing_offer().unwrap();
    bob.begin_pairing_from_offer(offer1.as_bytes()).unwrap();
    wait_until(|| !alice.list_conversations().unwrap().is_empty());

    // The offerer must be able to mint a second offer for a different peer.
    let again = alice.export_pairing_offer();
    assert!(
        again.is_ok(),
        "re-export after an inbound pairing must succeed; got {:?}",
        again.err(),
    );
}

/// Second-scanner property (4b2-WO-otpk-per-offer): two live offers must be
/// independently pairable. Today both offers advertise the SAME fixed one-time
/// prekey, so once the first responder consumes it the offerer can no longer
/// decrypt the second responder's `pair-ack/2`, never hands off, and the second
/// responder times out.
///
/// RED signature: `bob2.begin_pairing_from_offer(offer2)` returns
/// `CoreError::Network("pairing handoff timed out")` after the 10 s handoff
/// deadline. GREEN: distinct per-offer prekeys let both pairings complete.
#[test]
fn two_live_offers_are_each_independently_pairable() {
    let dir = TempDir::new().unwrap();
    let d = TempDir::new().unwrap();
    let relay = spawn_relay_at(free_port(), GENEROUS_LIMITS, d.path());
    let url = format!("ws://{}", relay.base());

    let alice = new_client(&dir, "alice.db", &url); // offerer
    let bob1 = new_client(&dir, "bob1.db", &url); // first scanner
    let bob2 = new_client(&dir, "bob2.db", &url); // second scanner
    let alice_rx = Arc::new(Inbox::default());
    alice
        .start_sync(Arc::new(States::default()), alice_rx.clone())
        .unwrap();
    bob1.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();
    bob2.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();

    // Two offers live at the same time.
    let offer1 = alice.export_pairing_offer().unwrap();
    let offer2 = alice.export_pairing_offer().unwrap();

    // First scanner pairs (this returns only after Alice consumed offer1's
    // prekey and handed off). The second scanner must still be able to pair.
    let conv_b1 = bob1.begin_pairing_from_offer(offer1.as_bytes()).unwrap();
    let conv_b2 = bob2
        .begin_pairing_from_offer(offer2.as_bytes())
        .expect("second live offer must be independently pairable");

    // Both conversations live end to end.
    bob1.send_chat(&conv_b1, "from bob1").unwrap();
    bob2.send_chat(&conv_b2, "from bob2").unwrap();
    wait_until(|| {
        let t = alice_rx.texts();
        t.contains(&"from bob1".to_string()) && t.contains(&"from bob2".to_string())
    });
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

/// v2 §8 exhaustion → conversation-needs-repair, with NO timer dependence. The
/// peer is genuinely UNREACHABLE (its relay stays down after pairing), so no
/// verified `recovery-hello` ever returns to Alice. Each restart of ALICE's
/// relay wipes her receive inbox, so she runs one recovery cycle — bumping her
/// generation and re-probing the peer's (dead) relay. After the crate-private
/// 3-cycle bound with no contact, recovery is exhausted and the engine surfaces
/// `RePairRequired` + `on_conversation_needs_repair`.
///
/// Two relays are used deliberately: on a SHARED relay a live peer co-recovers
/// on every restart and converges Alice's generation, resetting the cycle
/// counter — so exhaustion-by-no-contact is only reachable when the peer is
/// actually unreachable (see the report FLAG). This is driven ENTIRELY by real
/// relay lifecycle + real generation advancement — no test-only hook on the
/// production surface. Exhaustion fires on the count-based 3-cycle bound (not
/// the 24h timer), which is why the test is deterministic; the generation-
/// OFFSET ≥ W arm is not the independent trigger here (report FLAG).
#[test]
fn v2_peer_unreachable_exhausts_recovery_and_needs_repair() {
    let dir = TempDir::new().unwrap();
    let da = TempDir::new().unwrap();
    let db = TempDir::new().unwrap();
    let port_a = free_port();
    let mut relay_a = spawn_relay_at(port_a, GENEROUS_LIMITS, da.path());
    let mut relay_b = spawn_relay_at(free_port(), GENEROUS_LIMITS, db.path());
    let url_a = format!("ws://{}", relay_a.base());
    let url_b = format!("ws://{}", relay_b.base());

    let alice = new_client(&dir, "alice.db", &url_a); // offerer, on relay A
    let bob = new_client(&dir, "bob.db", &url_b); // responder, on relay B
    let alice_rx = Arc::new(Inbox::default());
    let alice_st = Arc::new(States::default());
    alice
        .start_sync(alice_st.clone(), alice_rx.clone())
        .unwrap();
    bob.start_sync(Arc::new(States::default()), Arc::new(Inbox::default()))
        .unwrap();

    let offer = alice.export_pairing_offer().unwrap();
    let conv_b = bob.begin_pairing_from_offer(offer.as_bytes()).unwrap();
    let conv_a = alice.list_conversations().unwrap()[0];
    bob.send_chat(&conv_b, "before offline").unwrap();
    wait_until(|| alice_rx.texts().contains(&"before offline".to_string()));

    // The peer's relay goes down for good: Bob can neither recover his own inbox
    // nor deposit a recovery-hello to Alice. Alice will never get verified
    // contact, so her probe cycles accumulate with no reset.
    relay_b.kill();
    drop((bob, relay_b));

    // Restart ALICE's relay repeatedly. Each restart wipes her receive inbox →
    // 404 → one recovery cycle (`Recovering`, generation bump). With no peer
    // contact the 3-cycle bound (crate-private `RECOVERY_PROBE_CYCLES`, not
    // re-exported for a test) is reached and recovery is declared exhausted. A
    // 4th restart is slack in case a restart races Alice's reconnect.
    for _ in 0..4 {
        relay_a.kill();
        relay_a = spawn_relay_at(port_a, GENEROUS_LIMITS, da.path());
        if alice_st.saw(&ConnectionState::RePairRequired) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    wait_until(|| alice_st.saw(&ConnectionState::RePairRequired));
    assert!(
        alice_st.saw_needs_repair(),
        "exhausted v2 recovery must surface on_conversation_needs_repair"
    );
    assert!(
        alice.list_conversations().unwrap().contains(&conv_a),
        "the conversation is retained (re-pair is the user's next action)"
    );
    drop(relay_a);
}

/// v2 shared-relay analog of pending-deliver-after-reconnect: Alice queues a
/// chat while the relay is DOWN (deposit fails → held locally, never lost),
/// then on the relay's return both sides recover via derived mailboxes and the
/// queued message flushes through and is delivered. Unlike the retired
/// two-relay test — where Alice's own inbox survived and only the peer's relay
/// bounced — a shared-relay restart is a total loss for BOTH inboxes, so the
/// reconnect here rides a §10.7 generation bump. The client-side queue-and-
/// flush guarantee (INV: a send is durable across a transport outage) is the
/// invariant under test.
#[test]
fn v2_message_queued_while_relay_down_delivers_after_recovery() {
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
    bob.send_chat(&conv_b, "before down").unwrap();
    wait_until(|| alice_rx.texts().contains(&"before down".to_string()));

    // Relay down: Alice's deposit fails → the message is held pending locally.
    relay.kill();
    alice.send_chat(&conv_a, "queued while down").unwrap();
    assert!(
        alice
            .messages(&conv_a)
            .unwrap()
            .iter()
            .any(|m| m.body == b"queued while down"),
        "the message must be held locally, not lost, while the relay is down"
    );

    // Relay back: both recover via derived mailboxes and the pending message
    // flushes through to Bob.
    relay = spawn_relay_at(port, GENEROUS_LIMITS, d.path());
    wait_until(|| bob_rx.texts().contains(&"queued while down".to_string()));
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
