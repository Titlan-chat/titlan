// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §6 Phase 3 acceptance: two real tezca-core instances exchange 1,000
//! messages through a REAL relay process; the relay is SIGKILLed and
//! restarted mid-test with client retry recovering cleanly; memory stays
//! flat under sustained load.
//!
//! Mailbox-recovery note (flagged for Phase 4): after a relay restart all
//! mailboxes are gone (INV-3). This harness — playing the role of both
//! clients — recreates mailboxes and re-shares the new IDs in-process,
//! which models client-level recovery without designing the client
//! signaling protocol here. How real clients re-exchange mailbox IDs when
//! BOTH directions die simultaneously is a Phase 4 design item.

mod common;

use common::*;
use tezca_core::config::PaddingProfile;
use tezca_core::envelope::InnerFrame;
use tezca_core::storage::{DbKey, Store};
use tezca_core::{identity, session};

struct Endpoint {
    store: Store,
    addr: String,
}

fn paired_endpoints(dir: &tempfile::TempDir) -> (Endpoint, Endpoint) {
    let a_store = Store::open(&dir.path().join("a.db"), &DbKey::generate()).unwrap();
    let b_store = Store::open(&dir.path().join("b.db"), &DbKey::generate()).unwrap();
    identity::initialize(&a_store).unwrap();
    identity::initialize(&b_store).unwrap();
    let a_addr = identity::local_address(&a_store).unwrap();
    let bundle = identity::export_prekey_bundle(&b_store).unwrap();
    let b_addr = session::establish_session(&a_store, &bundle).unwrap();
    (
        Endpoint {
            store: a_store,
            addr: a_addr,
        },
        Endpoint {
            store: b_store,
            addr: b_addr,
        },
    )
}

/// Drains every queued message for `inbox`, acking each, decrypting with
/// `receiver`'s session with `peer_addr`. Returns decrypted chat texts.
fn drain_inbox(
    base: &str,
    inbox: &str,
    receiver: &Endpoint,
    peer_addr: &str,
    expected: usize,
) -> Vec<String> {
    let profile = PaddingProfile::default_profile();
    let mut got = Vec::new();
    if expected == 0 {
        return got;
    }
    let mut ws = ws_subscribe(base, inbox).expect("ws subscribe");
    while got.len() < expected {
        let (id, envelope) = ws_next_message(&mut ws).expect("delivery frame");
        let frame = session::decrypt_message(&receiver.store, peer_addr, &envelope, &profile)
            .expect("decrypt relayed envelope");
        got.push(frame.into_chat_v1().expect("chat payload"));
        ws_ack(&mut ws, &id).expect("ack");
    }
    got
}

#[test]
fn thousand_messages_with_kill_and_restart() {
    let profile = PaddingProfile::default_profile();
    let dir = tempfile::TempDir::new().unwrap();
    let (alice, bob) = paired_endpoints(&dir);

    let port = free_port();
    let mut relay = spawn_relay_at(port, GENEROUS_LIMITS, dir.path());
    let base = relay.base();

    // Conversation-scoped, per-direction mailboxes.
    let mut inbox_a = create_mailbox_id(&base);
    let mut inbox_b = create_mailbox_id(&base);

    let mut delivered_to_a: Vec<String> = Vec::new();
    let mut delivered_to_b: Vec<String> = Vec::new();
    let mut pending_to_b: Vec<String> = Vec::new(); // sent, not yet confirmed e2e
    let mut pending_to_a: Vec<String> = Vec::new();
    let mut killed = false;

    for batch_start in (0..1000).step_by(50) {
        // 25 A→B then 25 B→A per round of 50.
        for i in batch_start..batch_start + 25 {
            let text = format!("a->b {i}");
            let wire = session::encrypt_message(
                &alice.store,
                &bob.addr,
                &InnerFrame::chat_v1(&text),
                &profile,
            )
            .unwrap();
            let resp = deposit(&base, &inbox_b, &wire);
            assert_eq!(resp.status, 202, "deposit a->b #{i}");
            pending_to_b.push(text);
        }
        for i in batch_start + 25..batch_start + 50 {
            let text = format!("b->a {i}");
            let wire = session::encrypt_message(
                &bob.store,
                &alice.addr,
                &InnerFrame::chat_v1(&text),
                &profile,
            )
            .unwrap();
            let resp = deposit(&base, &inbox_a, &wire);
            assert_eq!(resp.status, 202, "deposit b->a #{i}");
            pending_to_a.push(text);
        }

        // Mid-test crash: kill at the 500-message mark with deposits queued
        // but undelivered — those in-RAM messages are lost (INV-3).
        if batch_start + 50 == 500 && !killed {
            killed = true;
            relay.kill();

            // Deposits must now fail at the transport level.
            assert!(
                std::net::TcpStream::connect_timeout(
                    &format!("127.0.0.1:{port}").parse().unwrap(),
                    std::time::Duration::from_millis(300),
                )
                .is_err(),
                "relay port must be closed after SIGKILL"
            );

            // Restart on the SAME port; clients retry and recover.
            relay = spawn_relay_at(port, GENEROUS_LIMITS, dir.path());

            // Everything relay-side is gone (INV-3): recreate mailboxes.
            inbox_a = create_mailbox_id(&base);
            inbox_b = create_mailbox_id(&base);

            // Client redelivery: re-encrypt every unconfirmed payload as a
            // fresh ratchet message and deposit again.
            for text in pending_to_b.clone() {
                let wire = session::encrypt_message(
                    &alice.store,
                    &bob.addr,
                    &InnerFrame::chat_v1(&text),
                    &profile,
                )
                .unwrap();
                assert_eq!(deposit(&base, &inbox_b, &wire).status, 202);
            }
            for text in pending_to_a.clone() {
                let wire = session::encrypt_message(
                    &bob.store,
                    &alice.addr,
                    &InnerFrame::chat_v1(&text),
                    &profile,
                )
                .unwrap();
                assert_eq!(deposit(&base, &inbox_a, &wire).status, 202);
            }
        }

        // Drain both inboxes; confirmed messages leave the pending sets.
        let got_b = drain_inbox(&base, &inbox_b, &bob, &alice.addr, pending_to_b.len());
        delivered_to_b.extend(got_b);
        pending_to_b.clear();
        let got_a = drain_inbox(&base, &inbox_a, &alice, &bob.addr, pending_to_a.len());
        delivered_to_a.extend(got_a);
        pending_to_a.clear();
    }

    assert!(killed, "the kill/restart leg must have executed");
    assert_eq!(delivered_to_b.len(), 500);
    assert_eq!(delivered_to_a.len(), 500);
    // Every distinct payload arrived exactly once (relay-level dupes would
    // fail decrypt as Replay before reaching here; content-level check too).
    let mut seen_b: Vec<&String> = delivered_to_b.iter().collect();
    seen_b.sort();
    seen_b.dedup();
    assert_eq!(seen_b.len(), 500, "no duplicate deliveries to B");
    let mut seen_a: Vec<&String> = delivered_to_a.iter().collect();
    seen_a.sort();
    seen_a.dedup();
    assert_eq!(seen_a.len(), 500, "no duplicate deliveries to A");
}

#[test]
fn unacked_messages_are_redelivered_on_reconnect() {
    let (relay, _dir) = spawn_relay(GENEROUS_LIMITS);
    let base = relay.base();
    let inbox = create_mailbox_id(&base);

    let blob = opaque_envelope(600);
    assert_eq!(deposit(&base, &inbox, &blob).status, 202);

    // First subscriber reads the message but never acks.
    let first_id = {
        let mut ws = ws_subscribe(&base, &inbox).expect("subscribe");
        let (id, envelope) = ws_next_message(&mut ws).expect("first delivery");
        assert_eq!(envelope, blob);
        id
        // ws dropped without ack
    };

    // Reconnect: same message must be redelivered (at-least-once until ack).
    let mut ws = ws_subscribe(&base, &inbox).expect("re-subscribe");
    let (id, envelope) = ws_next_message(&mut ws).expect("redelivery");
    assert_eq!(id, first_id, "same relay message id on redelivery");
    assert_eq!(envelope, blob);
    ws_ack(&mut ws, &id).expect("ack");

    // After ack, nothing further is queued: a fresh subscribe should yield
    // no immediate delivery frame (read must time out).
    drop(ws);
    let mut ws = ws_subscribe(&base, &inbox).expect("post-ack subscribe");
    assert!(
        ws_next_message(&mut ws).is_err(),
        "acked message must not be redelivered"
    );
}

#[test]
fn memory_stays_flat_under_sustained_load() {
    let (relay, _dir) = spawn_relay(GENEROUS_LIMITS);
    let base = relay.base();
    let inbox = create_mailbox_id(&base);
    let blob = opaque_envelope(600);

    let cycle = |n: usize| {
        for _ in 0..n {
            assert_eq!(deposit(&base, &inbox, &blob).status, 202);
        }
        let mut ws = ws_subscribe(&base, &inbox).expect("subscribe");
        for _ in 0..n {
            let (id, _env) = ws_next_message(&mut ws).expect("delivery");
            ws_ack(&mut ws, &id).expect("ack");
        }
    };

    // Warm-up, then measure.
    cycle(500);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let warmed = relay.rss_kb();

    for _ in 0..20 {
        cycle(500); // 10,000 sustained deposit/deliver/ack cycles
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    let after = relay.rss_kb();

    assert!(
        after <= warmed + warmed / 10,
        "relay RSS grew from {warmed} kB to {after} kB under sustained load (>10%)"
    );
}
