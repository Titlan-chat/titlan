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
    let mut inbox_a = create_mailbox_id(&base); // messages FOR alice
    let mut inbox_b = create_mailbox_id(&base); // messages FOR bob

    let mut delivered_to_a: Vec<String> = Vec::new();
    let mut delivered_to_b: Vec<String> = Vec::new();
    let mut killed = false;

    // 20 batches × 50 = 1,000 messages. Each batch: A→B, drain B, then B→A,
    // drain A. Draining B before B replies matters — in PQXDH only the
    // initiator (Alice) holds a session until the responder (Bob) decrypts
    // her first message, after which Bob's ratchet is live and he can send.
    for batch in 0..20 {
        // ---- A → B (25) ----
        let texts_b: Vec<String> = (0..25)
            .map(|i| {
                let text = format!("a->b {}", batch * 25 + i);
                let wire = session::encrypt_message(
                    &alice.store,
                    &bob.addr,
                    &InnerFrame::chat_v1(&text),
                    &profile,
                )
                .unwrap();
                assert_eq!(deposit(&base, &inbox_b, &wire).status, 202, "deposit a->b");
                text
            })
            .collect();

        // Mid-test crash at the 500-message mark (start of batch 10): the 25
        // just-deposited, still-undelivered A→B messages are in RAM and are
        // lost (INV-3). Clients recover by recreating mailboxes and resending.
        if batch == 10 && !killed {
            killed = true;
            relay.kill();
            assert!(
                std::net::TcpStream::connect_timeout(
                    &format!("127.0.0.1:{port}").parse().unwrap(),
                    std::time::Duration::from_millis(300),
                )
                .is_err(),
                "relay port must be closed after SIGKILL"
            );

            // Restart on the SAME port; everything relay-side is gone.
            relay = spawn_relay_at(port, GENEROUS_LIMITS, dir.path());
            inbox_a = create_mailbox_id(&base);
            inbox_b = create_mailbox_id(&base);

            // Client redelivery: re-encrypt the lost A→B batch as fresh
            // ratchet messages and redeposit to the new mailbox.
            for text in &texts_b {
                let wire = session::encrypt_message(
                    &alice.store,
                    &bob.addr,
                    &InnerFrame::chat_v1(text),
                    &profile,
                )
                .unwrap();
                assert_eq!(
                    deposit(&base, &inbox_b, &wire).status,
                    202,
                    "redeposit a->b"
                );
            }
        }

        let got_b = drain_inbox(&base, &inbox_b, &bob, &alice.addr, texts_b.len());
        assert_eq!(got_b, texts_b, "A→B batch content, in order");
        delivered_to_b.extend(got_b);

        // ---- B → A (25) — Bob now has a live session from draining above ----
        let texts_a: Vec<String> = (0..25)
            .map(|i| {
                let text = format!("b->a {}", batch * 25 + i);
                let wire = session::encrypt_message(
                    &bob.store,
                    &alice.addr,
                    &InnerFrame::chat_v1(&text),
                    &profile,
                )
                .unwrap();
                assert_eq!(deposit(&base, &inbox_a, &wire).status, 202, "deposit b->a");
                text
            })
            .collect();
        let got_a = drain_inbox(&base, &inbox_a, &alice, &bob.addr, texts_a.len());
        assert_eq!(got_a, texts_a, "B→A batch content, in order");
        delivered_to_a.extend(got_a);
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

// Ignored in the concurrent `cargo test --workspace` run: this measures
// whole-process RSS, which is disturbed by transient allocator high-water
// when dozens of other test processes hammer the machine at once. CI runs it
// in isolation (a dedicated single-test step) so the measurement is clean.
#[test]
#[ignore = "RSS-sensitive; run in isolation (see CI reproducible-build/memory step)"]
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

    // "Flat under sustained load" means NO UNBOUNDED GROWTH — i.e. no leak.
    // The general-purpose allocator ramps to a high-water mark over the first
    // few thousand allocations (per-thread arenas fill in), which is a
    // bounded plateau, not a leak. So we warm PAST that ramp (12k messages)
    // to reach steady state, snapshot RSS, then assert the next 10k messages
    // grow it < 10%. A real leak keeps climbing across this window; a
    // plateaued allocator does not.
    for _ in 0..24 {
        cycle(500); // 12,000 messages: reach allocator steady state
    }
    let steady = settled_rss(&relay);

    // OBSERVABILITY ONLY (no behavior change): sample the relay child's RSS at
    // the END of each sustained cycle so the trajectory is visible — a rising
    // line across the 20 samples is a leak; a step-then-flat plateau is the
    // allocator's high-water mark. This is a plain /proc read (rss_kb) and does
    // NOT alter the message counts, the settled_rss snapshots, or the assertion.
    let mut series_kb: Vec<u64> = Vec::with_capacity(20);
    for _ in 0..20 {
        cycle(500); // 10,000 more sustained deposit/deliver/ack cycles
        series_kb.push(relay.rss_kb());
    }
    let after = settled_rss(&relay);

    // Unconditional magnitudes (pass AND fail). libtest captures stdout unless
    // the run passes `--nocapture`; on a failing run the assert dumps captured
    // stdout anyway, so these lines are always available where the outcome is.
    let delta_kb = after as i64 - steady as i64;
    let growth_pct = delta_kb as f64 / steady as f64 * 100.0;
    println!(
        "MEMFLAT steady_kb={steady} after_kb={after} delta_kb={delta_kb} growth_pct={growth_pct:.2}"
    );
    println!("MEMFLAT sustained_series_kb={series_kb:?}");

    assert!(
        after <= steady + steady / 10,
        "relay RSS grew from {steady} kB (steady state) to {after} kB over 10k \
         sustained messages (>10%) — indicates a leak, not allocator warm-up"
    );
}

/// Settled resident memory: the minimum of several samples after a brief
/// drain. The minimum reflects live/high-water memory (what a leak grows);
/// it filters transient allocation spikes that appear only under heavy
/// parallel-test CPU contention (the whole workspace suite runs at once).
fn settled_rss(relay: &common::RelayProc) -> u64 {
    let mut min = u64::MAX;
    for _ in 0..5 {
        std::thread::sleep(std::time::Duration::from_millis(150));
        min = min.min(relay.rss_kb());
    }
    min
}
