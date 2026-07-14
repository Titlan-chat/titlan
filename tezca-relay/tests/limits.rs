// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §6 Phase 3 rate limiting, capacity, TTL, and §8 negative tests. All
//! limits are config (maintainer-approved defaults); tests pass explicit
//! tight values so they run fast and deterministically.

mod common;

use common::*;

#[test]
fn deposit_negatives() {
    let (relay, _dir) = spawn_relay(&["--max-blob-bytes", "16384"]);
    let base = relay.base();
    let inbox = create_mailbox_id(&base);

    // Not an envelope at all (bad magic).
    assert_eq!(deposit(&base, &inbox, b"NOPE not an envelope").status, 400);
    // Wrong envelope version (magic ok, version byte 0x02).
    let mut wrong_version = opaque_envelope(64);
    wrong_version[4] = 0x02;
    assert_eq!(deposit(&base, &inbox, &wrong_version).status, 400);
    // Empty body.
    assert_eq!(deposit(&base, &inbox, &[]).status, 400);
    // Truncated: shorter than the minimum well-formed envelope (9 bytes).
    assert_eq!(deposit(&base, &inbox, b"TZCA\x01\x02\x00\x00").status, 400);
    // Oversized blob.
    assert_eq!(deposit(&base, &inbox, &opaque_envelope(17000)).status, 413);
    // Unknown mailbox.
    assert_eq!(
        deposit(
            &base,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            &opaque_envelope(64)
        )
        .status,
        404
    );
    // A valid deposit still works after all those rejections.
    assert_eq!(deposit(&base, &inbox, &opaque_envelope(600)).status, 202);
}

#[test]
fn relay_stores_blobs_verbatim_and_blindly() {
    // INV-2: the relay must not parse beyond magic+version — a blob whose
    // "kind" byte is garbage and whose ciphertext is arbitrary must round
    // trip verbatim… rejected only if magic/version are wrong. Kind byte is
    // NOT validated by the relay (that's endpoint business).
    let (relay, _dir) = spawn_relay(&[]);
    let base = relay.base();
    let inbox = create_mailbox_id(&base);

    let mut odd_kind = opaque_envelope(600);
    odd_kind[5] = 0x7F; // relay must not care
    assert_eq!(deposit(&base, &inbox, &odd_kind).status, 202);

    let mut ws = ws_subscribe(&base, &inbox).expect("subscribe");
    let (id, delivered) = ws_next_message(&mut ws).expect("delivery");
    assert_eq!(delivered, odd_kind, "blob must round-trip byte-verbatim");
    ws_ack(&mut ws, &id).expect("ack");
}

#[test]
fn mailbox_message_capacity() {
    let (relay, _dir) = spawn_relay(&["--mailbox-max-messages", "5"]);
    let base = relay.base();
    let inbox = create_mailbox_id(&base);
    let blob = opaque_envelope(64);

    for i in 0..5 {
        assert_eq!(deposit(&base, &inbox, &blob).status, 202, "deposit {i}");
    }
    assert_eq!(
        deposit(&base, &inbox, &blob).status,
        507,
        "mailbox over message cap must yield 507"
    );
}

#[test]
fn mailbox_byte_capacity() {
    // 3 × ~2KiB blobs fit under 8 KiB; the 4th pushes past the byte cap.
    let (relay, _dir) = spawn_relay(&["--mailbox-max-bytes", "8192"]);
    let base = relay.base();
    let inbox = create_mailbox_id(&base);
    let blob = opaque_envelope(2500);

    assert_eq!(deposit(&base, &inbox, &blob).status, 202);
    assert_eq!(deposit(&base, &inbox, &blob).status, 202);
    assert_eq!(deposit(&base, &inbox, &blob).status, 202);
    assert_eq!(deposit(&base, &inbox, &blob).status, 507);
}

#[test]
fn create_rate_limit_per_source() {
    let (relay, _dir) = spawn_relay(&["--rate-create-per-min", "3"]);
    let base = relay.base();

    for _ in 0..3 {
        assert_eq!(create_mailbox(&base).status, 201);
    }
    let limited = create_mailbox(&base);
    assert_eq!(limited.status, 429);
    assert!(
        limited.header("retry-after").is_some(),
        "429 must carry Retry-After"
    );
}

#[test]
fn deposit_rate_limit_per_mailbox() {
    let (relay, _dir) = spawn_relay(&[
        "--rate-deposit-per-min-mailbox",
        "5",
        "--rate-deposit-per-min-source",
        "1000000",
    ]);
    let base = relay.base();
    let inbox = create_mailbox_id(&base);
    let blob = opaque_envelope(64);

    for _ in 0..5 {
        assert_eq!(deposit(&base, &inbox, &blob).status, 202);
    }
    assert_eq!(deposit(&base, &inbox, &blob).status, 429);
}

#[test]
fn ttl_expires_messages_and_mailboxes() {
    let (relay, _dir) = spawn_relay(&["--ttl-secs", "1", "--sweep-secs", "1"]);
    let base = relay.base();
    let inbox = create_mailbox_id(&base);

    assert_eq!(deposit(&base, &inbox, &opaque_envelope(64)).status, 202);
    std::thread::sleep(std::time::Duration::from_secs(3)); // > ttl + sweep

    // Mailbox (idle past TTL) is gone: deposits 404, subscribe refused.
    assert_eq!(deposit(&base, &inbox, &opaque_envelope(64)).status, 404);
    assert!(
        ws_subscribe(&base, &inbox).is_err(),
        "subscribe to an expired mailbox must be refused"
    );
}
