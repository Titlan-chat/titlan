// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §6 Phase 3 zero-knowledge checks (INV-2, INV-3): the relay emits nothing
//! that pairs mailboxes with sources — in fact it emits (almost) nothing at
//! all; it writes nothing persistent; unknown and expired mailboxes are
//! indistinguishable; DELETE answers identically whether or not the mailbox
//! existed (maintainer-approved F3 refinement).

mod common;

use common::*;

/// INV-2 focus: the reject paths specifically (429 rate-limited, 507
/// capacity, DELETE) must never emit a mailbox ID or a source address —
/// least of all the two together. Drives each reject path under tight limits
/// and asserts the relay's entire output is silent of both.
#[test]
fn reject_paths_never_emit_mailbox_id_or_source() {
    let (relay, _dir) = spawn_relay(&[
        "--rate-create-per-min",
        "2",
        "--mailbox-max-messages",
        "2",
        "--rate-deposit-per-min-source",
        "1000",
        "--rate-deposit-per-min-mailbox",
        "1000",
    ]);
    let base = relay.base();

    // 507: fill a mailbox past its 2-message cap.
    let full = create_mailbox_id(&base);
    assert_eq!(deposit(&base, &full, &opaque_envelope(64)).status, 202);
    assert_eq!(deposit(&base, &full, &opaque_envelope(64)).status, 202);
    assert_eq!(
        deposit(&base, &full, &opaque_envelope(64)).status,
        507,
        "capacity reject"
    );

    // 429: exceed the per-source create rate (limit 2 → we already made 1).
    let _second = create_mailbox_id(&base); // 2nd create (ok)
    assert_eq!(create_mailbox(&base).status, 429, "rate-limit reject");

    // DELETE reject paths: existing, never-existed, already-deleted.
    assert_eq!(delete_mailbox(&base, &full).status, 204);
    assert_eq!(
        delete_mailbox(&base, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").status,
        204
    );
    assert_eq!(delete_mailbox(&base, &full).status, 204);

    let output = relay.kill_and_collect_output();
    assert!(
        !output.contains(&full),
        "INV-2 violation: a mailbox id leaked via a reject path:\n{output}"
    );
    assert!(
        !output.contains("127.0.0.1"),
        "INV-2 violation: a source address leaked via a reject path:\n{output}"
    );
    assert!(
        output.lines().count() <= 2 && output.len() <= 256,
        "reject paths broke the zero-logging policy — {} bytes:\n{output}",
        output.len()
    );
}

#[test]
fn relay_output_contains_no_mailbox_ids_or_source_addresses() {
    let (relay, _dir) = spawn_relay(&[]);
    let base = relay.base();

    // Exercise success AND error paths.
    let inbox = create_mailbox_id(&base);
    assert_eq!(deposit(&base, &inbox, &opaque_envelope(600)).status, 202);
    let _ = deposit(&base, &inbox, b"garbage-not-an-envelope"); // 400 path
    let _ = deposit(
        &base,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &opaque_envelope(64),
    ); // 404 path
    {
        let mut ws = ws_subscribe(&base, &inbox).expect("subscribe");
        let (id, _env) = ws_next_message(&mut ws).expect("delivery");
        ws_ack(&mut ws, &id).expect("ack");
    }
    let _ = delete_mailbox(&base, &inbox);

    let output = relay.kill_and_collect_output();

    assert!(
        !output.contains(&inbox),
        "INV-2 violation: relay output contains a mailbox id:\n{output}"
    );
    assert!(
        !output.contains("127.0.0.1"),
        "INV-2 violation: relay output contains a client source address:\n{output}"
    );
    // Zero-logging policy: at most the fixed startup/shutdown lines.
    assert!(
        output.lines().count() <= 2 && output.len() <= 256,
        "zero-logging policy violated — relay wrote {} bytes / {} lines:\n{output}",
        output.len(),
        output.lines().count()
    );
}

#[test]
fn relay_never_writes_to_storage() {
    let (relay, dir) = spawn_relay(&[]);
    let base = relay.base();

    let inbox = create_mailbox_id(&base);
    for _ in 0..50 {
        assert_eq!(deposit(&base, &inbox, &opaque_envelope(2000)).status, 202);
    }
    {
        let mut ws = ws_subscribe(&base, &inbox).expect("subscribe");
        for _ in 0..50 {
            let (id, _env) = ws_next_message(&mut ws).expect("delivery");
            ws_ack(&mut ws, &id).expect("ack");
        }
    }

    // INV-3: no persistent writes — /proc storage-write counter ≈ 0 where
    // readable (always on CI; some sandboxes deny it, in which case the
    // cwd-empty check below is the primary signal).
    if let Some(written) = relay.storage_write_bytes() {
        assert!(
            written < 16384,
            "INV-3 violation: relay wrote {written} bytes to storage"
        );
    }
    // …and its working directory stays empty.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read cwd")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            !name.ends_with(".db") // client stores from other harness uses
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "INV-3 violation: relay left files in its cwd: {leftovers:?}"
    );
}

#[test]
fn unknown_and_expired_mailboxes_are_indistinguishable() {
    let (relay, _dir) = spawn_relay(&["--ttl-secs", "1", "--sweep-secs", "1"]);
    let base = relay.base();
    let blob = opaque_envelope(64);

    // Deposit to a never-existed (but well-formed) mailbox id.
    let unknown = deposit(&base, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &blob);

    // Deposit to a real mailbox after it expired.
    let inbox = create_mailbox_id(&base);
    std::thread::sleep(std::time::Duration::from_secs(3)); // > ttl + sweep
    let expired = deposit(&base, &inbox, &blob);

    assert_eq!(unknown.status, 404);
    assert_eq!(expired.status, unknown.status);
    assert_eq!(
        expired.body, unknown.body,
        "unknown vs expired mailbox responses must be byte-identical"
    );
    assert_eq!(
        expired.header("content-type"),
        unknown.header("content-type")
    );
}

#[test]
fn delete_reveals_nothing_about_mailbox_existence() {
    let (relay, _dir) = spawn_relay(&[]);
    let base = relay.base();

    let inbox = create_mailbox_id(&base);
    let existing = delete_mailbox(&base, &inbox);
    let never_existed = delete_mailbox(&base, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let already_deleted = delete_mailbox(&base, &inbox);

    assert_eq!(existing.status, 204, "DELETE returns 204 unconditionally");
    assert_eq!(never_existed.status, existing.status);
    assert_eq!(already_deleted.status, existing.status);
    assert_eq!(never_existed.body, existing.body);
    assert_eq!(already_deleted.body, existing.body);

    // And the deleted mailbox now behaves exactly like an unknown one.
    let after = deposit(&base, &inbox, &opaque_envelope(64));
    assert_eq!(after.status, 404);
}
