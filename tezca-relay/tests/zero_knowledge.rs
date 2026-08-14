// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §6 Phase 3 zero-knowledge checks (INV-2, INV-3): the relay emits nothing
//! that pairs mailboxes with sources — in fact it emits (almost) nothing at
//! all; it writes nothing persistent; unknown and expired mailboxes are
//! indistinguishable; DELETE answers identically whether or not the mailbox
//! existed (maintainer-approved F3 refinement).

mod common;

use common::*;
use tezca_core::envelope::{Envelope, EnvelopeKind};

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
        .filter_map(std::result::Result::ok)
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

/// INV-8 (freeze H4.1) interior-invariance (G4.2 ratified 2026-08-10): the
/// relay PIPELINE's observable behavior is independent of envelope
/// interiors — not just the admission parser (which
/// `admission_checks_magic_version_and_length_only` already pins to
/// blob[0..=4]). Two envelopes identical except interior bytes (differing
/// kind/type-version byte and every ciphertext byte, equal length) must
/// see: identical admission verdicts, byte-identical HTTP responses,
/// identical delivery framing modulo message id, and identical rate-limit
/// accounting (per report p5-5b2-inv-matrix T3(c)2).
#[test]
fn relay_treatment_is_byte_identical_for_differing_inner_payload_types() {
    // Tight per-mailbox deposit budget so the accounting leg trips it fast;
    // everything else mirrors GENEROUS_LIMITS.
    const MAILBOX_DEPOSIT_BUDGET: usize = 5;
    let (relay, _dir) = spawn_relay(&[
        "--rate-create-per-min",
        "100000",
        "--rate-deposit-per-min-source",
        "1000000",
        "--rate-deposit-per-min-mailbox",
        "5",
        "--rate-ws-per-min-mailbox",
        "100000",
    ]);
    let base = relay.base();

    // Identical except interiors: kind/type-version byte differs
    // (SessionSetup vs Ratchet) and every ciphertext byte differs; equal
    // length by construction.
    let setup_blob = Envelope {
        kind: EnvelopeKind::SessionSetup,
        ciphertext: vec![0x11; 600],
    }
    .encode();
    let ratchet_blob = Envelope {
        kind: EnvelopeKind::Ratchet,
        ciphertext: vec![0x77; 600],
    }
    .encode();
    assert_eq!(setup_blob.len(), ratchet_blob.len(), "equal length");
    assert_eq!(
        setup_blob[..5],
        ratchet_blob[..5],
        "identical outer magic+version"
    );
    assert_ne!(setup_blob[5], ratchet_blob[5], "differing kind byte");

    // The relay's rate windows are fixed wall-clock minutes
    // (limits.rs::current_minute); keep the whole deposit phase inside one
    // window so both mailboxes meter against one budget.
    wait_out_imminent_rate_window_rollover();

    let box_setup = create_mailbox_id(&base);
    let box_ratchet = create_mailbox_id(&base);

    // Dimensions 1+2 — admission verdict and response bytes. Same cadence
    // per mailbox: deposit until the per-mailbox budget trips, collecting
    // every response.
    let responses_setup: Vec<_> = (0..=MAILBOX_DEPOSIT_BUDGET)
        .map(|_| deposit(&base, &box_setup, &setup_blob))
        .collect();
    let responses_ratchet: Vec<_> = (0..=MAILBOX_DEPOSIT_BUDGET)
        .map(|_| deposit(&base, &box_ratchet, &ratchet_blob))
        .collect();

    // Dimension 4 — rate-limit accounting: identical status sequences with
    // the budget tripping at the same deposit ordinal.
    let statuses_setup: Vec<u16> = responses_setup.iter().map(|r| r.status).collect();
    let statuses_ratchet: Vec<u16> = responses_ratchet.iter().map(|r| r.status).collect();
    let mut expected = vec![202u16; MAILBOX_DEPOSIT_BUDGET];
    expected.push(429);
    assert_eq!(statuses_setup, expected, "setup-kind accounting sequence");
    assert_eq!(
        statuses_setup, statuses_ratchet,
        "rate-limit accounting must be interior-independent"
    );

    // Byte-identical responses at every ordinal (202s and the 429), modulo
    // wall-clock header VALUES (`date`, and `retry-after` on the 429 —
    // computed from seconds-to-window-rollover, limits.rs), which are
    // asserted adjacent instead of equal.
    for (i, (rs, rr)) in responses_setup.iter().zip(&responses_ratchet).enumerate() {
        assert_eq!(
            response_fingerprint(rs),
            response_fingerprint(rr),
            "HTTP response bytes must be interior-independent (deposit #{i})"
        );
    }
    let (ra_setup, ra_ratchet) = (
        retry_after_secs_of(responses_setup.last().unwrap()),
        retry_after_secs_of(responses_ratchet.last().unwrap()),
    );
    assert!(
        ra_setup.abs_diff(ra_ratchet) <= 1,
        "Retry-After is wall-clock-derived and may tick once between the two \
         429s, never more (setup {ra_setup}s vs ratchet {ra_ratchet}s)"
    );

    // Dimension 3 — delivery framing modulo message id: every admitted
    // envelope comes back byte-transparent (delivery payload == deposited
    // bytes) in a 0x01||id(16)||envelope frame (shape enforced by
    // ws_next_message), with equal admitted counts on both mailboxes.
    // Frame lengths agree because the deposited blobs are equal-length;
    // only the 16-byte message ids (and the interior bytes deposited
    // differently by construction) may differ.
    let mut ids_seen = Vec::new();
    for (mailbox, blob) in [(&box_setup, &setup_blob), (&box_ratchet, &ratchet_blob)] {
        let mut ws = ws_subscribe(&base, mailbox).expect("subscribe");
        for n in 0..MAILBOX_DEPOSIT_BUDGET {
            let (id, envelope) = ws_next_message(&mut ws).expect("delivery frame");
            assert_eq!(
                &envelope, blob,
                "delivery must be byte-transparent (frame #{n} of {mailbox})"
            );
            ws_ack(&mut ws, &id).expect("ack");
            ids_seen.push(id);
        }
    }
    let deduped: std::collections::HashSet<_> = ids_seen.iter().collect();
    assert_eq!(
        deduped.len(),
        ids_seen.len(),
        "message ids are unique — the only varying framing bytes"
    );
}

/// Fingerprint of an HTTP response for byte-identity comparison: status,
/// ordered (lowercased-name) headers, body. `date` and `retry-after`
/// VALUES are wall-clock artifacts, payload-independent by construction;
/// they are replaced with a placeholder here (presence and position still
/// compared) and asserted adjacent at the call site.
fn response_fingerprint(resp: &HttpResponse) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let headers = resp
        .headers
        .iter()
        .map(|(k, v)| {
            let name = k.to_ascii_lowercase();
            let value = if name == "date" || name == "retry-after" {
                "<wall-clock>".to_string()
            } else {
                v.clone()
            };
            (name, value)
        })
        .collect();
    (resp.status, headers, resp.body.clone())
}

fn retry_after_secs_of(resp: &HttpResponse) -> u64 {
    resp.header("retry-after")
        .expect("429 carries Retry-After")
        .parse()
        .expect("numeric Retry-After")
}

/// Sleeps past the minute boundary when the current fixed rate window
/// (limits.rs: wall-clock minute) is about to roll over, so a single
/// window covers the whole deposit phase.
fn wait_out_imminent_rate_window_rollover() {
    let into_window = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
        % 60;
    if into_window > 55 {
        std::thread::sleep(std::time::Duration::from_secs(60 - into_window + 1));
    }
}
