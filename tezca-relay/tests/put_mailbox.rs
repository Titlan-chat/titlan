// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! §8 `PUT /v1/mailboxes/{id}` acceptance: idempotent create-at-client-id for
//! §10.7 derived-recovery mailboxes. Focus on the two INV-2 no-oracle
//! properties — byte-identical created-vs-existing, and uniform capacity error
//! at the global cap regardless of id existence.

mod common;

use common::*;

fn put(base: &str, id: &str) -> HttpResponse {
    http_request(base, "PUT", &format!("/v1/mailboxes/{id}"), &[])
}

const ID_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43-char base64url
const ID_B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const ID_C: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

#[test]
fn put_creates_idempotently_with_byte_identical_response() {
    let (relay, _dir) = spawn_relay(&[]);
    let base = relay.base();

    // First PUT: creates. Second PUT of the SAME id: already exists. The
    // responses MUST be byte-identical (status + body) — no existence oracle.
    let first = put(&base, ID_A);
    let second = put(&base, ID_A);
    assert_eq!(first.status, 201, "PUT create returns 201");
    assert_eq!(second.status, 201, "idempotent PUT returns 201");
    assert_eq!(
        (first.status, &first.body),
        (second.status, &second.body),
        "created and already-existing PUT responses must be byte-identical",
    );
    assert!(first.body.is_empty(), "no body (no oracle)");

    // The client-specified mailbox is real: a deposit is accepted and a
    // subscriber receives it.
    let blob = opaque_envelope(600);
    assert_eq!(deposit(&base, ID_A, &blob).status, 202);
    let mut ws = ws_subscribe(&base, ID_A).expect("subscribe to PUT-created mailbox");
    let (_id, delivered) = ws_next_message(&mut ws).expect("delivery");
    assert_eq!(delivered, blob);

    // A malformed id (not 43-char base64url) is rejected on shape alone.
    assert_eq!(put(&base, "not-a-valid-mailbox-id").status, 400);
}

#[test]
fn put_at_cap_is_uniform_capacity_error_regardless_of_existence() {
    // Global cap of 2. Fill it with two PUT-created mailboxes.
    let (relay, _dir) = spawn_relay(&["--max-mailboxes", "2"]);
    let base = relay.base();
    assert_eq!(put(&base, ID_A).status, 201);
    assert_eq!(put(&base, ID_B).status, 201); // now at cap

    // A NEW id at cap → capacity error.
    let new_at_cap = put(&base, ID_C);
    // An EXISTING id at cap → the SAME capacity error (no oracle: the caller
    // cannot tell "exists" from "does not exist" once at cap).
    let existing_at_cap = put(&base, ID_A);

    assert_eq!(new_at_cap.status, 503, "new id at cap → capacity error");
    assert_eq!(
        existing_at_cap.status, 503,
        "existing id at cap → same capacity error (uniform, no oracle)",
    );
    assert_eq!(
        (new_at_cap.status, &new_at_cap.body),
        (existing_at_cap.status, &existing_at_cap.body),
        "at-cap PUT responses must be byte-identical whether or not the id exists",
    );
}

#[test]
fn put_rate_limited_returns_429_when_source_limit_exhausted() {
    let (relay, _dir) = spawn_relay(&["--rate-put-per-min-source", "2"]);
    let base = relay.base();
    assert_eq!(put(&base, ID_A).status, 201);
    assert_eq!(put(&base, ID_B).status, 201);
    // Third PUT from the same source in the window exceeds the limit of 2.
    assert_eq!(put(&base, ID_C).status, 429);
}

#[test]
fn put_source_counter_is_independent_of_create_and_deposit() {
    // The slot refactor must keep PUT / create / deposit counters separate.
    //
    // Direction 1: exhausting create AND deposit leaves PUT admissible.
    let (relay, _dir) = spawn_relay(&[
        "--rate-put-per-min-source",
        "5",
        "--rate-create-per-min",
        "1",
        "--rate-deposit-per-min-source",
        "1",
    ]);
    let base = relay.base();
    assert_eq!(create_mailbox(&base).status, 201); // create counter → exhausted
    assert_eq!(create_mailbox(&base).status, 429);
    assert_eq!(
        put(&base, ID_A).status,
        201,
        "PUT unaffected by create exhaustion"
    );
    assert_eq!(deposit(&base, ID_A, &opaque_envelope(600)).status, 202); // deposit → exhausted
    assert_eq!(deposit(&base, ID_A, &opaque_envelope(600)).status, 429);
    assert_eq!(
        put(&base, ID_B).status,
        201,
        "PUT unaffected by deposit exhaustion"
    );

    // Direction 2: exhausting PUT leaves create AND deposit admissible.
    let (relay2, _dir2) = spawn_relay(&[
        "--rate-put-per-min-source",
        "1",
        "--rate-create-per-min",
        "5",
        "--rate-deposit-per-min-source",
        "5",
    ]);
    let base2 = relay2.base();
    assert_eq!(put(&base2, ID_A).status, 201); // PUT counter → exhausted
    assert_eq!(put(&base2, ID_B).status, 429);
    assert_eq!(
        create_mailbox(&base2).status,
        201,
        "create unaffected by PUT exhaustion"
    );
    assert_eq!(
        deposit(&base2, ID_A, &opaque_envelope(600)).status,
        202,
        "deposit unaffected by PUT exhaustion",
    );
}
