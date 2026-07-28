// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! 4b-2 CI relay TLS (maintainer-ratified): the debug/test-only rcgen trust
//! anchor in tezca-core's rustls client, validated end-to-end on the host —
//! the exact posture the Android instrumented job uses (relay serving an
//! rcgen self-signed cert; client trusting it ONLY via `TEZCA_TEST_RELAY_PIN`
//! under the `test-relay-anchor` feature; both HTTP and WebSocket legs).
//!
//! Also the negative control: a relay presenting a DIFFERENT certificate is
//! rejected — the anchor is pin verification, not blanket trust.

mod common;

use std::sync::{Arc, Mutex};

use common::{GENEROUS_LIMITS, free_port, spawn_relay_tls_at};
use tempfile::TempDir;
use tezca_core::client::{
    ConnectionObserver, ConnectionState, ConversationId, MessageReceiver, TitlanClient,
};
use tezca_core::storage::{DbKey, StoredMessage};

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

#[derive(Default)]
struct States;
impl ConnectionObserver for States {
    fn on_state(&self, _id: ConversationId, _s: ConnectionState) {}
    fn on_conversation_needs_repair(&self, _id: ConversationId) {}
}

/// Writes an rcgen self-signed cert + key into `dir`; returns the pin
/// (hex SHA-256 of the leaf DER) the client anchor consumes.
fn gen_cert(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate test cert");
    let digest = ring::digest::digest(&ring::digest::SHA256, ck.cert.der().as_ref());
    let pin: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, ck.cert.pem()).expect("write cert");
    std::fs::write(&key, ck.signing_key.serialize_pem()).expect("write key");
    (cert, key, pin)
}

fn wait_until(cond: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while !cond() {
        assert!(
            std::time::Instant::now() < deadline,
            "condition not met within 20s"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// One test function on purpose: TEZCA_TEST_RELAY_PIN is process-global, so
/// the positive flow and the wrong-cert negative control run sequentially
/// against the SAME pinned value.
///
/// Env plumbing: `std::env::set_var` is unsafe in edition 2024 (and the
/// workspace denies unsafe_code), so the anchor env var is instead set the
/// safe way — at process spawn. The parent branch generates the cert, then
/// re-execs this same test binary filtered to this test with the env in
/// place; the child branch (env present) runs the real flow. This also
/// mirrors production reality: the anchor env is set before the engine
/// exists, never mutated mid-process.
#[test]
fn anchored_wss_pairs_and_delivers_and_wrong_cert_is_rejected() {
    let Ok(_pin) = std::env::var("TEZCA_TEST_RELAY_PIN") else {
        // Parent branch: mint the cert, re-exec with the anchor env set.
        let certs = TempDir::new().unwrap();
        let (cert, key, pin) = gen_cert(&certs);
        let exe = std::env::current_exe().expect("test binary path");
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "anchored_wss_pairs_and_delivers_and_wrong_cert_is_rejected",
                "--nocapture",
            ])
            .env("TEZCA_TEST_RELAY_PIN", &pin)
            .env("TEZCA_ANCHOR_E2E_CERT", &cert)
            .env("TEZCA_ANCHOR_E2E_KEY", &key)
            .output()
            .expect("re-exec anchored test");
        assert!(
            out.status.success(),
            "anchored child run failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        return;
    };
    let cert = std::path::PathBuf::from(std::env::var("TEZCA_ANCHOR_E2E_CERT").expect("cert env"));
    let key = std::path::PathBuf::from(std::env::var("TEZCA_ANCHOR_E2E_KEY").expect("key env"));

    let state_dir = TempDir::new().unwrap();
    let relay_dir = TempDir::new().unwrap();
    let port = free_port();
    let relay = spawn_relay_tls_at(port, &cert, &key, GENEROUS_LIMITS, relay_dir.path());
    let url = format!("wss://{}", relay.base());

    // Positive: both legs (reqwest https + rustls wss) trust exactly the
    // pinned cert — full v2 pairing and a delivered message prove it.
    let alice_key = DbKey::generate();
    let alice = TitlanClient::open(&state_dir.path().join("alice.db"), &alice_key, &url)
        .expect("open alice");
    alice.initialize_identity().expect("init alice");
    let bob_key = DbKey::generate();
    let bob =
        TitlanClient::open(&state_dir.path().join("bob.db"), &bob_key, &url).expect("open bob");
    bob.initialize_identity().expect("init bob");

    let alice_rx = Arc::new(Inbox::default());
    alice
        .start_sync(Arc::new(States), alice_rx.clone())
        .expect("alice sync");

    let offer = alice
        .export_pairing_offer()
        .expect("offer over anchored tls");
    let conv_b = bob
        .begin_pairing_from_offer(offer.as_bytes())
        .expect("pair over anchored tls");
    bob.send_chat(&conv_b, "over anchored tls").expect("send");
    wait_until(|| alice_rx.texts().contains(&"over anchored tls".to_string()));
    drop(relay);

    // Negative: same pin env, DIFFERENT relay cert — every operation that
    // reaches TLS must fail. Proves the anchor verifies, not blindly trusts.
    let wrong_certs = TempDir::new().unwrap();
    let (wrong_cert, wrong_key, _unused_pin) = gen_cert(&wrong_certs);
    let wrong_dir = TempDir::new().unwrap();
    let wrong_port = free_port();
    let _wrong = spawn_relay_tls_at(
        wrong_port,
        &wrong_cert,
        &wrong_key,
        GENEROUS_LIMITS,
        wrong_dir.path(),
    );
    let wrong_url = format!("wss://127.0.0.1:{wrong_port}");
    let mallory_key = DbKey::generate();
    let mallory = TitlanClient::open(
        &state_dir.path().join("mallory.db"),
        &mallory_key,
        &wrong_url,
    )
    .expect("open client against wrong-cert relay");
    mallory.initialize_identity().expect("init");
    assert!(
        mallory.export_pairing_offer().is_err(),
        "a relay presenting a cert that does not match the pin must be rejected"
    );
}
