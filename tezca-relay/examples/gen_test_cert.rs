// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! CI/test-harness helper (dev-scope; never part of the relay binary):
//! generates the rcgen self-signed TLS certificate the CI test relay serves,
//! plus the pin the debug-only client trust anchor consumes
//! (`TEZCA_TEST_RELAY_PIN` = hex SHA-256 of the leaf cert DER — the same
//! value tezca-core's ws/pin.rs `PinVerifier` checks).
//!
//! Usage: cargo run -p tezca-relay --example gen_test_cert -- <out-dir>
//! Writes: <out-dir>/{cert.pem,key.pem,pin.hex}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: gen_test_cert <out-dir>");
    let dir = std::path::PathBuf::from(out);
    std::fs::create_dir_all(&dir).expect("create out dir");

    // SANs cover the emulator's host-loopback alias (10.0.2.2) and the
    // runner-local health probe; the pin verifier ignores names, so these
    // exist only for curl/browser hygiene.
    let ck = rcgen::generate_simple_self_signed(vec![
        "10.0.2.2".to_string(),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
    ])
    .expect("generate self-signed test cert");

    let digest = ring::digest::digest(&ring::digest::SHA256, ck.cert.der().as_ref());
    let pin: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();

    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).expect("write cert.pem");
    std::fs::write(dir.join("key.pem"), ck.signing_key.serialize_pem()).expect("write key.pem");
    std::fs::write(dir.join("pin.hex"), format!("{pin}\n")).expect("write pin.hex");
    println!("wrote cert.pem, key.pem, pin.hex to {}", dir.display());
}
