// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! F6 (5a-3 conformance, ratified 2026-08-20): the relay's TLS listener
//! advertises `http/1.1` and NOTHING else in ALPN.
//!
//! The relay serves HTTP/1.1 plus the `WebSocket` upgrade only (axum is built
//! without the http2 feature), so advertising `h2` offers a protocol surface
//! the server does not implement. Pinning the advertised list keeps the
//! transport negotiation honest and matches the frozen relay-API text.
//!
//! Transport negotiation only — no wire bytes change. The relay-API request
//! and envelope formats are untouched.

mod common;

use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;

use common::{GENEROUS_LIMITS, free_port, spawn_relay_tls_at};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tempfile::TempDir;

/// Trusts exactly the pinned leaf certificate, so the only thing that can
/// fail this test's handshakes is the ALPN negotiation under test.
#[derive(Debug)]
struct PinVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if digest.as_ref() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("relay cert pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Writes an rcgen self-signed cert + key into `dir`; returns their paths and
/// the SHA-256 of the leaf DER (the verifier's pin).
fn gen_cert(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf, [u8; 32]) {
    let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("generate test cert");
    let digest = ring::digest::digest(&ring::digest::SHA256, ck.cert.der().as_ref());
    let mut pin = [0u8; 32];
    pin.copy_from_slice(digest.as_ref());
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, ck.cert.pem()).expect("write cert");
    std::fs::write(&key, ck.signing_key.serialize_pem()).expect("write key");
    (cert, key, pin)
}

/// Completes one TLS handshake against `port` offering exactly `alpn`.
///
/// `Ok(Some(p))` = handshake established and `p` was negotiated;
/// `Ok(None)` = established with no protocol agreed; `Err` = the relay
/// refused the handshake (an ALPN mismatch is a fatal
/// `no_application_protocol` alert).
fn handshake_alpn(port: u16, pin: [u8; 32], alpn: &[&[u8]]) -> Result<Option<Vec<u8>>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    let name = ServerName::try_from("127.0.0.1").map_err(|e| e.to_string())?;
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let mut sock = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    sock.set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    conn.complete_io(&mut sock).map_err(|e| e.to_string())?;
    // A TLS 1.3 client can finish its own handshake before reading the
    // server's response; poke the stream once so a fatal alert sent in reply
    // to the `ClientHello` surfaces here rather than being missed. Short
    // timeout: an alert already in flight arrives immediately on loopback,
    // and a healthy server simply has nothing to say until it is asked.
    let negotiated = conn.alpn_protocol().map(<[u8]>::to_vec);
    sock.set_read_timeout(Some(std::time::Duration::from_millis(300)))
        .map_err(|e| e.to_string())?;
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);
    let mut scratch = [0u8; 1];
    match stream.read(&mut scratch) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(negotiated)
}

/// The relay must offer `http/1.1` and only `http/1.1`: an `h2`-only client
/// gets no protocol (in practice, a rejected handshake), while the `http/1.1`
/// client — the posture every real client uses — still negotiates cleanly.
#[test]
fn relay_offers_http1_alpn_only_and_never_h2() {
    let certs = TempDir::new().unwrap();
    let (cert, key, pin) = gen_cert(&certs);
    let relay_dir = TempDir::new().unwrap();
    let port = free_port();
    let relay = spawn_relay_tls_at(port, &cert, &key, GENEROUS_LIMITS, relay_dir.path());

    // Positive control FIRST: proves the harness, the cert pin and the
    // handshake plumbing all work before the intended assertion runs.
    let http1 = handshake_alpn(port, pin, &[b"http/1.1"]).expect("http/1.1 client must connect");
    assert_eq!(
        http1.as_deref(),
        Some(&b"http/1.1"[..]),
        "the relay must negotiate http/1.1 with an http/1.1 client",
    );

    // The intended assertion: h2 is not on offer. Both conformant outcomes
    // are accepted — a refused handshake (the rustls server sends a fatal
    // `no_application_protocol` alert when its non-empty list shares nothing
    // with the client's) or an established connection with no protocol
    // agreed. Negotiating h2 is neither.
    if let Ok(Some(p)) = handshake_alpn(port, pin, &[b"h2"]) {
        panic!(
            "relay negotiated ALPN {:?} with an h2-only client; http/1.1 must be the only offered protocol",
            String::from_utf8_lossy(&p),
        );
    }
    drop(relay);
}
