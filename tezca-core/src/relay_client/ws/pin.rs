// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! TLS for `wss://` on the ring provider, with an optional per-conversation
//! certificate pin for self-hosted / air-gapped relays (`optional-but-designed`,
//! work order §6). Default (no pin) uses platform trust roots. Not exercised by
//! the plain-`ws://` integration tests; verified at Phase 5.
//!
//! MVP pins the SHA-256 of the leaf certificate DER. SPKI-scoped pinning
//! (survives cert renewal with the same key) is a Phase-5 refinement.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::{CoreError, Result};

/// Establishes a TLS stream to `host` over `tcp`, honoring an optional pin.
pub(super) async fn tls_connect(
    tcp: TcpStream,
    host: &str,
    pin: Option<[u8; 32]>,
) -> Result<TlsStream<TcpStream>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = match pin {
        Some(pin) => rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(tls_err)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
            .with_no_client_auth(),
        None => {
            let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
                .map_err(|e| CoreError::Network(format!("platform verifier: {e}")))?;
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(tls_err)?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        }
    };
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| CoreError::Network("invalid relay hostname".into()))?;
    TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|e| CoreError::Network(e.to_string()))
}

fn tls_err(e: rustls::Error) -> CoreError {
    CoreError::Network(e.to_string())
}

/// Trusts exactly the pinned leaf certificate (bypasses CA validation — the
/// pin IS the trust anchor for a self-hosted relay).
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
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        if digest.as_ref() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "relay certificate pin mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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
