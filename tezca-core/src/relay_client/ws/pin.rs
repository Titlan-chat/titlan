// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! TLS for `wss://` on the ring provider, with an optional per-conversation
//! certificate pin for self-hosted / air-gapped relays (`optional-but-designed`,
//! work order §6). Default (no pin) uses the bundled Mozilla root store. Not exercised by
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

/// Builds a rustls client config that trusts exactly the pinned leaf cert
/// (via [`PinVerifier`]). Shared by the wss connector and — under the
/// `test-relay-anchor` feature — the reqwest HTTP client.
pub(super) fn pinned_client_config(pin: [u8; 32]) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(tls_err)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
            .with_no_client_auth(),
    )
}

/// The bundled Mozilla root store (`webpki-roots`, generated from CCADB): the
/// no-pin trust anchors on every platform (RC-D7 as amended, 5d-4). The
/// device's own store — including user-installed CAs — is never consulted, and
/// no live revocation check is performed (rustls fetches neither CRLs nor
/// OCSP). Single trust-store site (scripts/check-invariants.sh family 18b).
fn bundled_root_store() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Builds the no-pin rustls client config over [`bundled_root_store`]. Shared
/// by the wss connector and the reqwest HTTP client, so both legs carry one
/// trust decision.
pub(super) fn bundled_client_config() -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(tls_err)?
        .with_root_certificates(bundled_root_store())
        .with_no_client_auth())
}

/// Debug/CI-only trust anchor for the test relay (maintainer-ratified 4b-2):
/// reads `TEZCA_TEST_RELAY_PIN` (hex SHA-256 of the relay's leaf cert DER) and
/// anchors trust on exactly that certificate, reusing the audited
/// [`PinVerifier`]. Compiled ONLY under the `test-relay-anchor` feature — the
/// release .so carries neither this code nor the env-var string
/// (asserted by scripts/check-invariants.sh). No new dependencies, no FFI
/// surface: the instrumented harness sets the env var in-process.
#[cfg(feature = "test-relay-anchor")]
pub(super) fn env_test_pin() -> Option<[u8; 32]> {
    let hex_pin = std::env::var("TEZCA_TEST_RELAY_PIN").ok()?;
    let bytes = hex::decode(hex_pin.trim()).ok()?;
    bytes.try_into().ok()
}

/// Establishes a TLS stream to `host` over `tcp`, honoring an optional pin.
pub(super) async fn tls_connect(
    tcp: TcpStream,
    host: &str,
    pin: Option<[u8; 32]>,
) -> Result<TlsStream<TcpStream>> {
    // A per-conversation pin always wins; the test anchor only fills the
    // no-pin (bundled-roots) case, and only in test-relay-anchor builds.
    #[cfg(feature = "test-relay-anchor")]
    let pin = pin.or_else(env_test_pin);
    let config = if let Some(pin) = pin {
        pinned_client_config(pin)?
    } else {
        bundled_client_config()?
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::WebPkiServerVerifier;

    /// Generates a self-signed leaf and returns its DER plus the SHA-256 the
    /// verifier would pin it to.
    fn self_signed() -> (CertificateDer<'static>, [u8; 32]) {
        let cert = rcgen::generate_simple_self_signed(vec!["relay.example".to_string()])
            .expect("generate self-signed cert")
            .cert;
        let der = cert.der().clone();
        let digest = ring::digest::digest(&ring::digest::SHA256, der.as_ref());
        let mut pin = [0u8; 32];
        pin.copy_from_slice(digest.as_ref());
        (der, pin)
    }

    fn verifier(pin: [u8; 32]) -> PinVerifier {
        PinVerifier {
            pin,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    fn server_name() -> ServerName<'static> {
        ServerName::try_from("relay.example").expect("server name")
    }

    #[test]
    fn pinned_certificate_is_accepted() {
        let (der, pin) = self_signed();
        let name = server_name();
        let result = verifier(pin).verify_server_cert(
            &der,
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_hours(500_000)),
        );
        assert!(result.is_ok(), "cert matching the pin must be accepted");
    }

    #[test]
    fn certificate_not_matching_pin_is_rejected() {
        // The presented cert is legitimate and self-consistent, but its DER
        // hash differs from the pin the conversation was configured with — the
        // exact MITM/cert-swap case pinning exists to stop.
        let (presented, _presented_pin) = self_signed();
        let (_other, expected_pin) = self_signed();
        assert_ne!(
            ring::digest::digest(&ring::digest::SHA256, presented.as_ref()).as_ref(),
            expected_pin,
            "the two self-signed certs must differ (sanity)"
        );
        let name = server_name();
        let result = verifier(expected_pin).verify_server_cert(
            &presented,
            &[],
            &name,
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_hours(500_000)),
        );
        let err = result.expect_err("cert not matching the pin must be rejected");
        assert!(
            matches!(err, rustls::Error::General(_)),
            "rejection is a pin mismatch, got {err:?}"
        );
    }

    #[test]
    fn advertises_the_providers_signature_schemes() {
        // The verifier must offer the ring provider's schemes, else the
        // handshake would negotiate nothing and every wss:// connection fail.
        let (_der, pin) = self_signed();
        assert!(
            !verifier(pin).supported_verify_schemes().is_empty(),
            "must advertise the ring provider's signature schemes"
        );
    }

    #[test]
    fn bundled_config_builds_with_isrg_root_x1() {
        let _config = bundled_client_config().expect("bundled config builds");
        assert!(
            webpki_roots::TLS_SERVER_ROOTS.len() > 100,
            "the Mozilla store is present"
        );
        let has_isrg = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .any(|ta| String::from_utf8_lossy(ta.subject.as_ref()).contains("ISRG Root X1"));
        assert!(
            has_isrg,
            "ISRG Root X1 (Let's Encrypt) must be a bundled anchor"
        );
    }

    #[test]
    fn bundled_config_rejects_self_signed() {
        let (leaf, _) = self_signed();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(bundled_root_store()), provider)
                .build()
                .expect("webpki verifier builds from the bundled store");
        let result = verifier.verify_server_cert(&leaf, &[], &server_name(), &[], UnixTime::now());
        assert!(
            matches!(
                result,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                ))
            ),
            "a self-signed leaf must be rejected as UnknownIssuer, got {result:?}"
        );
    }
}
