// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! `UniFFI` surface (A3): the Kotlin-facing wrapper over [`crate::client`].
//! Bindings are generated in Phase 4b; the Rust integration tests exercise the
//! underlying [`crate::client::TitlanClient`] directly. Fixed-size ids/keys
//! cross the FFI as `Vec<u8>` (16 or 32 bytes); the wrapper converts.

#![allow(missing_docs)]

use std::sync::Arc;

use zeroize::Zeroize;

use crate::client::{
    ConnectionObserver, ConnectionState, ConversationId, MessageReceiver, TitlanClient,
};
use crate::storage::{DbKey, StoredMessage};

/// Generates a fresh 32-byte DB key from the OS CSPRNG in Rust (maintainer
/// decision 5a: the key is born in tezca-core, wrapped by the caller —
/// Android Keystore on-device). The returned bytes cross the FFI once at
/// birth; the Kotlin side wraps and zeroizes its copy.
#[uniffi::export]
#[must_use]
pub fn generate_db_key() -> Vec<u8> {
    DbKey::generate().as_bytes().to_vec()
}

/// Which validity bound a rejected v3 offer failed (mirror of
/// [`crate::error::OfferExpiryDetail`]; freeze §5 — one user surface for
/// both, distinct details for diagnostics).
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiOfferExpiryDetail {
    Expired,
    NotYetValid,
}

/// FFI error surfaced to Kotlin (flattened from [`crate::CoreError`]).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TitlanError {
    #[error("pairing inbox unavailable (stale QR)")]
    PairingUnavailable,
    /// A scanned offer is outside its embedded validity window (freeze §5;
    /// raised at decode, before any network I/O — timestamps only, no INV-1
    /// exposure).
    #[error("pairing offer outside validity (issued_at {issued_at}, ttl {ttl_s} s, now {now})")]
    OfferExpired {
        issued_at: u64,
        ttl_s: u32,
        now: u64,
        detail: FfiOfferExpiryDetail,
    },
    /// The offer's `offer_sig` did not verify (crypto class, distinct from
    /// proof-of-scan failure).
    #[error("pairing offer signature invalid")]
    OfferSignatureInvalid,
    /// The responder's `pair-ack` failed proof-of-scan verification (crypto
    /// class; the offer is burned — 5a-2 four-way surface, P5-D2).
    #[error("proof-of-scan verification failed")]
    ProofOfScanFailed,
    /// Structurally invalid input — truncated/oversized fields, trailing
    /// bytes, or an unsupported payload/offer version (v1/v2 offers land
    /// here, never in a crypto class — 5a-2 four-way surface, P5-D2).
    #[error("malformed input: {msg}")]
    Malformed { msg: String },
    /// Underlying libsignal protocol failure (mirror of
    /// [`crate::CoreError::Signal`]; on the pairing path these are key-decode
    /// and PQXDH failures — the Kotlin pairing mapper classes them CRYPTO).
    #[error("protocol error: {msg}")]
    Protocol { msg: String },
    #[error("network error: {msg}")]
    Network { msg: String },
    #[error("{msg}")]
    Other { msg: String },
}

impl From<crate::CoreError> for TitlanError {
    fn from(e: crate::CoreError) -> Self {
        match e {
            crate::CoreError::PairingUnavailable => TitlanError::PairingUnavailable,
            crate::CoreError::OfferExpired {
                issued_at,
                ttl_s,
                now,
                detail,
            } => TitlanError::OfferExpired {
                issued_at,
                ttl_s,
                now,
                detail: match detail {
                    crate::error::OfferExpiryDetail::Expired => FfiOfferExpiryDetail::Expired,
                    crate::error::OfferExpiryDetail::NotYetValid => {
                        FfiOfferExpiryDetail::NotYetValid
                    }
                },
            },
            crate::CoreError::OfferSignatureInvalid => TitlanError::OfferSignatureInvalid,
            crate::CoreError::Network(m) => TitlanError::Network { msg: m },
            other => TitlanError::Other {
                msg: other.to_string(),
            },
        }
    }
}

/// Connection state pushed to the UI (mirror of [`ConnectionState`]).
#[derive(uniffi::Enum)]
pub enum FfiConnectionState {
    Connecting,
    Online,
    Offline,
    Backoff { secs: u32 },
    Recovering,
    RePairRequired,
}

impl From<ConnectionState> for FfiConnectionState {
    fn from(s: ConnectionState) -> Self {
        match s {
            ConnectionState::Connecting => FfiConnectionState::Connecting,
            ConnectionState::Online => FfiConnectionState::Online,
            ConnectionState::Offline => FfiConnectionState::Offline,
            ConnectionState::Backoff { secs } => FfiConnectionState::Backoff { secs },
            ConnectionState::Recovering => FfiConnectionState::Recovering,
            ConnectionState::RePairRequired => FfiConnectionState::RePairRequired,
        }
    }
}

/// A stored message delivered to the UI.
#[derive(uniffi::Record)]
pub struct FfiMessage {
    pub id: Vec<u8>,
    pub conversation_id: Vec<u8>,
    pub incoming: bool,
    pub payload_type: u8,
    pub type_version: u8,
    pub body: Vec<u8>,
}

impl From<StoredMessage> for FfiMessage {
    fn from(m: StoredMessage) -> Self {
        FfiMessage {
            id: m.id.to_vec(),
            conversation_id: m.conversation_id.to_vec(),
            incoming: matches!(m.direction, crate::storage::Direction::Incoming),
            payload_type: m.payload_type,
            type_version: m.type_version,
            body: m.body,
        }
    }
}

/// Kotlin implements these to receive delivered messages / state changes.
#[uniffi::export(callback_interface)]
pub trait FfiMessageReceiver: Send + Sync {
    fn on_message(&self, conversation_id: Vec<u8>, message: FfiMessage);
}

#[uniffi::export(callback_interface)]
pub trait FfiConnectionObserver: Send + Sync {
    fn on_state(&self, conversation_id: Vec<u8>, state: FfiConnectionState);
    /// §10.7 recovery exhausted → re-pair is the last resort (frozen §1).
    fn on_conversation_needs_repair(&self, conversation_id: Vec<u8>);
    /// A queued send permanently failed (relay rejected the blob).
    fn on_permanent_send_failure(&self, conversation_id: Vec<u8>, message_id: Vec<u8>);
    /// The encrypted store could not be read/written.
    fn on_storage_error(&self, detail: String);
}

struct ReceiverAdapter(Box<dyn FfiMessageReceiver>);
impl MessageReceiver for ReceiverAdapter {
    fn on_message(&self, conversation_id: ConversationId, message: StoredMessage) {
        self.0.on_message(conversation_id.to_vec(), message.into());
    }
}

struct ObserverAdapter(Box<dyn FfiConnectionObserver>);
impl ConnectionObserver for ObserverAdapter {
    fn on_state(&self, conversation_id: ConversationId, state: ConnectionState) {
        self.0.on_state(conversation_id.to_vec(), state.into());
    }
    fn on_conversation_needs_repair(&self, conversation_id: ConversationId) {
        self.0
            .on_conversation_needs_repair(conversation_id.to_vec());
    }
    fn on_permanent_send_failure(&self, conversation_id: ConversationId, message_id: [u8; 16]) {
        self.0
            .on_permanent_send_failure(conversation_id.to_vec(), message_id.to_vec());
    }
    fn on_storage_error(&self, detail: &str) {
        self.0.on_storage_error(detail.to_owned());
    }
}

/// The embedded validity window of a v3 offer (mirror of
/// [`crate::client::OfferValidity`]; freeze §6 — the ONE governing value the
/// UI countdown reads).
#[derive(uniffi::Record)]
pub struct FfiOfferValidity {
    /// Mint time embedded in the offer (Unix seconds, offerer clock).
    pub issued_at: u64,
    /// Time-to-live embedded in the offer, in seconds.
    pub ttl_s: u32,
}

/// The Kotlin-facing client object.
#[derive(uniffi::Object)]
pub struct FfiClient {
    inner: TitlanClient,
}

fn conv_id(bytes: &[u8]) -> std::result::Result<ConversationId, TitlanError> {
    bytes.try_into().map_err(|_| TitlanError::Other {
        msg: "conversation id must be 16 bytes".into(),
    })
}

#[uniffi::export]
impl FfiClient {
    /// Opens the encrypted store at `db_path` with a 32-byte `db_key`.
    /// The FFI-side transient copies of the key are zeroized before
    /// returning (INV-1 hygiene; [`DbKey`] itself zeroizes on drop).
    ///
    /// # Errors
    ///
    /// Returns [`TitlanError::Other`] when `db_key` is not exactly 32 bytes,
    /// otherwise the [`CoreError`] mapping from opening the store (bad key,
    /// storage failures).
    #[uniffi::constructor]
    pub fn open(
        db_path: String,
        db_key: Vec<u8>,
        my_relay_url: String,
    ) -> std::result::Result<Arc<Self>, TitlanError> {
        let mut db_key = db_key;
        // The [u8; 32] is moved straight into DbKey (zeroize-on-drop), so
        // the only residual FFI copy is the Vec, zeroized on every path.
        let key = <[u8; 32]>::try_from(db_key.as_slice()).map(DbKey::from_bytes);
        db_key.zeroize();
        let key = key.map_err(|_| TitlanError::Other {
            msg: "db key must be 32 bytes".into(),
        })?;
        let inner = TitlanClient::open(std::path::Path::new(&db_path), &key, &my_relay_url)?;
        Ok(Arc::new(FfiClient { inner }))
    }

    ///
    /// # Errors
    ///
    /// Returns the [`CoreError`] mapping: storage errors (including an already-
    /// initialized identity) and libsignal key-generation failures.
    pub fn initialize_identity(&self) -> std::result::Result<(), TitlanError> {
        Ok(self.inner.initialize_identity()?)
    }

    ///
    /// # Errors
    ///
    /// Returns the [`CoreError`] mapping of storage query failures.
    pub fn is_initialized(&self) -> std::result::Result<bool, TitlanError> {
        Ok(self.inner.is_initialized()?)
    }

    /// v3 asymmetric offer export (authenticated embedded validity +
    /// proof-of-scan + derived-recovery pairing).
    ///
    /// # Errors
    ///
    /// Returns the [`CoreError`] mapping: storage/libsignal bundle-export
    /// errors and [`TitlanError::Network`] when setting up the pairing inbox
    /// fails.
    pub fn export_pairing_offer(&self) -> std::result::Result<Vec<u8>, TitlanError> {
        Ok(self.inner.export_pairing_offer()?.as_bytes().to_vec())
    }

    /// Consumes a scanned v3 offer; returns the new conversation id. Validity
    /// is evaluated at decode, BEFORE any network I/O (freeze §4).
    ///
    /// # Errors
    ///
    /// Returns [`TitlanError::OfferExpired`]/[`TitlanError::OfferSignatureInvalid`]
    /// from the decode-time validity rule, [`TitlanError::PairingUnavailable`]
    /// for a stale offer, otherwise the [`CoreError`] mapping of parse,
    /// network, storage, and libsignal handshake failures.
    pub fn begin_pairing_from_offer(
        &self,
        payload: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, TitlanError> {
        Ok(self.inner.begin_pairing_from_offer(&payload)?.to_vec())
    }

    /// Reads the relay URL out of a scanned offer WITHOUT establishing a
    /// session, so the UI can surface a non-default relay for confirmation
    /// before pairing (frozen §3). Parsing stays in core (A3).
    ///
    /// # Errors
    ///
    /// Returns the [`CoreError`] mapping when `payload` is not structurally a
    /// v3 offer.
    pub fn peek_offer_relay(&self, payload: Vec<u8>) -> std::result::Result<String, TitlanError> {
        Ok(self.inner.peek_offer_relay(&payload)?)
    }

    /// Reads the embedded validity window (`issued_at`, `ttl_s`) from a
    /// minted/scanned offer WITHOUT accepting it — the single source for the
    /// UI countdown (freeze §6; the display-only Kotlin TTL constant is
    /// deleted in the same change).
    ///
    /// # Errors
    ///
    /// Returns the [`CoreError`] mapping when `payload` is not structurally a
    /// v3 offer.
    pub fn peek_offer_validity(
        &self,
        payload: Vec<u8>,
    ) -> std::result::Result<FfiOfferValidity, TitlanError> {
        let v = self.inner.peek_offer_validity(&payload)?;
        Ok(FfiOfferValidity {
            issued_at: v.issued_at,
            ttl_s: v.ttl_s,
        })
    }

    ///
    /// # Errors
    ///
    /// Returns the [`CoreError`] mapping of storage query failures.
    pub fn list_conversations(&self) -> std::result::Result<Vec<Vec<u8>>, TitlanError> {
        Ok(self
            .inner
            .list_conversations()?
            .into_iter()
            .map(|c| c.to_vec())
            .collect())
    }

    ///
    /// # Errors
    ///
    /// Returns [`TitlanError::Other`] when `conversation_id` is not 16 bytes,
    /// otherwise the storage-failure mapping.
    pub fn set_conversation_relay(
        &self,
        conversation_id: Vec<u8>,
        url: String,
    ) -> std::result::Result<(), TitlanError> {
        Ok(self
            .inner
            .set_conversation_relay(&conv_id(&conversation_id)?, &url)?)
    }

    ///
    /// # Errors
    ///
    /// Returns [`TitlanError::Other`] when `conversation_id` is not 16 bytes,
    /// otherwise the [`CoreError`] mapping of persistence failures (the deposit
    /// is retried by sync, never an error here).
    pub fn send_chat(
        &self,
        conversation_id: Vec<u8>,
        text: String,
    ) -> std::result::Result<(), TitlanError> {
        Ok(self.inner.send_chat(&conv_id(&conversation_id)?, &text)?)
    }

    ///
    /// # Errors
    ///
    /// Returns [`TitlanError::Other`] when `conversation_id` is not 16 bytes,
    /// otherwise the storage-failure mapping.
    pub fn messages(
        &self,
        conversation_id: Vec<u8>,
    ) -> std::result::Result<Vec<FfiMessage>, TitlanError> {
        Ok(self
            .inner
            .messages(&conv_id(&conversation_id)?)?
            .into_iter()
            .map(FfiMessage::from)
            .collect())
    }

    ///
    /// # Errors
    ///
    /// Returns the [`CoreError`] mapping when listing the conversations to
    /// spawn fails.
    pub fn start_sync(
        &self,
        observer: Box<dyn FfiConnectionObserver>,
        receiver: Box<dyn FfiMessageReceiver>,
    ) -> std::result::Result<(), TitlanError> {
        Ok(self.inner.start_sync(
            Arc::new(ObserverAdapter(observer)),
            Arc::new(ReceiverAdapter(receiver)),
        )?)
    }

    ///
    /// # Errors
    ///
    /// Returns the [`CoreError`] mapping from the client `stop_sync`, which is
    /// infallible in the current implementation.
    pub fn stop_sync(&self) -> std::result::Result<(), TitlanError> {
        Ok(self.inner.stop_sync()?)
    }
}

// ---- 5a-2: four-way failure-surface classification at the FFI boundary ----
// (P5-D2, ratified 2026-08-05; freeze §5 seam — 5a-1 landed the core
// variants, 5a-2 makes the four-way class visible across the FFI so the
// Kotlin dialog mapper can distinguish network / expired / malformed /
// crypto without string inspection. The classes live in the VARIANTS; the
// user vocabulary lives in the Kotlin mapper.)
#[cfg(test)]
mod classification_tests {
    use super::TitlanError;
    use crate::CoreError;
    use crate::error::OfferExpiryDetail;

    /// The audited accept-path-reachable set (evidence log [AUD.A]) mapped to
    /// its FFI classification — TOTAL: no offer-caused or transport failure
    /// may fall through to `Other` (the internal class). Deliberate INTERNAL
    /// assignments (`Storage`, `PayloadTooLarge`) are asserted LAST as
    /// `Other`, so this test pins the whole table.
    #[test]
    fn accept_path_classification_is_total_and_four_way() {
        // NETWORK-UNREACHABLE class.
        assert!(
            matches!(
                TitlanError::from(CoreError::Network("relay unreachable".into())),
                TitlanError::Network { .. }
            ),
            "Network must map to TitlanError::Network"
        );
        // EXPIRED class: both details, fields preserved (timestamps only).
        for detail in [OfferExpiryDetail::Expired, OfferExpiryDetail::NotYetValid] {
            match TitlanError::from(CoreError::OfferExpired {
                issued_at: 1_755_000_000,
                ttl_s: 3600,
                now: 1_755_010_000,
                detail,
            }) {
                TitlanError::OfferExpired {
                    issued_at,
                    ttl_s,
                    now,
                    ..
                } => {
                    assert_eq!(issued_at, 1_755_000_000, "issued_at carried");
                    assert_eq!(ttl_s, 3600, "ttl_s carried");
                    assert_eq!(now, 1_755_010_000, "now carried");
                }
                other => panic!("OfferExpired({detail:?}) must stay OfferExpired, got {other:?}"),
            }
        }
        assert!(
            matches!(
                TitlanError::from(CoreError::PairingUnavailable),
                TitlanError::PairingUnavailable
            ),
            "PairingUnavailable must stay distinct (EXPIRED class in the mapper)"
        );
        // CRYPTO class: signature, distinct.
        assert!(
            matches!(
                TitlanError::from(CoreError::OfferSignatureInvalid),
                TitlanError::OfferSignatureInvalid
            ),
            "OfferSignatureInvalid must stay distinct"
        );
        // MALFORMED class: structural decode failures…
        assert!(
            matches!(
                TitlanError::from(CoreError::Malformed("trailing bytes in pairing offer")),
                TitlanError::Malformed { .. }
            ),
            "Malformed must map to TitlanError::Malformed (class MALFORMED), not Other"
        );
        // …AND unsupported-version (v1/v2 bytes).
        assert!(
            matches!(
                TitlanError::from(CoreError::UnsupportedVersion { got: 2 }),
                TitlanError::Malformed { .. }
            ),
            "UnsupportedVersion must map to TitlanError::Malformed (class MALFORMED), not Other"
        );
        // CRYPTO class: proof-of-scan and libsignal processing.
        assert!(
            matches!(
                TitlanError::from(CoreError::ProofOfScanFailed),
                TitlanError::ProofOfScanFailed
            ),
            "ProofOfScanFailed must map to TitlanError::ProofOfScanFailed, not Other"
        );
        assert!(
            matches!(
                TitlanError::from(CoreError::Signal("bad key data".into())),
                TitlanError::Protocol { .. }
            ),
            "Signal must map to TitlanError::Protocol (class CRYPTO on the pairing path)"
        );
        // Deliberate INTERNAL class: device-local faults stay in Other.
        assert!(
            matches!(
                TitlanError::from(CoreError::Storage("disk full".into())),
                TitlanError::Other { .. }
            ),
            "Storage is the INTERNAL class: Other"
        );
        assert!(
            matches!(
                TitlanError::from(CoreError::PayloadTooLarge {
                    len: 9000,
                    max: 8186
                }),
                TitlanError::Other { .. }
            ),
            "PayloadTooLarge is the INTERNAL class: Other"
        );
    }

    /// Negative pin (order: "unsupported-version never surfaces as crypto"):
    /// the structural family maps to `Malformed` and to NO crypto-class
    /// variant.
    #[test]
    fn structural_family_never_surfaces_as_crypto() {
        for e in [
            CoreError::UnsupportedVersion { got: 1 },
            CoreError::UnsupportedVersion { got: 2 },
            CoreError::Malformed("offer ttl_s out of range"),
        ] {
            let mapped = TitlanError::from(e);
            assert!(
                !matches!(
                    mapped,
                    TitlanError::OfferSignatureInvalid
                        | TitlanError::ProofOfScanFailed
                        | TitlanError::Protocol { .. }
                ),
                "structural failure must never surface as a crypto-class variant, got {mapped:?}"
            );
            assert!(
                matches!(mapped, TitlanError::Malformed { .. }),
                "structural failure must surface as Malformed, got {mapped:?}"
            );
        }
    }

    /// Negative pin (order: "signature failure never surfaces as expired"):
    /// every crypto-class failure maps to its own distinct variant and never
    /// to `OfferExpired`.
    #[test]
    fn crypto_family_is_distinct_and_never_expired() {
        assert!(
            matches!(
                TitlanError::from(CoreError::ProofOfScanFailed),
                TitlanError::ProofOfScanFailed
            ),
            "ProofOfScanFailed must map to its own variant, not Other"
        );
        assert!(
            matches!(
                TitlanError::from(CoreError::Signal("PQXDH failure".into())),
                TitlanError::Protocol { .. }
            ),
            "Signal must map to Protocol, not Other"
        );
        for e in [
            CoreError::OfferSignatureInvalid,
            CoreError::ProofOfScanFailed,
            CoreError::Signal("PQXDH failure".into()),
        ] {
            let mapped = TitlanError::from(e);
            assert!(
                !matches!(mapped, TitlanError::OfferExpired { .. }),
                "a crypto-class failure must never surface as expired, got {mapped:?}"
            );
        }
    }
}
