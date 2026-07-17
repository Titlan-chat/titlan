// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! UniFFI surface (A3): the Kotlin-facing wrapper over [`crate::client`].
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
pub fn generate_db_key() -> Vec<u8> {
    DbKey::generate().as_bytes().to_vec()
}

/// FFI error surfaced to Kotlin (flattened from [`crate::CoreError`]).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TitlanError {
    #[error("pairing inbox unavailable (stale QR)")]
    PairingUnavailable,
    #[error("network error: {msg}")]
    Network { msg: String },
    #[error("{msg}")]
    Other { msg: String },
}

impl From<crate::CoreError> for TitlanError {
    fn from(e: crate::CoreError) -> Self {
        match e {
            crate::CoreError::PairingUnavailable => TitlanError::PairingUnavailable,
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

    pub fn initialize_identity(&self) -> std::result::Result<(), TitlanError> {
        Ok(self.inner.initialize_identity()?)
    }

    pub fn is_initialized(&self) -> std::result::Result<bool, TitlanError> {
        Ok(self.inner.is_initialized()?)
    }

    pub fn export_pairing_payload(&self) -> std::result::Result<Vec<u8>, TitlanError> {
        Ok(self.inner.export_pairing_payload()?.as_bytes().to_vec())
    }

    pub fn begin_pairing_from_scan(
        &self,
        payload: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, TitlanError> {
        Ok(self.inner.begin_pairing_from_scan(&payload)?.to_vec())
    }

    pub fn list_conversations(&self) -> std::result::Result<Vec<Vec<u8>>, TitlanError> {
        Ok(self
            .inner
            .list_conversations()?
            .into_iter()
            .map(|c| c.to_vec())
            .collect())
    }

    pub fn set_conversation_relay(
        &self,
        conversation_id: Vec<u8>,
        url: String,
    ) -> std::result::Result<(), TitlanError> {
        Ok(self
            .inner
            .set_conversation_relay(&conv_id(&conversation_id)?, &url)?)
    }

    pub fn send_chat(
        &self,
        conversation_id: Vec<u8>,
        text: String,
    ) -> std::result::Result<(), TitlanError> {
        Ok(self.inner.send_chat(&conv_id(&conversation_id)?, &text)?)
    }

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

    pub fn stop_sync(&self) -> std::result::Result<(), TitlanError> {
        Ok(self.inner.stop_sync()?)
    }
}
