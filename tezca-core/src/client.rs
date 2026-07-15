// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! `TitlanClient` — the high-level Phase 4a surface consumed by the Android
//! app through UniFFI (bindings generated in Phase 4b). It composes identity,
//! session, storage, and the relay client behind one object; Kotlin stays
//! UI-only (A3).
//!
//! Phase 4a scaffold: `open` and the identity accessors are wired so the
//! acceptance tests reach the genuinely-new behavior; pairing, sync, sending,
//! §10.7 recovery, and per-conversation pinning are the green implementation.

use std::path::Path;
use std::sync::Arc;

use crate::Result;
use crate::storage::{DbKey, Store, StoredMessage};

/// Opaque per-conversation identifier (16 random bytes; matches storage).
pub type ConversationId = [u8; 16];

/// Connection state for one conversation's receive-sync, pushed to the UI via
/// [`ConnectionObserver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Establishing the WebSocket / subscribing.
    Connecting,
    /// Subscribed and receiving.
    Online,
    /// No network (e.g. GrapheneOS per-app network revoked); backing off.
    Offline,
    /// Waiting `secs` before the next reconnect attempt.
    Backoff {
        /// Seconds until the next attempt.
        secs: u32,
    },
    /// One-sided mailbox loss; recovering in-band via `mailbox-update/1`.
    Recovering,
    /// Total mailbox loss (§10.7 option ii): the user must re-pair.
    RePairRequired,
}

/// Sink for decrypted, persisted incoming messages (Kotlin implements it).
pub trait MessageReceiver: Send + Sync {
    /// Called once per delivered message, after it is decrypted and stored.
    fn on_message(&self, conversation_id: ConversationId, message: StoredMessage);
}

/// Sink for per-conversation connection-state changes (Kotlin implements it).
pub trait ConnectionObserver: Send + Sync {
    /// Called on every connection-state transition.
    fn on_state(&self, conversation_id: ConversationId, state: ConnectionState);
}

/// The bytes shown as a pairing QR (or shared as a link fragment). Format is
/// normative in `proto/pairing.md`.
pub struct PairingPayload {
    bytes: Vec<u8>,
}

impl PairingPayload {
    /// Wraps raw payload bytes (e.g. decoded from a scanned QR).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The raw payload bytes to encode into a QR / link fragment.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// High-level client: one instance per on-device identity/database.
pub struct TitlanClient {
    store: Store,
}

impl TitlanClient {
    /// Opens (creating if absent) the encrypted database at `path` with `key`,
    /// using `my_relay_url` as the default relay for this device's inboxes and
    /// new conversations (INV-5: every conversation may override it).
    pub fn open(path: &Path, key: &DbKey, _my_relay_url: &str) -> Result<TitlanClient> {
        Ok(TitlanClient {
            store: Store::open(path, key)?,
        })
    }

    /// Generates the local identity + initial prekeys (A1). Errors if already
    /// initialized.
    pub fn initialize_identity(&self) -> Result<()> {
        crate::identity::initialize(&self.store)
    }

    /// `true` once [`Self::initialize_identity`] has completed.
    pub fn is_initialized(&self) -> Result<bool> {
        crate::identity::is_initialized(&self.store)
    }

    /// The database schema version (used by the migration test).
    pub fn schema_version(&self) -> Result<u32> {
        self.store.schema_version()
    }

    /// Exports the pairing payload and creates the single-use pairing inbox on
    /// the default relay (`proto/pairing.md`).
    pub fn export_pairing_payload(&self) -> Result<PairingPayload> {
        todo!("Phase 4a green")
    }

    /// Processes a scanned pairing payload: PQXDH, creates this side's inbox,
    /// sends `pair-ack/1`, and records the conversation. Returns its id.
    pub fn begin_pairing_from_scan(&self, _payload: &[u8]) -> Result<ConversationId> {
        todo!("Phase 4a green")
    }

    /// Lists conversation ids (most-recent first).
    pub fn list_conversations(&self) -> Result<Vec<ConversationId>> {
        todo!("Phase 4a green")
    }

    /// Overrides the relay URL for a conversation (INV-5).
    pub fn set_conversation_relay(&self, _id: &ConversationId, _url: &str) -> Result<()> {
        todo!("Phase 4a green")
    }

    /// Sets (or clears with `None`) the per-conversation TLS SPKI pin
    /// (schema v2 `relay_pin`; cert-pinning is optional-but-designed).
    pub fn set_conversation_pin(
        &self,
        _id: &ConversationId,
        _spki_sha256: Option<[u8; 32]>,
    ) -> Result<()> {
        todo!("Phase 4a green")
    }

    /// Reads the per-conversation TLS SPKI pin, if any.
    pub fn conversation_pin(&self, _id: &ConversationId) -> Result<Option<[u8; 32]>> {
        todo!("Phase 4a green")
    }

    /// Messages of a conversation in insertion order.
    pub fn messages(&self, _id: &ConversationId) -> Result<Vec<StoredMessage>> {
        todo!("Phase 4a green")
    }

    /// Queues and sends a `chat/1` message (persists `pending`, deposits,
    /// marks sent; retried by the sync loop on failure).
    pub fn send_chat(&self, _id: &ConversationId, _text: &str) -> Result<()> {
        todo!("Phase 4a green")
    }

    /// Starts per-conversation receive-sync (WebSocket + reconnect/backoff +
    /// §10.7 recovery). Delivery and state changes arrive on the callbacks.
    pub fn start_sync(
        &self,
        _observer: Arc<dyn ConnectionObserver>,
        _receiver: Arc<dyn MessageReceiver>,
    ) -> Result<()> {
        todo!("Phase 4a green")
    }

    /// Stops all sync tasks.
    pub fn stop_sync(&self) -> Result<()> {
        todo!("Phase 4a green")
    }
}
