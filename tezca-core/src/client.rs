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
use std::sync::{Arc, OnceLock};

use tokio::runtime::Runtime;

use crate::Result;
use crate::relay_client::Engine;
use crate::storage::{DbKey, Store, StoredMessage};

/// One process-wide async runtime shared by every [`TitlanClient`].
///
/// A device runs a single identity in production, but tests (and any host
/// that opens several databases) create many clients. Giving each its own
/// multi-thread runtime makes the live OS-thread count scale with the number
/// of clients, which exhausts `RLIMIT_NPROC` on constrained hosts (CI's 2-core
/// runners) and makes tokio panic with "OS can't spawn worker thread". A
/// single bounded runtime keeps the worker-thread count constant regardless of
/// how many clients are open. Handles are cheap to clone and safe to share.
fn shared_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tezca-core")
            .build()
            .expect("build shared tezca-core runtime")
    })
}

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
    store: Arc<Store>,
    my_relay: String,
    engine: Arc<Engine>,
}

impl TitlanClient {
    /// Opens (creating if absent) the encrypted database at `path` with `key`,
    /// using `my_relay_url` as the default relay for this device's inboxes and
    /// new conversations (INV-5: every conversation may override it).
    pub fn open(path: &Path, key: &DbKey, my_relay_url: &str) -> Result<TitlanClient> {
        let store = Arc::new(Store::open(path, key)?);
        let engine = Engine::new(
            store.clone(),
            my_relay_url.to_owned(),
            shared_runtime().handle().clone(),
        )?;
        Ok(TitlanClient {
            store,
            my_relay: my_relay_url.to_owned(),
            engine,
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
        let pairing_inbox = shared_runtime().block_on(self.engine.create_mailbox())?;
        self.engine.spawn_pairing(pairing_inbox.clone());
        let bundle = crate::identity::export_prekey_bundle(&self.store)?;
        let payload =
            crate::pairing::encode_pairing_payload(&bundle, &self.my_relay, &pairing_inbox);
        Ok(PairingPayload::from_bytes(payload))
    }

    /// Processes a scanned pairing payload: PQXDH, creates this side's inbox,
    /// sends `pair-ack/1`, awaits the peer's reply, and records the
    /// conversation. Returns its id. `PairingUnavailable` if the QR is stale.
    pub fn begin_pairing_from_scan(&self, payload: &[u8]) -> Result<ConversationId> {
        let conv = shared_runtime().block_on(self.engine.begin_pairing(payload))?;
        self.engine.spawn_conversation(conv);
        Ok(conv)
    }

    /// Lists conversation ids (most-recent first).
    pub fn list_conversations(&self) -> Result<Vec<ConversationId>> {
        self.store.list_conversation_ids()
    }

    /// Overrides the relay URL for a conversation (INV-5).
    pub fn set_conversation_relay(&self, id: &ConversationId, url: &str) -> Result<()> {
        self.store.set_conversation_relay(id, url)
    }

    /// Sets (or clears with `None`) the per-conversation TLS SPKI pin
    /// (schema v2 `relay_pin`; cert-pinning is optional-but-designed).
    pub fn set_conversation_pin(
        &self,
        id: &ConversationId,
        spki_sha256: Option<[u8; 32]>,
    ) -> Result<()> {
        self.store.set_conversation_pin(id, spki_sha256)
    }

    /// Reads the per-conversation TLS SPKI pin, if any.
    pub fn conversation_pin(&self, id: &ConversationId) -> Result<Option<[u8; 32]>> {
        self.store.conversation_pin(id)
    }

    /// Messages of a conversation in insertion order.
    pub fn messages(&self, id: &ConversationId) -> Result<Vec<StoredMessage>> {
        self.store.list_messages(id)
    }

    /// Queues and sends a `chat/1` message (persists `pending`, deposits,
    /// marks sent; retried by the sync loop on failure).
    pub fn send_chat(&self, id: &ConversationId, text: &str) -> Result<()> {
        shared_runtime().block_on(self.engine.send_chat(id, text))
    }

    /// Starts per-conversation receive-sync (WebSocket + reconnect/backoff +
    /// §10.7 recovery). Delivery and state changes arrive on the callbacks.
    pub fn start_sync(
        &self,
        observer: Arc<dyn ConnectionObserver>,
        receiver: Arc<dyn MessageReceiver>,
    ) -> Result<()> {
        self.engine.set_callbacks(observer, receiver);
        for conv in self.store.list_conversation_ids()? {
            self.engine.spawn_conversation(conv);
        }
        Ok(())
    }

    /// Stops all sync tasks. They currently run on the shared runtime and end
    /// when their subscriptions error out; explicit cancellation is post-MVP.
    pub fn stop_sync(&self) -> Result<()> {
        Ok(())
    }
}
