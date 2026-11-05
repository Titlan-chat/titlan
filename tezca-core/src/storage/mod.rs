// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! SQLCipher-encrypted persistence (A4, INV-1).
//!
//! The database key is an INPUT to this module: core never generates it
//! unprompted, never writes it anywhere, never logs it. On Android the raw
//! key exists only in RAM, wrapped at rest by a non-exportable hardware
//! Keystore key (Phase 4). Tests hold generated keys in memory only.

pub(crate) mod schema;
pub(crate) mod signal_stores;

use std::path::Path;
use std::sync::Mutex;

use rand::TryRngCore;
use zeroize::Zeroize;

use crate::envelope::InnerFrame;
use crate::storage::schema::sql_err;
use crate::{CoreError, Result};

/// A 32-byte `SQLCipher` database key. Zeroized on drop.
pub struct DbKey([u8; 32]);

impl Drop for DbKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl DbKey {
    /// Generates a fresh key from the OS CSPRNG. The caller owns wrapping
    /// and storage (Android Keystore on-device; RAM only in tests). An OS
    /// whose CSPRNG fails is unrecoverable, hence the panic.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG cannot provide entropy — unrecoverable by design
    /// (see above).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OS CSPRNG unavailable");
        Self(bytes)
    }

    /// Wraps existing key bytes (e.g. unwrapped by Android Keystore).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Direction of a stored message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    /// Sent by the local identity.
    Outgoing = 0,
    /// Received from the peer.
    Incoming = 1,
}

/// A message row read back from storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// Message id (16 random bytes).
    pub id: [u8; 16],
    /// Owning conversation id.
    pub conversation_id: [u8; 16],
    /// Direction.
    pub direction: Direction,
    /// Payload type byte as stored.
    pub payload_type: u8,
    /// Payload type version.
    pub type_version: u8,
    /// Payload bytes (inside the encrypted DB — INV-1).
    pub body: Vec<u8>,
    /// Local clock at insert for an outgoing row, Unix seconds (1.1, L-D2);
    /// `None` for incoming rows and for rows stored before 1.1 (never
    /// back-filled).
    pub sent_at: Option<i64>,
    /// Local clock at insert for an incoming row, Unix seconds (1.1, L-D2);
    /// `None` for outgoing rows and for rows stored before 1.1.
    pub received_at: Option<i64>,
}

/// A conversation as the list renders it (1.1, L-D3/L-D4): the local-only
/// label (schema v4; `None` = unlabelled, the UI shows the hex form) and the
/// two times the list orders and annotates by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSummary {
    /// Conversation id.
    pub id: [u8; 16],
    /// Local-only label; never crosses the wire (INV-1: a contact name).
    pub label: Option<String>,
    /// Creation time, Unix seconds.
    pub created_at: i64,
    /// `max(created_at, max(sent_at, received_at))` over the conversation's
    /// message rows — equals `created_at` while no timestamped row exists.
    pub last_activity_at: i64,
}

/// Upper bound of a conversation label, in Unicode scalar values (1.1, L-D3).
pub const MAX_LABEL_SCALARS: usize = 64;

/// The 1.1 label rule (L-D3), applied before any write: `None` and the empty
/// string clear the label (`Ok(None)`); otherwise the label is trimmed and
/// must be non-blank, at most [`MAX_LABEL_SCALARS`] scalar values and free of
/// control characters. Violations are rejected, never truncated or repaired.
///
/// # Errors
///
/// Returns [`CoreError::InvalidLabel`] naming the rule the label broke.
pub fn normalize_label(label: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = label else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidLabel("blank after trimming"));
    }
    if trimmed.chars().count() > MAX_LABEL_SCALARS {
        return Err(CoreError::InvalidLabel(
            "more than MAX_LABEL_SCALARS scalar values",
        ));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(CoreError::InvalidLabel("control character"));
    }
    Ok(Some(trimmed.to_owned()))
}

/// A conversation's routing row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    /// Conversation id.
    pub id: [u8; 16],
    /// Peer's pairing address (derived from their identity key).
    pub peer_address: String,
    /// Peer's relay URL — where this side deposits to reach them (INV-5).
    pub relay_url: String,
    /// Peer's inbox on their relay (`None` until learned via pair-ack/update).
    pub mailbox_send: Option<String>,
    /// This side's inbox (on this device's relay) where the peer deposits.
    pub mailbox_recv: Option<String>,
    /// Optional TLS SPKI pin for the peer's relay (schema v2).
    pub relay_pin: Option<[u8; 32]>,
}

/// §10.7 derived-recovery state for a conversation (schema v3). `None`/0 fields
/// mean "not a v2 recovery-capable conversation" or "not yet established".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryRecord {
    /// 0 = offerer, 1 = responder (the derived-mailbox `role_label`); `None` for
    /// v1-paired conversations.
    pub role: Option<u8>,
    /// This side's 32-byte recovery-root contribution.
    pub own_contrib: Option<[u8; 32]>,
    /// The peer's 32-byte recovery-root contribution (once received).
    pub peer_contrib: Option<[u8; 32]>,
    /// `HMAC(A_contribution, B_contribution)` once both are known.
    pub root: Option<[u8; 32]>,
    /// This side's current recovery generation `g`.
    pub own_gen: u32,
    /// Last generation observed from a verified peer control frame.
    pub peer_gen: u32,
}

/// An open, keyed `SQLCipher` store.
pub struct Store {
    pub(crate) conn: Mutex<rusqlite::Connection>,
}

impl Store {
    /// Opens (creating if absent) the database at `path` with `key`, applies
    /// pending migrations, and verifies the key. A wrong key yields
    /// [`CoreError::BadDbKey`] — cleanly, with no partial state.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::BadDbKey`] when the key does not decrypt the
    /// database, and [`CoreError::Storage`] for any other open or migration
    /// failure.
    pub fn open(path: &Path, key: &DbKey) -> Result<Store> {
        let conn = rusqlite::Connection::open(path).map_err(sql_err)?;

        // SQLCipher raw-key syntax; hex string is wiped after use.
        let mut key_hex = hex::encode(key.as_bytes());
        let pragma = format!("PRAGMA key = \"x'{key_hex}'\";");
        let applied = conn.execute_batch(&pragma);
        key_hex.zeroize();
        drop(pragma);
        applied.map_err(sql_err)?;
        conn.execute_batch("PRAGMA cipher_memory_security = ON;")
            .map_err(sql_err)?;

        // First real read fails with NOTADB when the key is wrong.
        let probe: std::result::Result<i64, rusqlite::Error> =
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0));
        if probe.is_err() {
            return Err(CoreError::BadDbKey);
        }

        schema::migrate(&conn)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    /// Current schema version (max applied migration).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn schema_version(&self) -> Result<u32> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)
    }

    /// Creates a conversation with `peer_address`. `relay_url = None` fills
    /// the single default constant (INV-5). Returns the conversation id.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn create_conversation(
        &self,
        peer_address: &str,
        relay_url: Option<&str>,
    ) -> Result<[u8; 16]> {
        let id = random_id();
        let relay = relay_url.unwrap_or(crate::config::DEFAULT_RELAY_URL);
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO conversations (id, peer_address, relay_url, created_at)
             VALUES (?1, ?2, ?3, unixepoch())",
            rusqlite::params![id.as_slice(), peer_address, relay],
        )
        .map_err(sql_err)?;
        Ok(id)
    }

    /// The relay URL configured for a conversation (INV-5: per-conversation).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query fails
    /// — including when no row exists for the given id (`QueryReturnedNoRows`).
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn conversation_relay_url(&self, conversation_id: &[u8; 16]) -> Result<String> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT relay_url FROM conversations WHERE id = ?1",
            [conversation_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(sql_err)
    }

    /// Persists a message body for a conversation.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn save_message(
        &self,
        conversation_id: &[u8; 16],
        direction: Direction,
        frame: &InnerFrame,
    ) -> Result<[u8; 16]> {
        self.insert_message(conversation_id, direction, frame, 0)
            .map(|m| m.id)
    }

    /// Finds an existing conversation by peer address.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn conversation_by_peer(&self, peer_address: &str) -> Result<Option<[u8; 16]>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        match conn.query_row(
            "SELECT id FROM conversations WHERE peer_address = ?1",
            [peer_address],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(v) => Ok(Some(blob16(v))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(sql_err(e)),
        }
    }

    /// Reads a conversation's routing row.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn get_conversation(&self, id: &[u8; 16]) -> Result<Option<Conversation>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        match conn.query_row(
            "SELECT peer_address, relay_url, mailbox_send, mailbox_recv, relay_pin
             FROM conversations WHERE id = ?1",
            [id.as_slice()],
            |row| {
                Ok(Conversation {
                    id: *id,
                    peer_address: row.get(0)?,
                    relay_url: row.get(1)?,
                    mailbox_send: row.get(2)?,
                    mailbox_recv: row.get(3)?,
                    relay_pin: row.get::<_, Option<Vec<u8>>>(4)?.map(|v| blob32(&v)),
                })
            },
        ) {
            Ok(c) => Ok(Some(c)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(sql_err(e)),
        }
    }

    /// Lists conversation ids, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn list_conversation_ids(&self) -> Result<Vec<[u8; 16]>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn
            .prepare("SELECT id FROM conversations ORDER BY created_at DESC, rowid DESC")
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], |row| Ok(blob16(row.get::<_, Vec<u8>>(0)?)))
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    /// Lists conversations for the list screen (1.1, L-D4): ordered by
    /// `last_activity_at DESC, created_at DESC, rowid DESC`, each with its
    /// label and times. [`Self::list_conversation_ids`] is unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn list_conversation_summaries(&self) -> Result<Vec<ConversationSummary>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT c.id, c.label, c.created_at,
                        MAX(c.created_at,
                            COALESCE((SELECT MAX(m.sent_at) FROM messages m
                                       WHERE m.conversation_id = c.id), 0),
                            COALESCE((SELECT MAX(m.received_at) FROM messages m
                                       WHERE m.conversation_id = c.id), 0)) AS last_activity_at
                 FROM conversations c
                 ORDER BY last_activity_at DESC, c.created_at DESC, c.rowid DESC",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ConversationSummary {
                    id: blob16(row.get::<_, Vec<u8>>(0)?),
                    label: row.get(1)?,
                    created_at: row.get(2)?,
                    last_activity_at: row.get(3)?,
                })
            })
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }

    /// Sets or clears a conversation's local-only label (1.1, L-D3) after
    /// [`normalize_label`]. Touches no routing column.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidLabel`] when the label breaks the rule, or
    /// [`CoreError::Storage`] when the underlying `SQLCipher` query fails —
    /// including when no row exists for the given id.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn set_conversation_label(&self, id: &[u8; 16], label: Option<&str>) -> Result<()> {
        let label = normalize_label(label)?;
        let conn = self.conn.lock().expect("store mutex poisoned");
        let changed = conn
            .execute(
                "UPDATE conversations SET label = ?2 WHERE id = ?1",
                rusqlite::params![id.as_slice(), label],
            )
            .map_err(sql_err)?;
        if changed == 0 {
            return Err(CoreError::Storage("conversation not found".into()));
        }
        Ok(())
    }

    /// Reads a conversation's label (`None` = unlabelled).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails — including when no row exists for the given id.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn conversation_label(&self, id: &[u8; 16]) -> Result<Option<String>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT label FROM conversations WHERE id = ?1",
            [id.as_slice()],
            |row| row.get(0),
        )
        .map_err(sql_err)
    }

    /// Creates a conversation with explicit routing (mailboxes may be unknown
    /// until the peer replies). Returns the id.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn create_routed_conversation(
        &self,
        peer_address: &str,
        peer_relay: &str,
        mailbox_send: Option<&str>,
        mailbox_recv: &str,
    ) -> Result<[u8; 16]> {
        let id = random_id();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO conversations
               (id, peer_address, relay_url, mailbox_send, mailbox_recv, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, unixepoch())",
            rusqlite::params![
                id.as_slice(),
                peer_address,
                peer_relay,
                mailbox_send,
                mailbox_recv
            ],
        )
        .map_err(sql_err)?;
        Ok(id)
    }

    /// Updates where to send for a conversation (peer's relay + inbox), learned
    /// from a `pair-ack/2` or `mailbox-update/1`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn set_conversation_send(
        &self,
        id: &[u8; 16],
        relay: &str,
        mailbox_send: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE conversations SET relay_url = ?2, mailbox_send = ?3 WHERE id = ?1",
            rusqlite::params![id.as_slice(), relay, mailbox_send],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Overrides the peer relay URL for a conversation (INV-5).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn set_conversation_relay(&self, id: &[u8; 16], relay: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE conversations SET relay_url = ?2 WHERE id = ?1",
            rusqlite::params![id.as_slice(), relay],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Updates this side's receive inbox (used by §10.7 one-sided recovery).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn set_conversation_recv(&self, id: &[u8; 16], mailbox_recv: &str) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE conversations SET mailbox_recv = ?2 WHERE id = ?1",
            rusqlite::params![id.as_slice(), mailbox_recv],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Sets or clears the per-conversation TLS SPKI pin (schema v2).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn set_conversation_pin(&self, id: &[u8; 16], pin: Option<[u8; 32]>) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE conversations SET relay_pin = ?2 WHERE id = ?1",
            rusqlite::params![id.as_slice(), pin.map(|p| p.to_vec())],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Reads the per-conversation TLS SPKI pin.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query fails
    /// — including when no row exists for the given id (`QueryReturnedNoRows`).
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn conversation_pin(&self, id: &[u8; 16]) -> Result<Option<[u8; 32]>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT relay_pin FROM conversations WHERE id = ?1",
            [id.as_slice()],
            |row| Ok(row.get::<_, Option<Vec<u8>>>(0)?.map(|v| blob32(&v))),
        )
        .map_err(sql_err)
    }

    /// Reads the §10.7 derived-recovery state (schema v3). All fields are
    /// `None`/0 for a v1-paired conversation (re-pair-only).
    pub(crate) fn recovery_state(&self, id: &[u8; 16]) -> Result<Option<RecoveryRecord>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        match conn.query_row(
            "SELECT recovery_role, recovery_own_contrib, recovery_peer_contrib,
                    recovery_root, recovery_own_gen, recovery_peer_gen
             FROM conversations WHERE id = ?1",
            [id.as_slice()],
            |row| {
                Ok(RecoveryRecord {
                    // rusqlite's FromSql for u8/u32 is range-checked: an
                    // out-of-range column value becomes a conversion error
                    // on the existing rusqlite error channel (sql_err).
                    role: row.get::<_, Option<u8>>(0)?,
                    own_contrib: row.get::<_, Option<Vec<u8>>>(1)?.map(|v| blob32(&v)),
                    peer_contrib: row.get::<_, Option<Vec<u8>>>(2)?.map(|v| blob32(&v)),
                    root: row.get::<_, Option<Vec<u8>>>(3)?.map(|v| blob32(&v)),
                    own_gen: row.get::<_, u32>(4)?,
                    peer_gen: row.get::<_, u32>(5)?,
                })
            },
        ) {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(sql_err(e)),
        }
    }

    /// At pairing: records this side's role and its recovery-root contribution.
    pub(crate) fn set_recovery_pairing(
        &self,
        id: &[u8; 16],
        role: u8,
        own_contrib: &[u8; 32],
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE conversations
               SET recovery_role = ?2, recovery_own_contrib = ?3 WHERE id = ?1",
            rusqlite::params![id.as_slice(), i64::from(role), own_contrib.as_slice()],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// When the peer's contribution arrives: stores it and the derived root
    /// (`root = HMAC(A_contribution, B_contribution)`, computed by the caller).
    pub(crate) fn set_recovery_root(
        &self,
        id: &[u8; 16],
        peer_contrib: &[u8; 32],
        root: &[u8; 32],
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE conversations
               SET recovery_peer_contrib = ?2, recovery_root = ?3 WHERE id = ?1",
            rusqlite::params![id.as_slice(), peer_contrib.as_slice(), root.as_slice()],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Persists the current recovery generation state (own, last-known peer).
    pub(crate) fn set_recovery_generations(
        &self,
        id: &[u8; 16],
        own_gen: u32,
        peer_gen: u32,
    ) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE conversations
               SET recovery_own_gen = ?2, recovery_peer_gen = ?3 WHERE id = ?1",
            rusqlite::params![id.as_slice(), i64::from(own_gen), i64::from(peer_gen)],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Saves an outgoing message as `pending` (status 0). Returns its id.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    pub fn save_outgoing(
        &self,
        conversation_id: &[u8; 16],
        frame: &InnerFrame,
    ) -> Result<[u8; 16]> {
        self.insert_message(conversation_id, Direction::Outgoing, frame, 0)
            .map(|m| m.id)
    }

    /// Saves an incoming (already decrypted) message as `received` (status 2)
    /// and returns the row as stored — the receiver callback hands exactly
    /// this row to the UI (1.1: `received_at` is the local clock at insert).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    pub fn save_incoming(
        &self,
        conversation_id: &[u8; 16],
        frame: &InnerFrame,
    ) -> Result<StoredMessage> {
        self.insert_message(conversation_id, Direction::Incoming, frame, 2)
    }

    fn insert_message(
        &self,
        conversation_id: &[u8; 16],
        direction: Direction,
        frame: &InnerFrame,
        status: u8,
    ) -> Result<StoredMessage> {
        let id = random_id();
        // L-D2: the local clock, on the row's own side only.
        let now = unix_seconds_now();
        let (sent_at, received_at) = match direction {
            Direction::Outgoing => (Some(now), None),
            Direction::Incoming => (None, Some(now)),
        };
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO messages (id, conversation_id, direction, payload_type,
                                   type_version, body, status, sent_at, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                id.as_slice(),
                conversation_id.as_slice(),
                direction as u8,
                frame.payload_type as u8,
                frame.type_version,
                frame.payload,
                status,
                sent_at,
                received_at,
            ],
        )
        .map_err(sql_err)?;
        Ok(StoredMessage {
            id,
            conversation_id: *conversation_id,
            direction,
            payload_type: frame.payload_type as u8,
            type_version: frame.type_version,
            body: frame.payload.clone(),
            sent_at,
            received_at,
        })
    }

    /// Marks a message as sent (status 1).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn mark_message_sent(&self, message_id: &[u8; 16]) -> Result<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE messages SET status = 1 WHERE id = ?1",
            [message_id.as_slice()],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Pending outgoing chat frames for a conversation (for redelivery).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails, or [`CoreError::UnknownPayloadType`] when a stored payload-type
    /// byte is outside the registry.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn pending_chat(&self, conversation_id: &[u8; 16]) -> Result<Vec<([u8; 16], InnerFrame)>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, payload_type, type_version, body FROM messages
                 WHERE conversation_id = ?1 AND direction = 0 AND status = 0
                 ORDER BY rowid",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([conversation_id.as_slice()], |row| {
                Ok((
                    blob16(row.get::<_, Vec<u8>>(0)?),
                    row.get::<_, u8>(1)?,
                    row.get::<_, u8>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(sql_err)?;
        let mut out = Vec::new();
        for r in rows {
            let (id, pt, ver, body) = r.map_err(sql_err)?;
            out.push((
                id,
                InnerFrame {
                    payload_type: crate::envelope::PayloadType::try_from(pt)?,
                    type_version: ver,
                    payload: body,
                },
            ));
        }
        Ok(out)
    }

    /// Lists messages of a conversation in insertion order.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Storage`] when the underlying `SQLCipher` query
    /// fails.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned (a prior panic while holding it).
    pub fn list_messages(&self, conversation_id: &[u8; 16]) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, conversation_id, direction, payload_type, type_version, body,
                        sent_at, received_at
                 FROM messages WHERE conversation_id = ?1 ORDER BY rowid",
            )
            .map_err(sql_err)?;
        let rows = stmt
            .query_map([conversation_id.as_slice()], |row| {
                Ok(StoredMessage {
                    id: blob16(row.get::<_, Vec<u8>>(0)?),
                    conversation_id: blob16(row.get::<_, Vec<u8>>(1)?),
                    direction: if row.get::<_, u8>(2)? == 0 {
                        Direction::Outgoing
                    } else {
                        Direction::Incoming
                    },
                    payload_type: row.get(3)?,
                    type_version: row.get(4)?,
                    body: row.get(5)?,
                    sent_at: row.get(6)?,
                    received_at: row.get(7)?,
                })
            })
            .map_err(sql_err)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(sql_err)
    }
}

/// 16 random bytes from the OS CSPRNG (ids, not secrets).
pub(crate) fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut id)
        .expect("OS CSPRNG unavailable");
    id
}

/// Local wall clock in Unix seconds (1.1, L-D2): what `insert_message` writes
/// into `sent_at` / `received_at`. Saturates rather than panics on a clock
/// before the epoch or beyond `i64`.
fn unix_seconds_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn blob16(v: Vec<u8>) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = v.len().min(16);
    out[..n].copy_from_slice(&v[..n]);
    out
}

fn blob32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = v.len().min(32);
    out[..n].copy_from_slice(&v[..n]);
    out
}

#[cfg(test)]
mod v3_tests {
    use super::*;

    #[test]
    fn schema_v3_migrates_and_recovery_state_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("t.db"), &DbKey::generate()).expect("open");
        assert_eq!(
            store.schema_version().expect("version"),
            4,
            "schema migrates to v4 (v3 recovery state, v4 label)"
        );

        let conv = store
            .create_routed_conversation("peeraddr", "wss://relay/v1", None, "myinbox")
            .expect("create conversation");

        // A freshly created conversation is v1-style until recovery is set:
        // all recovery fields NULL / 0.
        assert_eq!(
            store.recovery_state(&conv).expect("read").expect("row"),
            RecoveryRecord {
                role: None,
                own_contrib: None,
                peer_contrib: None,
                root: None,
                own_gen: 0,
                peer_gen: 0,
            },
        );

        // Pairing: this side records its role (offerer) + its own contribution.
        let own = [0x11u8; 32];
        store
            .set_recovery_pairing(&conv, 0, &own)
            .expect("set pairing");
        // Peer contribution arrives → derived root persisted.
        let peer = [0x22u8; 32];
        let root = [0x33u8; 32];
        store
            .set_recovery_root(&conv, &peer, &root)
            .expect("set root");
        // Generation state advances.
        store
            .set_recovery_generations(&conv, 2, 1)
            .expect("set generations");

        assert_eq!(
            store.recovery_state(&conv).expect("read").expect("row"),
            RecoveryRecord {
                role: Some(0),
                own_contrib: Some(own),
                peer_contrib: Some(peer),
                root: Some(root),
                own_gen: 2,
                peer_gen: 1,
            },
        );
    }
}

#[cfg(test)]
mod v1_to_v3_migration_tests {
    use super::*;

    /// 18c: a POPULATED, genuine v1-schema database (v1 DDL with
    /// `schema_migrations` recording exactly version 1) opened through the
    /// production `Store::open` path migrates to v3 with every pre-existing
    /// row intact and the v3 columns present at their defaults. The earlier
    /// migration tests only ever ran the chain against an empty file.
    #[test]
    fn populated_v1_database_migrates_to_v3_preserving_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v1.db");
        let key = DbKey::generate();
        let conv_id: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).expect("index < 16"));
        let msg_id = [0xEEu8; 16];

        // Build the v1 database exactly as Phase 2 created it: a keyed
        // SQLCipher connection, the migration-mechanism table, the v1 DDL,
        // and the version-1 record — then populate one row per table.
        {
            let conn = rusqlite::Connection::open(&path).expect("open raw v1 db");
            let mut key_hex = hex::encode(key.as_bytes());
            let pragma = format!("PRAGMA key = \"x'{key_hex}'\";");
            conn.execute_batch(&pragma).expect("key the connection");
            key_hex.zeroize();
            conn.execute_batch(
                "CREATE TABLE schema_migrations (
                   version INTEGER PRIMARY KEY,
                   applied_at INTEGER NOT NULL
                 );",
            )
            .expect("migration-mechanism table");
            conn.execute_batch(schema::V1_DDL).expect("v1 ddl");
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (1, unixepoch())",
                [],
            )
            .expect("record version 1");

            conn.execute(
                "INSERT INTO local_identity
                   (id, address_name, registration_id, identity_keypair, created_at)
                 VALUES (1, 'addr-v1', 42, x'0102', unixepoch())",
                [],
            )
            .expect("local_identity row");
            conn.execute(
                "INSERT INTO sessions (address, device_id, record, updated_at)
                 VALUES ('peer-a', 1, x'AA', unixepoch())",
                [],
            )
            .expect("sessions row");
            conn.execute(
                "INSERT INTO identities (address, identity_key, trusted_at)
                 VALUES ('peer-a', x'BB', unixepoch())",
                [],
            )
            .expect("identities row");
            conn.execute(
                "INSERT INTO conversations
                   (id, peer_address, relay_url, mailbox_send, mailbox_recv, created_at)
                 VALUES (?1, 'peer-a', 'wss://r.example/v1', 'sendbox', 'recvbox', unixepoch())",
                [conv_id.as_slice()],
            )
            .expect("conversations row");
            conn.execute(
                "INSERT INTO messages
                   (id, conversation_id, direction, payload_type, type_version, body, status)
                 VALUES (?1, ?2, 1, 1, 1, x'686921', 2)",
                rusqlite::params![msg_id.as_slice(), conv_id.as_slice()],
            )
            .expect("messages row");

            // The pre-state is verifiably version 1 before Store::open runs.
            let v: u32 = conn
                .query_row(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                    [],
                    |row| row.get(0),
                )
                .expect("read version");
            assert_eq!(v, 1, "pre-state must be schema v1");
        }

        // Production open path: the v2, v3 and v4 migrations run here.
        let store = Store::open(&path, &key).expect("open migrated store");
        assert_eq!(store.schema_version().expect("version"), 4);

        // Every pre-existing row survives intact.
        assert_eq!(
            crate::identity::local_address(&store).expect("local address"),
            "addr-v1"
        );
        let convo = store
            .get_conversation(&conv_id)
            .expect("read conversation")
            .expect("conversation row survives");
        assert_eq!(convo.peer_address, "peer-a");
        assert_eq!(convo.relay_url, "wss://r.example/v1");
        assert_eq!(convo.mailbox_send.as_deref(), Some("sendbox"));
        assert_eq!(convo.mailbox_recv.as_deref(), Some("recvbox"));
        assert_eq!(convo.relay_pin, None, "v2 column defaults to NULL");
        assert_eq!(
            store.conversation_label(&conv_id).expect("label"),
            None,
            "v4 column defaults to NULL"
        );
        let messages = store.list_messages(&conv_id).expect("messages");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, msg_id);
        assert_eq!(messages[0].direction, Direction::Incoming);
        assert_eq!(messages[0].payload_type, 1);
        assert_eq!(messages[0].type_version, 1);
        assert_eq!(messages[0].body, b"hi!".to_vec());
        {
            let conn = store.conn.lock().expect("store mutex poisoned");
            let (regid, keypair): (u32, Vec<u8>) = conn
                .query_row(
                    "SELECT registration_id, identity_keypair FROM local_identity WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("local_identity survives");
            assert_eq!((regid, keypair), (42, vec![0x01, 0x02]));
            let session_record: Vec<u8> = conn
                .query_row(
                    "SELECT record FROM sessions WHERE address = 'peer-a' AND device_id = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("sessions row survives");
            assert_eq!(session_record, vec![0xAA]);
            let identity_key: Vec<u8> = conn
                .query_row(
                    "SELECT identity_key FROM identities WHERE address = 'peer-a'",
                    [],
                    |row| row.get(0),
                )
                .expect("identities row survives");
            assert_eq!(identity_key, vec![0xBB]);
        }

        // The v3 columns exist at their defaults for the pre-existing row.
        assert_eq!(
            store.recovery_state(&conv_id).expect("read").expect("row"),
            RecoveryRecord {
                role: None,
                own_contrib: None,
                peer_contrib: None,
                root: None,
                own_gen: 0,
                peer_gen: 0,
            },
        );
    }
}

#[cfg(test)]
mod v4_tests {
    use super::*;

    /// The v2 and v3 migration DDL exactly as `schema::migrate` applies it,
    /// restated here as fixture literals so the v3 pre-state is genuine and
    /// independent of the production migration code under test.
    const V2_ALTER: &str = "ALTER TABLE conversations ADD COLUMN relay_pin BLOB;";
    const V3_ALTER: &str = "ALTER TABLE conversations ADD COLUMN recovery_role INTEGER;
         ALTER TABLE conversations ADD COLUMN recovery_own_contrib BLOB;
         ALTER TABLE conversations ADD COLUMN recovery_peer_contrib BLOB;
         ALTER TABLE conversations ADD COLUMN recovery_root BLOB;
         ALTER TABLE conversations ADD COLUMN recovery_own_gen INTEGER NOT NULL DEFAULT 0;
         ALTER TABLE conversations ADD COLUMN recovery_peer_gen INTEGER NOT NULL DEFAULT 0;";

    fn fresh_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("t.db"), &DbKey::generate()).expect("open");
        (dir, store)
    }

    fn routed(store: &Store, peer: &str) -> [u8; 16] {
        store
            .create_routed_conversation(peer, "wss://relay/v1", Some("sendbox"), "myinbox")
            .expect("create conversation")
    }

    fn set_i64(store: &Store, sql: &str, id: &[u8; 16], value: i64) {
        let conn = store.conn.lock().expect("store mutex poisoned");
        let changed = conn
            .execute(sql, rusqlite::params![id.as_slice(), value])
            .expect("fixture update");
        assert_eq!(changed, 1, "fixture update must hit exactly one row");
    }

    fn unix_seconds_now() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after the epoch")
                .as_secs(),
        )
        .expect("fits i64")
    }

    /// L-D1 (the 18c precedent): a POPULATED, genuine v3-schema database
    /// opened through the production `Store::open` path migrates to v4 with
    /// every pre-existing row and recovery column intact and `label` NULL.
    #[test]
    fn migrate_v3_to_v4_preserves_rows_and_adds_null_label() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v3.db");
        let key = DbKey::generate();
        let conv_id = [0x3Cu8; 16];
        let msg_id = [0x4Du8; 16];
        let own = [0x11u8; 32];
        let peer = [0x22u8; 32];
        let root = [0x33u8; 32];

        {
            let conn = rusqlite::Connection::open(&path).expect("open raw v3 db");
            let mut key_hex = hex::encode(key.as_bytes());
            let pragma = format!("PRAGMA key = \"x'{key_hex}'\";");
            conn.execute_batch(&pragma).expect("key the connection");
            key_hex.zeroize();
            conn.execute_batch(
                "CREATE TABLE schema_migrations (
                   version INTEGER PRIMARY KEY,
                   applied_at INTEGER NOT NULL
                 );",
            )
            .expect("migration-mechanism table");
            conn.execute_batch(schema::V1_DDL).expect("v1 ddl");
            conn.execute_batch(V2_ALTER).expect("v2 alter");
            conn.execute_batch(V3_ALTER).expect("v3 alter");
            for v in 1..=3 {
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, unixepoch())",
                    [v],
                )
                .expect("record version");
            }
            conn.execute(
                "INSERT INTO local_identity
                   (id, address_name, registration_id, identity_keypair, created_at)
                 VALUES (1, 'addr-v3', 42, x'0102', unixepoch())",
                [],
            )
            .expect("local_identity row");
            conn.execute(
                "INSERT INTO conversations
                   (id, peer_address, relay_url, mailbox_send, mailbox_recv, created_at,
                    relay_pin, recovery_role, recovery_own_contrib, recovery_peer_contrib,
                    recovery_root, recovery_own_gen, recovery_peer_gen)
                 VALUES (?1, 'peer-a', 'wss://r.example/v1', 'sendbox', 'recvbox', 1700000000,
                         NULL, 0, ?2, ?3, ?4, 2, 1)",
                rusqlite::params![
                    conv_id.as_slice(),
                    own.as_slice(),
                    peer.as_slice(),
                    root.as_slice()
                ],
            )
            .expect("conversations row");
            conn.execute(
                "INSERT INTO messages
                   (id, conversation_id, direction, payload_type, type_version, body, status)
                 VALUES (?1, ?2, 1, 1, 1, x'686921', 2)",
                rusqlite::params![msg_id.as_slice(), conv_id.as_slice()],
            )
            .expect("messages row");
            let v: u32 = conn
                .query_row(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                    [],
                    |row| row.get(0),
                )
                .expect("read version");
            assert_eq!(v, 3, "pre-state must be schema v3");
            let has_label: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('conversations') WHERE name = 'label'",
                    [],
                    |row| row.get(0),
                )
                .expect("pragma_table_info");
            assert_eq!(has_label, 0, "pre-state has no label column");
        }

        // Production open path: only the v4 migration runs here.
        let store = Store::open(&path, &key).expect("open migrated store");
        assert_eq!(store.schema_version().expect("version"), 4);
        assert_eq!(
            crate::identity::local_address(&store).expect("local address"),
            "addr-v3"
        );
        let convo = store
            .get_conversation(&conv_id)
            .expect("read conversation")
            .expect("conversation row survives");
        assert_eq!(convo.peer_address, "peer-a");
        assert_eq!(convo.relay_url, "wss://r.example/v1");
        assert_eq!(convo.mailbox_send.as_deref(), Some("sendbox"));
        assert_eq!(convo.mailbox_recv.as_deref(), Some("recvbox"));
        assert_eq!(convo.relay_pin, None);
        assert_eq!(
            store.recovery_state(&conv_id).expect("read").expect("row"),
            RecoveryRecord {
                role: Some(0),
                own_contrib: Some(own),
                peer_contrib: Some(peer),
                root: Some(root),
                own_gen: 2,
                peer_gen: 1,
            },
            "v3 recovery columns survive the v4 migration intact"
        );
        assert_eq!(
            store.conversation_label(&conv_id).expect("read label"),
            None,
            "the new column reads NULL for a pre-existing row"
        );
        let messages = store.list_messages(&conv_id).expect("messages");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, msg_id);
        assert_eq!(messages[0].body, b"hi!".to_vec());
        assert_eq!(
            messages[0].sent_at, None,
            "pre-1.1 rows are never back-filled"
        );
        assert_eq!(
            messages[0].received_at, None,
            "pre-1.1 rows are never back-filled"
        );
        let summaries = store.list_conversation_summaries().expect("summaries");
        assert_eq!(
            summaries,
            vec![ConversationSummary {
                id: conv_id,
                label: None,
                created_at: 1_700_000_000,
                last_activity_at: 1_700_000_000,
            }],
            "an untimestamped history leaves last_activity_at = created_at"
        );
    }

    /// L-D3: set → read → clear, through both clearing forms, trimmed.
    #[test]
    fn label_set_get_clear_roundtrip() {
        let (_dir, store) = fresh_store();
        let conv = routed(&store, "peer-a");
        assert_eq!(store.conversation_label(&conv).expect("read"), None);

        store
            .set_conversation_label(&conv, Some("  Alice at work  "))
            .expect("set label");
        assert_eq!(
            store.conversation_label(&conv).expect("read").as_deref(),
            Some("Alice at work"),
            "the stored label is the trimmed text"
        );
        let summaries = store.list_conversation_summaries().expect("summaries");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].id, conv);
        assert_eq!(summaries[0].label.as_deref(), Some("Alice at work"));

        store
            .set_conversation_label(&conv, None)
            .expect("clear with None");
        assert_eq!(store.conversation_label(&conv).expect("read"), None);

        store
            .set_conversation_label(&conv, Some("Bob"))
            .expect("set again");
        store
            .set_conversation_label(&conv, Some(""))
            .expect("clear with the empty string");
        assert_eq!(
            store.conversation_label(&conv).expect("read"),
            None,
            "the empty string clears (L-D3: NULL/empty clears)"
        );

        let unknown = [0x99u8; 16];
        assert!(
            store.set_conversation_label(&unknown, Some("x")).is_err(),
            "labelling an unknown conversation is an error, not a silent no-op"
        );
    }

    /// L-D3: the rule rejects, never truncates — and a rejected write leaves
    /// the stored label untouched.
    #[test]
    fn label_rules_reject_blank_long_and_control() {
        assert_eq!(normalize_label(None).expect("None clears"), None);
        assert_eq!(normalize_label(Some("")).expect("empty clears"), None);
        assert_eq!(
            normalize_label(Some(" Team Ops "))
                .expect("trimmed")
                .as_deref(),
            Some("Team Ops")
        );
        let sixty_four = "é".repeat(MAX_LABEL_SCALARS);
        assert_eq!(
            normalize_label(Some(&sixty_four))
                .expect("64 scalar values are allowed (bytes do not count)")
                .as_deref(),
            Some(sixty_four.as_str())
        );
        for (label, why) in [
            ("   ", "blank after trimming"),
            ("\t\n", "whitespace-only"),
            (&"a".repeat(MAX_LABEL_SCALARS + 1), "65 scalar values"),
            ("ctrl\u{7}char", "a control character"),
            ("tab\tinside", "a tab (control)"),
            ("line\nbreak", "a line break (control)"),
            ("nul\0", "NUL"),
        ] {
            assert!(
                matches!(
                    normalize_label(Some(label)),
                    Err(CoreError::InvalidLabel(_))
                ),
                "{why} must be rejected as InvalidLabel"
            );
        }

        let (_dir, store) = fresh_store();
        let conv = routed(&store, "peer-a");
        store
            .set_conversation_label(&conv, Some("kept"))
            .expect("set label");
        assert!(matches!(
            store.set_conversation_label(&conv, Some("   ")),
            Err(CoreError::InvalidLabel(_))
        ));
        assert!(matches!(
            store.set_conversation_label(&conv, Some(&"x".repeat(MAX_LABEL_SCALARS + 1))),
            Err(CoreError::InvalidLabel(_))
        ));
        assert_eq!(
            store.conversation_label(&conv).expect("read").as_deref(),
            Some("kept"),
            "a rejected label leaves the stored one untouched"
        );
    }

    /// L-D2: the local clock is written at insert on the row's own side only.
    #[test]
    fn timestamps_written_at_insert() {
        let (_dir, store) = fresh_store();
        let conv = routed(&store, "peer-a");
        let before = unix_seconds_now();
        let out_id = store
            .save_outgoing(&conv, &InnerFrame::chat_v1("out"))
            .expect("save outgoing");
        let incoming = store
            .save_incoming(&conv, &InnerFrame::chat_v1("in"))
            .expect("save incoming");
        let after = unix_seconds_now();

        let messages = store.list_messages(&conv).expect("messages");
        assert_eq!(messages.len(), 2);
        let out = &messages[0];
        assert_eq!(out.id, out_id);
        assert_eq!(out.direction, Direction::Outgoing);
        let sent = out.sent_at.expect("outgoing rows carry sent_at");
        assert!(
            (before..=after).contains(&sent),
            "sent_at is the local clock at insert"
        );
        assert_eq!(out.received_at, None, "outgoing rows carry no received_at");

        let inc = &messages[1];
        assert_eq!(inc.id, incoming.id);
        assert_eq!(inc.direction, Direction::Incoming);
        let received = inc.received_at.expect("incoming rows carry received_at");
        assert!((before..=after).contains(&received));
        assert_eq!(inc.sent_at, None, "incoming rows carry no sent_at");
        assert_eq!(
            incoming, *inc,
            "save_incoming returns the row exactly as list_messages reads it back"
        );
    }

    /// L-D4: `last_activity_at = max(created_at, max(sent_at, received_at))`
    /// and the list orders by it; `list_conversation_ids` keeps its order.
    #[test]
    fn summaries_order_by_last_activity() {
        let (_dir, store) = fresh_store();
        let a = routed(&store, "peer-a");
        let b = routed(&store, "peer-b");
        let c = routed(&store, "peer-c");
        let backdate = "UPDATE conversations SET created_at = ?2 WHERE id = ?1";
        set_i64(&store, backdate, &a, 1_000);
        set_i64(&store, backdate, &b, 2_000);
        set_i64(&store, backdate, &c, 5_000);

        // A gets a message newer than B's creation; C's only message is older
        // than C itself (created_at wins).
        let a_msg = store
            .save_incoming(&a, &InnerFrame::chat_v1("hello"))
            .expect("save")
            .id;
        set_i64(
            &store,
            "UPDATE messages SET received_at = ?2 WHERE id = ?1",
            &a_msg,
            3_000,
        );
        let c_msg = store
            .save_outgoing(&c, &InnerFrame::chat_v1("old"))
            .expect("save");
        set_i64(
            &store,
            "UPDATE messages SET sent_at = ?2 WHERE id = ?1",
            &c_msg,
            100,
        );

        let summaries = store.list_conversation_summaries().expect("summaries");
        let order: Vec<[u8; 16]> = summaries.iter().map(|s| s.id).collect();
        assert_eq!(
            order,
            vec![c, a, b],
            "ordered by last activity, newest first"
        );
        let by_id = |id: &[u8; 16]| {
            summaries
                .iter()
                .find(|s| s.id == *id)
                .expect("present")
                .clone()
        };
        assert_eq!(by_id(&a).last_activity_at, 3_000, "A: the message is newer");
        assert_eq!(
            by_id(&b).last_activity_at,
            2_000,
            "B: no messages → created_at"
        );
        assert_eq!(
            by_id(&c).last_activity_at,
            5_000,
            "C: created_at beats an older message"
        );
        assert_eq!(by_id(&a).created_at, 1_000);

        assert_eq!(
            store.list_conversation_ids().expect("ids"),
            vec![c, b, a],
            "list_conversation_ids keeps the created_at order"
        );
    }

    /// L-D6: a label is a contact name. Setting one touches no routing or
    /// recovery column, and the label is absent from every frame the
    /// conversation would send afterwards — the pending frame and its
    /// padded encoding carry the chat text only.
    #[test]
    fn label_never_in_frame() {
        let (_dir, store) = fresh_store();
        let conv = routed(&store, "peer-a");
        store
            .set_recovery_pairing(&conv, 0, &[0x11u8; 32])
            .expect("recovery pairing");
        let routing_before = store.get_conversation(&conv).expect("read").expect("row");
        let recovery_before = store.recovery_state(&conv).expect("read").expect("row");

        let label = "titlan label sentinel core";
        store
            .set_conversation_label(&conv, Some(label))
            .expect("set label");
        assert_eq!(
            store.get_conversation(&conv).expect("read").expect("row"),
            routing_before,
            "the routing row is untouched by a label write"
        );
        assert_eq!(
            store.recovery_state(&conv).expect("read").expect("row"),
            recovery_before,
            "the recovery columns are untouched by a label write"
        );

        store
            .save_outgoing(&conv, &InnerFrame::chat_v1("hello after labelling"))
            .expect("queue a chat");
        let pending = store.pending_chat(&conv).expect("pending");
        assert_eq!(pending.len(), 1);
        let (_, frame) = &pending[0];
        assert_eq!(frame.payload, b"hello after labelling".to_vec());
        let encoded = frame
            .encode(&crate::config::PaddingProfile::default_profile())
            .expect("encode");
        for haystack in [frame.payload.as_slice(), encoded.as_slice()] {
            assert!(
                !contains(haystack, label.as_bytes()),
                "the label must not appear in the frame (INV-1: never on the wire)"
            );
        }
        assert!(
            contains(encoded.as_slice(), b"hello after labelling"),
            "positive control: the chat text is in the unencrypted inner frame"
        );
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
