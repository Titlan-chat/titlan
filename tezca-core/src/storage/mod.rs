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

/// A 32-byte SQLCipher database key. Zeroized on drop.
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
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OS CSPRNG unavailable");
        Self(bytes)
    }

    /// Wraps existing key bytes (e.g. unwrapped by Android Keystore).
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
}

/// An open, keyed SQLCipher store.
pub struct Store {
    pub(crate) conn: Mutex<rusqlite::Connection>,
}

impl Store {
    /// Opens (creating if absent) the database at `path` with `key`, applies
    /// pending migrations, and verifies the key. A wrong key yields
    /// [`CoreError::BadDbKey`] — cleanly, with no partial state.
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
    pub fn save_message(
        &self,
        conversation_id: &[u8; 16],
        direction: Direction,
        frame: &InnerFrame,
    ) -> Result<[u8; 16]> {
        let id = random_id();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO messages (id, conversation_id, direction, payload_type,
                                   type_version, body, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            rusqlite::params![
                id.as_slice(),
                conversation_id.as_slice(),
                direction as u8,
                frame.payload_type as u8,
                frame.type_version,
                frame.payload,
            ],
        )
        .map_err(sql_err)?;
        Ok(id)
    }

    /// Lists messages of a conversation in insertion order.
    pub fn list_messages(&self, conversation_id: &[u8; 16]) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT id, conversation_id, direction, payload_type, type_version, body
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

fn blob16(v: Vec<u8>) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = v.len().min(16);
    out[..n].copy_from_slice(&v[..n]);
    out
}
