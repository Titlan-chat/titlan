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

    /// Finds an existing conversation by peer address.
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

    /// Creates a conversation with explicit routing (mailboxes may be unknown
    /// until the peer replies). Returns the id.
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
    /// from a `pair-ack/1` or `mailbox-update/1`.
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
    pub fn conversation_pin(&self, id: &[u8; 16]) -> Result<Option<[u8; 32]>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT relay_pin FROM conversations WHERE id = ?1",
            [id.as_slice()],
            |row| Ok(row.get::<_, Option<Vec<u8>>>(0)?.map(|v| blob32(&v))),
        )
        .map_err(sql_err)
    }

    /// Saves an outgoing message as `pending` (status 0). Returns its id.
    pub fn save_outgoing(
        &self,
        conversation_id: &[u8; 16],
        frame: &InnerFrame,
    ) -> Result<[u8; 16]> {
        self.insert_message(conversation_id, Direction::Outgoing, frame, 0)
    }

    /// Saves an incoming (already decrypted) message as `received` (status 2).
    pub fn save_incoming(
        &self,
        conversation_id: &[u8; 16],
        frame: &InnerFrame,
    ) -> Result<[u8; 16]> {
        self.insert_message(conversation_id, Direction::Incoming, frame, 2)
    }

    fn insert_message(
        &self,
        conversation_id: &[u8; 16],
        direction: Direction,
        frame: &InnerFrame,
        status: u8,
    ) -> Result<[u8; 16]> {
        let id = random_id();
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO messages (id, conversation_id, direction, payload_type,
                                   type_version, body, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                id.as_slice(),
                conversation_id.as_slice(),
                direction as u8,
                frame.payload_type as u8,
                frame.type_version,
                frame.payload,
                status,
            ],
        )
        .map_err(sql_err)?;
        Ok(id)
    }

    /// Marks a message as sent (status 1).
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

fn blob32(v: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = v.len().min(32);
    out[..n].copy_from_slice(&v[..n]);
    out
}
