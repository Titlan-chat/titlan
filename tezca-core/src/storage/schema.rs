// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Schema migrations. Each migration runs inside a transaction and is
//! recorded in `schema_migrations` (§8: storage migration tests).

use crate::{CoreError, Result};

const V1_DDL: &str = "
CREATE TABLE local_identity (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  address_name TEXT NOT NULL,
  registration_id INTEGER NOT NULL,
  identity_keypair BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE sessions (
  address TEXT NOT NULL,
  device_id INTEGER NOT NULL,
  record BLOB NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (address, device_id)
);
CREATE TABLE identities (
  address TEXT PRIMARY KEY,
  identity_key BLOB NOT NULL,
  trusted_at INTEGER NOT NULL
);
CREATE TABLE prekeys (
  id INTEGER PRIMARY KEY,
  record BLOB NOT NULL
);
CREATE TABLE signed_prekeys (
  id INTEGER PRIMARY KEY,
  record BLOB NOT NULL
);
CREATE TABLE kyber_prekeys (
  id INTEGER PRIMARY KEY,
  record BLOB NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE conversations (
  id BLOB PRIMARY KEY,
  peer_address TEXT NOT NULL,
  relay_url TEXT NOT NULL,
  mailbox_send BLOB,
  mailbox_recv BLOB,
  padding_profile TEXT NOT NULL DEFAULT 'default',
  created_at INTEGER NOT NULL
);
CREATE TABLE messages (
  id BLOB PRIMARY KEY,
  conversation_id BLOB NOT NULL REFERENCES conversations(id),
  direction INTEGER NOT NULL,
  payload_type INTEGER NOT NULL,
  type_version INTEGER NOT NULL,
  body BLOB NOT NULL,
  sent_at INTEGER,
  received_at INTEGER,
  status INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_messages_conversation ON messages(conversation_id);
";

/// Applies all pending migrations to an open, keyed connection.
pub(crate) fn migrate(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
           version INTEGER PRIMARY KEY,
           applied_at INTEGER NOT NULL
         );",
    )
    .map_err(sql_err)?;

    let current: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(sql_err)?;

    if current < 1 {
        let tx = conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute_batch(V1_DDL).map_err(sql_err)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (1, unixepoch())",
            [],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
    }

    if current < 2 {
        // v2 (Phase 4a): per-conversation TLS SPKI pin (cert pinning is
        // optional-but-designed; NULL = use platform validation).
        let tx = conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute_batch("ALTER TABLE conversations ADD COLUMN relay_pin BLOB;")
            .map_err(sql_err)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (2, unixepoch())",
            [],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
    }

    if current < 3 {
        // v3 (Phase 4b-2): §10.7 derived-recovery state. All columns are
        // NULL/0 for v1-paired conversations (which stay re-pair-only —
        // no pairing secret, no recovery root; proto/pairing.md). recovery_role
        // is 0=offerer / 1=responder (the derived-mailbox role_label);
        // recovery_root = HMAC(A_contribution, B_contribution) once both are
        // known; own/peer contributions are kept so the root can be computed
        // when the second contribution arrives.
        let tx = conn.unchecked_transaction().map_err(sql_err)?;
        tx.execute_batch(
            "ALTER TABLE conversations ADD COLUMN recovery_role INTEGER;
             ALTER TABLE conversations ADD COLUMN recovery_own_contrib BLOB;
             ALTER TABLE conversations ADD COLUMN recovery_peer_contrib BLOB;
             ALTER TABLE conversations ADD COLUMN recovery_root BLOB;
             ALTER TABLE conversations ADD COLUMN recovery_own_gen INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE conversations ADD COLUMN recovery_peer_gen INTEGER NOT NULL DEFAULT 0;",
        )
        .map_err(sql_err)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (3, unixepoch())",
            [],
        )
        .map_err(sql_err)?;
        tx.commit().map_err(sql_err)?;
    }
    Ok(())
}

pub(crate) fn sql_err(e: rusqlite::Error) -> CoreError {
    CoreError::Storage(e.to_string())
}
