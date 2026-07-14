// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Implementations of libsignal's five store traits backed by the SQLCipher
//! database. Records are stored as the opaque serialized blobs libsignal
//! hands us — no cryptographic material is ever constructed or interpreted
//! here (INV-6).

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    ProtocolAddress, PublicKey, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};

use crate::storage::Store;

type SignalResult<T> = Result<T, SignalProtocolError>;

fn db_err(e: rusqlite::Error) -> SignalProtocolError {
    SignalProtocolError::InvalidState("sqlcipher store", e.to_string())
}

impl Store {
    fn blob(&self, sql: &str, id: u32) -> SignalResult<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        match conn.query_row(sql, [id], |row| row.get::<_, Vec<u8>>(0)) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
        }
    }

    fn put_blob(&self, sql: &str, id: u32, record: &[u8]) -> SignalResult<()> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.execute(sql, rusqlite::params![id, record])
            .map(|_| ())
            .map_err(db_err)
    }
}

/// SQLCipher-backed [`SessionStore`].
pub(crate) struct DbSessionStore<'a>(pub &'a Store);
/// SQLCipher-backed [`IdentityKeyStore`] (TOFU semantics per pairing, A7).
pub(crate) struct DbIdentityStore<'a>(pub &'a Store);
/// SQLCipher-backed [`PreKeyStore`].
pub(crate) struct DbPreKeyStore<'a>(pub &'a Store);
/// SQLCipher-backed [`SignedPreKeyStore`].
pub(crate) struct DbSignedPreKeyStore<'a>(pub &'a Store);
/// SQLCipher-backed [`KyberPreKeyStore`].
pub(crate) struct DbKyberPreKeyStore<'a>(pub &'a Store);

#[async_trait(?Send)]
impl SessionStore for DbSessionStore<'_> {
    async fn load_session(&self, address: &ProtocolAddress) -> SignalResult<Option<SessionRecord>> {
        let conn = self.0.conn.lock().expect("store mutex poisoned");
        let row = conn.query_row(
            "SELECT record FROM sessions WHERE address = ?1 AND device_id = ?2",
            rusqlite::params![address.name(), u32::from(address.device_id())],
            |row| row.get::<_, Vec<u8>>(0),
        );
        match row {
            Ok(bytes) => Ok(Some(SessionRecord::deserialize(&bytes)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> SignalResult<()> {
        let conn = self.0.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO sessions (address, device_id, record, updated_at)
             VALUES (?1, ?2, ?3, unixepoch())
             ON CONFLICT (address, device_id) DO UPDATE
             SET record = excluded.record, updated_at = excluded.updated_at",
            rusqlite::params![
                address.name(),
                u32::from(address.device_id()),
                record.serialize()?
            ],
        )
        .map(|_| ())
        .map_err(db_err)
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for DbIdentityStore<'_> {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        let bytes = self
            .0
            .blob(
                "SELECT identity_keypair FROM local_identity WHERE id = ?1",
                1,
            )?
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("identity", "not initialized".into())
            })?;
        IdentityKeyPair::try_from(bytes.as_slice())
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        let conn = self.0.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT registration_id FROM local_identity WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(db_err)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        let existing = {
            let conn = self.0.conn.lock().expect("store mutex poisoned");
            match conn.query_row(
                "SELECT identity_key FROM identities WHERE address = ?1",
                [address.name()],
                |row| row.get::<_, Vec<u8>>(0),
            ) {
                Ok(v) => Some(v),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(db_err(e)),
            }
        };
        let serialized = identity.serialize().to_vec();
        let change = match &existing {
            Some(known) if known != &serialized => IdentityChange::ReplacedExisting,
            _ => IdentityChange::NewOrUnchanged,
        };
        let conn = self.0.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "INSERT INTO identities (address, identity_key, trusted_at)
             VALUES (?1, ?2, unixepoch())
             ON CONFLICT (address) DO UPDATE
             SET identity_key = excluded.identity_key, trusted_at = excluded.trusted_at",
            rusqlite::params![address.name(), serialized],
        )
        .map_err(db_err)?;
        Ok(change)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> SignalResult<bool> {
        let conn = self.0.conn.lock().expect("store mutex poisoned");
        let existing = match conn.query_row(
            "SELECT identity_key FROM identities WHERE address = ?1",
            [address.name()],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(db_err(e)),
        };
        // TOFU (A7): first contact is trusted; afterwards the key must match.
        Ok(match existing {
            None => true,
            Some(known) => known == identity.serialize().to_vec(),
        })
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SignalResult<Option<IdentityKey>> {
        let conn = self.0.conn.lock().expect("store mutex poisoned");
        match conn.query_row(
            "SELECT identity_key FROM identities WHERE address = ?1",
            [address.name()],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(bytes) => Ok(Some(IdentityKey::decode(&bytes)?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
        }
    }
}

#[async_trait(?Send)]
impl PreKeyStore for DbPreKeyStore<'_> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> SignalResult<PreKeyRecord> {
        let bytes = self
            .0
            .blob("SELECT record FROM prekeys WHERE id = ?1", prekey_id.into())?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(&bytes)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> SignalResult<()> {
        self.0.put_blob(
            "INSERT INTO prekeys (id, record) VALUES (?1, ?2)
             ON CONFLICT (id) DO UPDATE SET record = excluded.record",
            prekey_id.into(),
            &record.serialize()?,
        )
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> SignalResult<()> {
        let conn = self.0.conn.lock().expect("store mutex poisoned");
        conn.execute("DELETE FROM prekeys WHERE id = ?1", [u32::from(prekey_id)])
            .map(|_| ())
            .map_err(db_err)
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for DbSignedPreKeyStore<'_> {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> SignalResult<SignedPreKeyRecord> {
        let bytes = self
            .0
            .blob(
                "SELECT record FROM signed_prekeys WHERE id = ?1",
                signed_prekey_id.into(),
            )?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> SignalResult<()> {
        self.0.put_blob(
            "INSERT INTO signed_prekeys (id, record) VALUES (?1, ?2)
             ON CONFLICT (id) DO UPDATE SET record = excluded.record",
            signed_prekey_id.into(),
            &record.serialize()?,
        )
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for DbKyberPreKeyStore<'_> {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> SignalResult<KyberPreKeyRecord> {
        let bytes = self
            .0
            .blob(
                "SELECT record FROM kyber_prekeys WHERE id = ?1",
                kyber_prekey_id.into(),
            )?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        KyberPreKeyRecord::deserialize(&bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> SignalResult<()> {
        self.0.put_blob(
            "INSERT INTO kyber_prekeys (id, record) VALUES (?1, ?2)
             ON CONFLICT (id) DO UPDATE SET record = excluded.record",
            kyber_prekey_id.into(),
            &record.serialize()?,
        )
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> SignalResult<()> {
        // MVP treats the single kyber prekey as last-resort: mark, don't
        // delete. Replay of a setup message is still rejected by the ratchet
        // layer (DuplicatedMessage); rotation lands post-MVP.
        let conn = self.0.conn.lock().expect("store mutex poisoned");
        conn.execute(
            "UPDATE kyber_prekeys SET used = 1 WHERE id = ?1",
            [u32::from(kyber_prekey_id)],
        )
        .map(|_| ())
        .map_err(db_err)
    }
}
