// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Identity lifecycle (A1): device-generated keypair, no accounts. All key
//! material is produced by libsignal (`IdentityKeyPair`, prekey records);
//! this module only orchestrates and persists (INV-6).

use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol::{
    GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyRecord, PreKeyRecord,
    SignedPreKeyRecord, Timestamp, kem,
};
use rand::TryRngCore;

use crate::pairing::{self, BundleData};
use crate::storage::Store;
use crate::storage::schema::sql_err;
use crate::{CoreError, Result};

// MVP: one signed prekey, one (last-resort) kyber prekey, one one-time
// prekey, generated at initialization. Rotation lands post-MVP.
const SIGNED_PREKEY_ID: u32 = 1;
const KYBER_PREKEY_ID: u32 = 1;
const ONETIME_PREKEY_ID: u32 = 1;
/// MVP device id (multi-device linking is out of scope).
pub(crate) const DEVICE_ID: u32 = 1;

pub(crate) fn signal_err<E: Into<libsignal_protocol::SignalProtocolError>>(e: E) -> CoreError {
    match e.into() {
        libsignal_protocol::SignalProtocolError::DuplicatedMessage(..) => CoreError::Replay,
        other => CoreError::Signal(other.to_string()),
    }
}

fn now_timestamp() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis();
    Timestamp::from_epoch_millis(u64::try_from(millis).expect("epoch millis fit u64"))
}

/// Generates the local identity, registration id, and initial prekey set
/// (signed + kyber + one one-time prekey), persisting them in `store`.
/// Errors if an identity already exists.
pub fn initialize(store: &Store) -> Result<()> {
    if is_initialized(store)? {
        return Err(CoreError::Storage("identity already initialized".into()));
    }

    // OS CSPRNG, as required by libsignal's caller-supplied-RNG contract.
    let mut rng = rand::rngs::OsRng.unwrap_err();

    let identity = IdentityKeyPair::generate(&mut rng);
    // 14-bit non-zero registration id (Signal convention).
    let registration_id = loop {
        let candidate = rng.try_next_u32().expect("OS CSPRNG unavailable") & 0x3FFF;
        if candidate != 0 {
            break candidate;
        }
    };
    // Address = hex of the serialized identity public key. Deriving it from
    // the identity key (rather than a random id) lets a recipient of a
    // session-setup message compute the sender's address from the message's
    // embedded identity key — needed to decrypt a `pair-ack/1` arriving on a
    // pairing inbox whose sender is otherwise unknown (blind relay, sealed
    // sender). It is still an unlinkable pseudonym (a public key, no PII).
    let address_name = address_for_identity(identity.identity_key());

    // Signed EC prekey: keypair + signature over its public key, both from
    // libsignal primitives.
    let signed_keypair = KeyPair::generate(&mut rng);
    let signed_sig = identity
        .private_key()
        .calculate_signature(&signed_keypair.public_key.serialize(), &mut rng)
        .map_err(signal_err)?;
    let signed_record = SignedPreKeyRecord::new(
        SIGNED_PREKEY_ID.into(),
        now_timestamp(),
        &signed_keypair,
        &signed_sig,
    );

    // Post-quantum prekey (A2: PQXDH hybrid is mandatory). Kyber1024 per
    // Signal's deployed PQXDH suite.
    let kyber_record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        KYBER_PREKEY_ID.into(),
        identity.private_key(),
    )
    .map_err(signal_err)?;

    let onetime_keypair = KeyPair::generate(&mut rng);
    let onetime_record = PreKeyRecord::new(ONETIME_PREKEY_ID.into(), &onetime_keypair);

    let conn = store.conn.lock().expect("store mutex poisoned");
    let tx = conn.unchecked_transaction().map_err(sql_err)?;
    tx.execute(
        "INSERT INTO local_identity (id, address_name, registration_id, identity_keypair, created_at)
         VALUES (1, ?1, ?2, ?3, unixepoch())",
        rusqlite::params![address_name, registration_id, identity.serialize().to_vec()],
    )
    .map_err(sql_err)?;
    tx.execute(
        "INSERT INTO signed_prekeys (id, record) VALUES (?1, ?2)",
        rusqlite::params![
            SIGNED_PREKEY_ID,
            signed_record.serialize().map_err(signal_err)?
        ],
    )
    .map_err(sql_err)?;
    tx.execute(
        "INSERT INTO kyber_prekeys (id, record) VALUES (?1, ?2)",
        rusqlite::params![
            KYBER_PREKEY_ID,
            kyber_record.serialize().map_err(signal_err)?
        ],
    )
    .map_err(sql_err)?;
    tx.execute(
        "INSERT INTO prekeys (id, record) VALUES (?1, ?2)",
        rusqlite::params![
            ONETIME_PREKEY_ID,
            onetime_record.serialize().map_err(signal_err)?
        ],
    )
    .map_err(sql_err)?;
    tx.commit().map_err(sql_err)
}

/// Derives the pairing address (pseudonym) for an identity public key: the
/// hex of its serialized form. Deterministic, so a recipient can compute a
/// sender's address from a received session-setup message's identity key.
pub(crate) fn address_for_identity(identity_key: &libsignal_protocol::IdentityKey) -> String {
    hex::encode(identity_key.serialize())
}

/// `true` once [`initialize`] has completed for this store.
pub fn is_initialized(store: &Store) -> Result<bool> {
    let conn = store.conn.lock().expect("store mutex poisoned");
    let count: u32 = conn
        .query_row("SELECT count(*) FROM local_identity", [], |row| row.get(0))
        .map_err(sql_err)?;
    Ok(count > 0)
}

/// The local pairing address (stable pseudonym carried in exported bundles).
pub fn local_address(store: &Store) -> Result<String> {
    let conn = store.conn.lock().expect("store mutex poisoned");
    conn.query_row(
        "SELECT address_name FROM local_identity WHERE id = 1",
        [],
        |row| row.get(0),
    )
    .map_err(sql_err)
}

/// Serializes a pairing bundle (`proto/pairing.md`, A7) advertising the
/// long-lived identity/signed/kyber material plus the given one-time prekey
/// `(id, public)`. Shared by the offer path ([export_offer_bundle]) and the
/// responder `pair-ack/2` path ([export_prekey_bundle]).
fn serialize_bundle(store: &Store, onetime: (u32, Vec<u8>)) -> Result<Vec<u8>> {
    let address_name = local_address(store)?;
    let (registration_id, identity_bytes) = {
        let conn = store.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT registration_id, identity_keypair FROM local_identity WHERE id = 1",
            [],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .map_err(sql_err)?
    };
    let identity = IdentityKeyPair::try_from(identity_bytes.as_slice()).map_err(signal_err)?;

    let read_record = |sql: &str, id: u32| -> Result<Vec<u8>> {
        let conn = store.conn.lock().expect("store mutex poisoned");
        conn.query_row(sql, [id], |row| row.get(0)).map_err(sql_err)
    };

    let signed_record = SignedPreKeyRecord::deserialize(&read_record(
        "SELECT record FROM signed_prekeys WHERE id = ?1",
        SIGNED_PREKEY_ID,
    )?)
    .map_err(signal_err)?;
    let kyber_record = KyberPreKeyRecord::deserialize(&read_record(
        "SELECT record FROM kyber_prekeys WHERE id = ?1",
        KYBER_PREKEY_ID,
    )?)
    .map_err(signal_err)?;

    let data = BundleData {
        address_name,
        registration_id,
        device_id: DEVICE_ID,
        identity_key: identity.identity_key().serialize().to_vec(),
        signed_prekey_id: SIGNED_PREKEY_ID,
        signed_prekey_pub: signed_record
            .public_key()
            .map_err(signal_err)?
            .serialize()
            .to_vec(),
        signed_prekey_sig: signed_record.signature().map_err(signal_err)?,
        kyber_prekey_id: KYBER_PREKEY_ID,
        kyber_prekey_pub: kyber_record
            .public_key()
            .map_err(signal_err)?
            .serialize()
            .to_vec(),
        kyber_prekey_sig: kyber_record.signature().map_err(signal_err)?,
        onetime_prekey: Some(onetime),
    };
    Ok(pairing::serialize(&data))
}

/// Exports the bundle for a responder's `pair-ack/2` (A7). It advertises the
/// fixed init one-time prekey [ONETIME_PREKEY_ID]: the offerer never runs PQXDH
/// against the responder's bundle (it ratchets its inbox-handoff on the session
/// the responder's `pair-ack/2` already established), so this prekey is never
/// consumed and is safely reused across pair-acks.
pub fn export_prekey_bundle(store: &Store) -> Result<Vec<u8>> {
    let onetime_public = {
        let conn = store.conn.lock().expect("store mutex poisoned");
        let record: Vec<u8> = conn
            .query_row(
                "SELECT record FROM prekeys WHERE id = ?1",
                [ONETIME_PREKEY_ID],
                |row| row.get(0),
            )
            .map_err(sql_err)?;
        PreKeyRecord::deserialize(&record)
            .map_err(signal_err)?
            .public_key()
            .map_err(signal_err)?
            .serialize()
            .to_vec()
    };
    serialize_bundle(store, (ONETIME_PREKEY_ID, onetime_public))
}

/// Exports the bundle carried by a pairing OFFER (A7; `proto/pairing.md`).
/// Unlike the responder path, each offer mints and persists a FRESH one-time
/// prekey with a unique id, so it advertises its own prekey: when the offerer
/// later processes a responder's `pair-ack/2`, libsignal's `remove_pre_key`
/// deletes exactly that offer's prekey, leaving every other live offer — and
/// every future offer — its own. Without this the single fixed
/// [ONETIME_PREKEY_ID] is deleted on the first inbound pairing and a device can
/// be paired into only once per identity.
pub fn export_offer_bundle(store: &Store) -> Result<Vec<u8>> {
    let onetime = mint_offer_onetime_prekey(store)?;
    serialize_bundle(store, onetime)
}

/// Mints a fresh one-time prekey for a single offer through the same libsignal
/// types and `prekeys` insert path [initialize] uses (INV-6 — only the id
/// allocation and lifecycle differ), returning `(id, public-key bytes)`.
///
/// Id allocation is monotonic (`MAX(id) + 1`), never colliding with the fixed
/// responder key at id 1 nor with any still-unconsumed offer prekey — a random
/// id could hit an existing row and `ON CONFLICT`-overwrite a live offer's
/// secret. The `MAX(id)` read and the `INSERT` run under a single store-mutex
/// acquisition, so two concurrent offers observe distinct ids.
fn mint_offer_onetime_prekey(store: &Store) -> Result<(u32, Vec<u8>)> {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let keypair = KeyPair::generate(&mut rng);
    let conn = store.conn.lock().expect("store mutex poisoned");
    let id: u32 = conn
        .query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM prekeys", [], |row| {
            row.get(0)
        })
        .map_err(sql_err)?;
    // u32::MAX is the wire's ABSENT_ID sentinel (pairing.rs); unreachable in any
    // real device lifetime (it needs ~4 billion prekey rows) — rejected rather
    // than silently advertised as "no prekey".
    if id == u32::MAX {
        return Err(CoreError::Storage(
            "one-time prekey id space exhausted".into(),
        ));
    }
    let record = PreKeyRecord::new(id.into(), &keypair);
    conn.execute(
        "INSERT INTO prekeys (id, record) VALUES (?1, ?2)",
        rusqlite::params![id, record.serialize().map_err(signal_err)?],
    )
    .map_err(sql_err)?;
    record
        .public_key()
        .map_err(signal_err)
        .map(|k| (id, k.serialize().to_vec()))
}
