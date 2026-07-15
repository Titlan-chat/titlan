// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Session establishment and message encrypt/decrypt (A2). Every
//! cryptographic operation in this module is a libsignal call — X3DH/PQXDH
//! via `process_prekey_bundle`, Double Ratchet via `message_encrypt` /
//! `message_decrypt` (INV-6). This module owns only orchestration: envelope
//! framing outside, inner-frame padding inside the encryption boundary.

use std::time::SystemTime;

use futures::executor::block_on;
use libsignal_protocol::{
    CiphertextMessage, DeviceId, IdentityKey, PreKeyBundle, PreKeySignalMessage, ProtocolAddress,
    PublicKey, SignalMessage, kem, message_decrypt, message_encrypt, process_prekey_bundle,
};
use rand::TryRngCore;

use crate::config::PaddingProfile;
use crate::envelope::{Envelope, EnvelopeKind, InnerFrame};
use crate::identity::{DEVICE_ID, signal_err};
use crate::storage::Store;
use crate::storage::signal_stores::{
    DbIdentityStore, DbKyberPreKeyStore, DbPreKeyStore, DbSessionStore, DbSignedPreKeyStore,
};
use crate::{CoreError, Result, pairing};

fn device_id(raw: u32) -> Result<DeviceId> {
    u8::try_from(raw)
        .ok()
        .and_then(|v| DeviceId::try_from(v).ok())
        .ok_or(CoreError::Malformed("invalid device id"))
}

fn address(name: &str, device: u32) -> Result<ProtocolAddress> {
    Ok(ProtocolAddress::new(name.to_owned(), device_id(device)?))
}

fn local_protocol_address(store: &Store) -> Result<ProtocolAddress> {
    address(&crate::identity::local_address(store)?, DEVICE_ID)
}

/// Processes a peer's exported pre-key bundle (from QR pairing, A7) and
/// establishes an outgoing PQXDH session. Returns the peer address parsed
/// from the bundle, after recording it as a TOFU identity.
pub fn establish_session(store: &Store, bundle: &[u8]) -> Result<String> {
    let data = pairing::parse(bundle)?;

    let identity_key = IdentityKey::decode(&data.identity_key).map_err(signal_err)?;
    let onetime = data
        .onetime_prekey
        .as_ref()
        .map(|(id, key)| {
            PublicKey::deserialize(key)
                .map(|k| ((*id).into(), k))
                .map_err(signal_err)
        })
        .transpose()?;
    let prekey_bundle = PreKeyBundle::new(
        data.registration_id,
        device_id(data.device_id)?,
        onetime,
        data.signed_prekey_id.into(),
        PublicKey::deserialize(&data.signed_prekey_pub).map_err(signal_err)?,
        data.signed_prekey_sig.clone(),
        data.kyber_prekey_id.into(),
        kem::PublicKey::deserialize(&data.kyber_prekey_pub).map_err(signal_err)?,
        data.kyber_prekey_sig.clone(),
        identity_key,
    )
    .map_err(signal_err)?;

    let remote = address(&data.address_name, data.device_id)?;
    let local = local_protocol_address(store)?;
    let mut rng = rand::rngs::OsRng.unwrap_err();

    block_on(process_prekey_bundle(
        &remote,
        &local,
        &mut DbSessionStore(store),
        &mut DbIdentityStore(store),
        &prekey_bundle,
        SystemTime::now(),
        &mut rng,
    ))
    .map_err(signal_err)?;

    Ok(data.address_name)
}

/// Encrypts `frame` for `peer`: pads to bucket (pre-crypto oversize check),
/// ratchet-encrypts, wraps in the outer envelope. Returns full wire bytes.
pub fn encrypt_message(
    store: &Store,
    peer: &str,
    frame: &InnerFrame,
    profile: &PaddingProfile,
) -> Result<Vec<u8>> {
    // Padding/oversize handling happens BEFORE any cryptographic call.
    let plaintext = frame.encode(profile)?;

    let remote = address(peer, DEVICE_ID)?;
    let local = local_protocol_address(store)?;
    let mut rng = rand::rngs::OsRng.unwrap_err();

    let message = block_on(message_encrypt(
        &plaintext,
        &remote,
        &local,
        &mut DbSessionStore(store),
        &mut DbIdentityStore(store),
        SystemTime::now(),
        &mut rng,
    ))
    .map_err(signal_err)?;

    let kind = match &message {
        CiphertextMessage::PreKeySignalMessage(_) => EnvelopeKind::SessionSetup,
        CiphertextMessage::SignalMessage(_) => EnvelopeKind::Ratchet,
        other => {
            return Err(CoreError::Signal(format!(
                "unexpected ciphertext message type {:?}",
                other.message_type()
            )));
        }
    };
    Ok(Envelope {
        kind,
        ciphertext: message.serialize().to_vec(),
    }
    .encode())
}

/// Parses the outer envelope, ratchet-decrypts, validates bucket/padding,
/// and returns the typed inner frame. Duplicate delivery yields
/// [`CoreError::Replay`].
pub fn decrypt_message(
    store: &Store,
    peer: &str,
    wire: &[u8],
    profile: &PaddingProfile,
) -> Result<InnerFrame> {
    let envelope = Envelope::parse(wire)?;
    let ciphertext = match envelope.kind {
        EnvelopeKind::SessionSetup => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(envelope.ciphertext.as_slice()).map_err(signal_err)?,
        ),
        EnvelopeKind::Ratchet => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(envelope.ciphertext.as_slice()).map_err(signal_err)?,
        ),
    };

    let remote = address(peer, DEVICE_ID)?;
    let local = local_protocol_address(store)?;
    let mut rng = rand::rngs::OsRng.unwrap_err();

    let plaintext = block_on(message_decrypt(
        &ciphertext,
        &remote,
        &local,
        &mut DbSessionStore(store),
        &mut DbIdentityStore(store),
        &mut DbPreKeyStore(store),
        &DbSignedPreKeyStore(store),
        &mut DbKyberPreKeyStore(store),
        &mut rng,
    ))
    .map_err(signal_err)?;

    InnerFrame::parse(&plaintext, profile)
}

/// Peeks the envelope kind without decrypting.
pub fn envelope_kind(wire: &[u8]) -> Result<EnvelopeKind> {
    Ok(Envelope::parse(wire)?.kind)
}

/// Decrypts a session-setup message whose sender is not yet known — a message
/// arriving on a pairing inbox (blind relay + sealed sender leave no sender
/// hint). The sender's address is derived from the identity key embedded in
/// the `PreKeySignalMessage`; the session is established and stored under it.
/// Returns `(sender_address, frame)`.
pub fn decrypt_setup_from_unknown(
    store: &Store,
    wire: &[u8],
    profile: &PaddingProfile,
) -> Result<(String, InnerFrame)> {
    let envelope = Envelope::parse(wire)?;
    if envelope.kind != EnvelopeKind::SessionSetup {
        return Err(CoreError::Malformed(
            "expected a session-setup message on a pairing inbox",
        ));
    }
    let msg = PreKeySignalMessage::try_from(envelope.ciphertext.as_slice()).map_err(signal_err)?;
    let sender = crate::identity::address_for_identity(msg.identity_key());
    let frame = decrypt_message(store, &sender, wire, profile)?;
    Ok((sender, frame))
}
