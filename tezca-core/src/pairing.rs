// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Pairing bundle framing per `proto/pairing.md` (v1). Pure serialization —
//! all key material inside is produced and validated by libsignal (INV-6).

use crate::{CoreError, Result};

pub(crate) const FORMAT_VERSION: u8 = 1;
const ABSENT_ID: u32 = 0xFFFF_FFFF;

/// Decoded pairing bundle fields (bytes are libsignal-serialized keys).
pub(crate) struct BundleData {
    pub address_name: String,
    pub registration_id: u32,
    pub device_id: u32,
    pub identity_key: Vec<u8>,
    pub signed_prekey_id: u32,
    pub signed_prekey_pub: Vec<u8>,
    pub signed_prekey_sig: Vec<u8>,
    pub kyber_prekey_id: u32,
    pub kyber_prekey_pub: Vec<u8>,
    pub kyber_prekey_sig: Vec<u8>,
    pub onetime_prekey: Option<(u32, Vec<u8>)>,
}

pub(crate) fn serialize(data: &BundleData) -> Vec<u8> {
    let mut out = Vec::with_capacity(2048);
    out.push(FORMAT_VERSION);
    put_bytes(&mut out, data.address_name.as_bytes());
    out.extend_from_slice(&data.registration_id.to_be_bytes());
    out.extend_from_slice(&data.device_id.to_be_bytes());
    put_bytes(&mut out, &data.identity_key);
    out.extend_from_slice(&data.signed_prekey_id.to_be_bytes());
    put_bytes(&mut out, &data.signed_prekey_pub);
    put_bytes(&mut out, &data.signed_prekey_sig);
    out.extend_from_slice(&data.kyber_prekey_id.to_be_bytes());
    put_bytes(&mut out, &data.kyber_prekey_pub);
    put_bytes(&mut out, &data.kyber_prekey_sig);
    match &data.onetime_prekey {
        Some((id, key)) => {
            out.extend_from_slice(&id.to_be_bytes());
            put_bytes(&mut out, key);
        }
        None => {
            out.extend_from_slice(&ABSENT_ID.to_be_bytes());
            put_bytes(&mut out, &[]);
        }
    }
    out
}

pub(crate) fn parse(bytes: &[u8]) -> Result<BundleData> {
    let mut cursor = Cursor { bytes, pos: 0 };
    let version = cursor.u8()?;
    if version != FORMAT_VERSION {
        return Err(CoreError::Malformed("unknown pairing bundle version"));
    }
    let address_name = String::from_utf8(cursor.bytes_field()?.to_vec())
        .map_err(|_| CoreError::Malformed("bundle address is not UTF-8"))?;
    let registration_id = cursor.u32()?;
    let device_id = cursor.u32()?;
    let identity_key = cursor.bytes_field()?.to_vec();
    let signed_prekey_id = cursor.u32()?;
    let signed_prekey_pub = cursor.bytes_field()?.to_vec();
    let signed_prekey_sig = cursor.bytes_field()?.to_vec();
    let kyber_prekey_id = cursor.u32()?;
    let kyber_prekey_pub = cursor.bytes_field()?.to_vec();
    let kyber_prekey_sig = cursor.bytes_field()?.to_vec();
    if kyber_prekey_pub.is_empty() {
        // A2: PQXDH is mandatory; a classical-only bundle is invalid.
        return Err(CoreError::Malformed("bundle lacks post-quantum prekey"));
    }
    let onetime_id = cursor.u32()?;
    let onetime_pub = cursor.bytes_field()?.to_vec();
    if cursor.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in pairing bundle"));
    }
    let onetime_prekey = if onetime_id == ABSENT_ID {
        None
    } else {
        Some((onetime_id, onetime_pub))
    };
    Ok(BundleData {
        address_name,
        registration_id,
        device_id,
        identity_key,
        signed_prekey_id,
        signed_prekey_pub,
        signed_prekey_sig,
        kyber_prekey_id,
        kyber_prekey_pub,
        kyber_prekey_sig,
        onetime_prekey,
    })
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("bundle field exceeds u16");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

const PAYLOAD_VERSION: u8 = 1;
const CONTROL_VERSION: u8 = 1;
const MAILBOX_ID_LEN: usize = 43;

/// Reply coordinates carried by `pair-ack/1` (scanner → displayer). The
/// scanner's address is derived from the setup message's identity key, so the
/// bundled `address_name` field is parsed for format-completeness but the
/// derived value is authoritative.
pub(crate) struct ReplyCoords {
    pub relay_url: String,
    pub inbox_id: String,
}

/// Encodes the QR/link pairing payload: version + bundle + relay + inbox
/// (`proto/pairing.md` §Pairing payload).
pub(crate) fn encode_pairing_payload(bundle: &[u8], relay_url: &str, inbox_id: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(bundle.len() + relay_url.len() + 64);
    out.push(PAYLOAD_VERSION);
    put_bytes(&mut out, bundle);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(inbox_id.as_bytes()); // fixed 43 bytes
    out
}

/// Parses the pairing payload. Returns (bundle bytes, relay url, inbox id).
pub(crate) fn parse_pairing_payload(bytes: &[u8]) -> Result<(Vec<u8>, String, String)> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.u8()? != PAYLOAD_VERSION {
        return Err(CoreError::Malformed("unknown pairing payload version"));
    }
    let bundle = c.bytes_field()?.to_vec();
    let relay = utf8(c.bytes_field()?)?;
    let inbox = utf8(c.take(MAILBOX_ID_LEN)?)?;
    if c.pos != bytes.len() {
        return Err(CoreError::Malformed("trailing bytes in pairing payload"));
    }
    Ok((bundle, relay, inbox))
}

/// Encodes a `pair-ack/1` inner-frame payload.
pub(crate) fn encode_pair_ack(relay_url: &str, inbox_id: &str, address_name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CONTROL_VERSION);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(inbox_id.as_bytes());
    put_bytes(&mut out, address_name.as_bytes());
    out
}

/// Parses a `pair-ack/1` payload.
pub(crate) fn parse_pair_ack(bytes: &[u8]) -> Result<ReplyCoords> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.u8()? != CONTROL_VERSION {
        return Err(CoreError::Malformed("unknown pair-ack version"));
    }
    let relay_url = utf8(c.bytes_field()?)?;
    let inbox_id = utf8(c.take(MAILBOX_ID_LEN)?)?;
    let _address_name = utf8(c.bytes_field()?)?; // parsed; derived value is authoritative
    Ok(ReplyCoords {
        relay_url,
        inbox_id,
    })
}

/// Encodes a `mailbox-update/1` inner-frame payload (relay + new inbox).
pub(crate) fn encode_mailbox_update(relay_url: &str, inbox_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CONTROL_VERSION);
    put_bytes(&mut out, relay_url.as_bytes());
    out.extend_from_slice(inbox_id.as_bytes());
    out
}

/// Parses a `mailbox-update/1` payload. Returns (relay url, inbox id).
pub(crate) fn parse_mailbox_update(bytes: &[u8]) -> Result<(String, String)> {
    let mut c = Cursor { bytes, pos: 0 };
    if c.u8()? != CONTROL_VERSION {
        return Err(CoreError::Malformed("unknown mailbox-update version"));
    }
    let relay_url = utf8(c.bytes_field()?)?;
    let inbox_id = utf8(c.take(MAILBOX_ID_LEN)?)?;
    Ok((relay_url, inbox_id))
}

fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| CoreError::Malformed("field is not UTF-8"))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(CoreError::Malformed("bundle length overflow"))?;
        if end > self.bytes.len() {
            return Err(CoreError::Malformed("truncated pairing bundle"));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn bytes_field(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }
}
