// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Dev-only VM-side deposit harness for device checklist (f) (maintainer-
//! ratified F2): drives tezca-core's REAL session/envelope path — a genuine
//! pairing (PQXDH + proof-of-scan) and `send_chat`'s encrypt-then-deposit —
//! to place exactly ONE encrypted `chat/1` envelope into the paired device's
//! inbox via the relay HTTP API. No bypass, no plaintext shortcut: every byte
//! that reaches the relay is produced by `session::encrypt_message` inside
//! the engine, exactly as the app produces it.
//!
//! A cargo example — dev scope only, same precedent as tezca-relay's
//! `gen_test_cert`: never part of the library, the cdylib, or any APK, and
//! compiled only on demand.
//!
//! TLS to the self-signed VM relay: build with `--features test-relay-anchor`
//! and set `TEZCA_TEST_RELAY_PIN` (hex SHA-256 of the relay leaf cert DER,
//! from gen_test_cert's pin.hex) — the identical anchor the instrumented
//! Android harness uses.
//!
//! State lives in `--dir` (created on demand): `titlan.db` (SQLCipher store)
//! plus `db.key` (hex). Writing the key beside the store is acceptable ONLY
//! here: this is a throwaway dev identity on the build host carrying nothing
//! but checklist traffic — INV-1 governs the product store, not this dev
//! fixture. Never mirror this pattern in product code.
//!
//! Subcommands:
//!   offer   --dir D --relay URL [--wait-secs N]
//!           mint a pairing offer, print its titlan://pair# link, then wait
//!           for the device to scan/paste it and complete pairing
//!   respond --dir D --relay URL --offer LINK
//!           consume a device-minted offer (titlan://pair# link or bare
//!           base64url payload) and complete pairing as the responder
//!   send    --dir D --relay URL [--conv HEX] [--text S]
//!           deposit ONE chat/1 message to the paired device's inbox,
//!           printing deposit epoch-ms timestamps (VM clock, informational —
//!           checklist t0/t1 both come from the device clock)
//!   selftest
//!           base64url codec vectors (no network, no state)

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::TryRngCore;
use tezca_core::client::TitlanClient;
use tezca_core::storage::{DbKey, Store};

const LINK_PREFIX: &str = "titlan://pair#";
const DB_FILE: &str = "titlan.db";
const KEY_FILE: &str = "db.key";
const DEFAULT_TEXT: &str = "doze-latency checklist deposit";
const DEFAULT_WAIT_SECS: u64 = 600;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage_exit();
    }
    let cmd = args.remove(0);
    let flags = parse_flags(&args);
    match cmd.as_str() {
        "selftest" => selftest(),
        "offer" => offer(&flags),
        "respond" => respond(&flags),
        "send" => send(&flags),
        _ => usage_exit(),
    }
}

fn usage_exit() -> ! {
    eprintln!(
        "usage: deposit_harness <offer|respond|send|selftest> \
         --dir <state-dir> --relay <url> [--offer <link>] [--conv <hex>] \
         [--text <s>] [--wait-secs <n>]"
    );
    std::process::exit(2);
}

fn parse_flags(args: &[String]) -> HashMap<String, String> {
    let mut flags = HashMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--dir" | "--relay" | "--offer" | "--conv" | "--text" | "--wait-secs" => {
                let Some(value) = it.next() else {
                    eprintln!("missing value for {flag}");
                    usage_exit();
                };
                flags.insert(flag.clone(), value.clone());
            }
            other => {
                eprintln!("unknown flag: {other}");
                usage_exit();
            }
        }
    }
    flags
}

fn required<'a>(flags: &'a HashMap<String, String>, key: &str) -> &'a str {
    match flags.get(key) {
        Some(v) => v,
        None => {
            eprintln!("missing required flag {key}");
            usage_exit();
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch")
        .as_millis()
}

/// Reads (or creates) the harness DB key. Dev fixture only — see module docs.
fn load_or_create_key(dir: &Path) -> [u8; 32] {
    let path = dir.join(KEY_FILE);
    if path.exists() {
        let s = std::fs::read_to_string(&path).expect("read db.key");
        let v = hex::decode(s.trim()).expect("db.key is not hex");
        v.try_into().expect("db.key must be 32 hex-encoded bytes")
    } else {
        let mut b = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut b)
            .expect("OS CSPRNG unavailable");
        std::fs::write(&path, format!("{}\n", hex::encode(b))).expect("write db.key");
        b
    }
}

/// Opens (creating on first use) the harness's own client — a full, real
/// tezca-core identity/store; `relay` is its default relay (INV-5 semantics,
/// same as the app's BuildConfig.RELAY_URL).
fn open_client(dir: &Path, relay: &str) -> TitlanClient {
    std::fs::create_dir_all(dir).expect("create state dir");
    let key = DbKey::from_bytes(load_or_create_key(dir));
    let client = TitlanClient::open(&dir.join(DB_FILE), &key, relay).expect("open store");
    if !client.is_initialized().expect("read init state") {
        client.initialize_identity().expect("initialize identity");
    }
    client
}

/// Harness as OFFERER: the device scans/pastes the printed link, the real v2
/// pairing (proof-of-scan, inbox handoff, recovery root) runs end to end, and
/// the session persists in --dir for later `send`s.
fn offer(flags: &HashMap<String, String>) {
    let dir = PathBuf::from(required(flags, "--dir"));
    let relay = required(flags, "--relay");
    let wait_secs: u64 = flags
        .get("--wait-secs")
        .map(|s| s.parse().expect("--wait-secs must be a number"))
        .unwrap_or(DEFAULT_WAIT_SECS);

    let client = open_client(&dir, relay);
    let before: HashSet<[u8; 16]> = client
        .list_conversations()
        .expect("list conversations")
        .into_iter()
        .collect();
    let payload = client
        .export_pairing_offer()
        .expect("export offer (is the relay reachable and the pin set?)");
    println!("{LINK_PREFIX}{}", b64url_encode(payload.as_bytes()));
    println!("offer minted — scan/paste it on the device within {wait_secs}s (single-use)");

    for _ in 0..wait_secs {
        std::thread::sleep(Duration::from_secs(1));
        let now = client.list_conversations().expect("list conversations");
        if let Some(new) = now.iter().find(|c| !before.contains(*c)) {
            println!("paired: conversation {}", hex::encode(new));
            return;
        }
    }
    eprintln!("no pairing completed within {wait_secs}s (the offer may stay live until its TTL)");
    std::process::exit(1);
}

/// Harness as RESPONDER: consumes a device-minted offer.
fn respond(flags: &HashMap<String, String>) {
    let dir = PathBuf::from(required(flags, "--dir"));
    let relay = required(flags, "--relay");
    let link = required(flags, "--offer");
    let b64 = link.strip_prefix(LINK_PREFIX).unwrap_or(link).trim();
    let Some(payload) = b64url_decode(b64) else {
        eprintln!("--offer is not a titlan://pair# link or base64url payload");
        std::process::exit(2);
    };

    let client = open_client(&dir, relay);
    let conv = client
        .begin_pairing_from_offer(&payload)
        .expect("pairing failed (offer stale? device app closed? relay unreachable?)");
    println!("paired: conversation {}", hex::encode(conv));
}

/// Deposits exactly ONE chat/1 message through the real engine path:
/// persist-pending → `session::encrypt_message` → HTTP deposit → mark sent.
fn send(flags: &HashMap<String, String>) {
    let dir = PathBuf::from(required(flags, "--dir"));
    let relay = required(flags, "--relay");
    let text = flags
        .get("--text")
        .map(String::as_str)
        .unwrap_or(DEFAULT_TEXT);

    let client = open_client(&dir, relay);
    let convs = client.list_conversations().expect("list conversations");
    let conv: [u8; 16] = match flags.get("--conv") {
        Some(h) => hex::decode(h.trim())
            .expect("--conv is not hex")
            .try_into()
            .expect("--conv must be 16 bytes of hex"),
        None => {
            if convs.len() != 1 {
                eprintln!(
                    "{} conversations in {} — pass --conv <hex-id> (pair first with \
                     `offer`/`respond` if there are none)",
                    convs.len(),
                    dir.display()
                );
                std::process::exit(2);
            }
            convs[0]
        }
    };

    println!("deposit-start epoch_ms={}", now_ms());
    client.send_chat(&conv, text).expect("send_chat failed");

    // send_chat's flush is deliberately best-effort in the engine (retried on
    // reconnect in the app); the checklist needs certainty, so verify through
    // a second read handle that nothing stayed pending. The engine clears the
    // pending row only on a relay 202 (or a permanent 400/413 rejection,
    // impossible for a real chat/1 under the 16 KiB blob cap).
    let key = DbKey::from_bytes(load_or_create_key(&dir));
    let store = Store::open(&dir.join(DB_FILE), &key).expect("re-open store");
    let pending = store.pending_chat(&conv).expect("read pending");
    if pending.is_empty() {
        println!("deposit-confirmed epoch_ms={}", now_ms());
    } else {
        eprintln!(
            "deposit NOT confirmed: {} chat message(s) still pending — relay unreachable \
             or peer mailbox gone. Do not re-run blindly: the next send would flush this \
             backlog and deposit more than one message.",
            pending.len()
        );
        std::process::exit(1);
    }
}

// ---- base64url (no padding) — the QrCodec/link wire encoding ---------------
// Hand-rolled to keep the harness dependency-free (base64 is an encoding, not
// cryptography — INV-6 untouched). Byte-compatible with the app's QrCodec
// (URL_SAFE | NO_PADDING | NO_WRAP); `selftest` pins RFC 4648 vectors.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() == 1 {
            return None; // impossible length for unpadded base64
        }
        let mut n: u32 = 0;
        for &c in chunk {
            n = (n << 6) | val(c)?;
        }
        n <<= (6 * (4 - chunk.len())) as u32;
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn selftest() {
    // RFC 4648 §10 vectors (url-safe alphabet, no padding).
    let vectors: [(&[u8], &str); 7] = [
        (b"", ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (b"fooba", "Zm9vYmE"),
        (b"foobar", "Zm9vYmFy"),
    ];
    for (raw, enc) in vectors {
        assert_eq!(b64url_encode(raw), enc, "encode {raw:?}");
        assert_eq!(b64url_decode(enc).expect("decode"), raw, "decode {enc}");
    }
    // URL-safe alphabet in use: 0xFB 0xFF encodes through '-' and '_'.
    let hi = [0xfbu8, 0xff];
    assert_eq!(b64url_encode(&hi), "-_8");
    assert_eq!(b64url_decode("-_8").expect("decode hi"), hi);
    // Round-trip every length 1..=257 with varied content.
    let mut data = Vec::new();
    for i in 0..=257u16 {
        data.push((i % 251) as u8);
        let enc = b64url_encode(&data);
        assert_eq!(b64url_decode(&enc).expect("round-trip decode"), data);
    }
    // Rejections: padding, non-alphabet chars, impossible length.
    assert!(b64url_decode("Zg==").is_none());
    assert!(b64url_decode("Zm9+").is_none());
    assert!(b64url_decode("A").is_none());
    println!("selftest ok");
}
