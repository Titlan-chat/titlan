// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Shared harness for the tezca-relay acceptance tests (work order §6
//! Phase 3). Spawns the REAL relay binary as a child process and drives it
//! over plain HTTP/1.1 (hand-rolled, loopback-only test client) and
//! WebSocket (tungstenite).
//!
//! The flag names used here are the relay's configuration contract; the
//! implementation must accept exactly these. The relay must set
//! SO_REUSEADDR so the kill/restart test can rebind the same port.
//!
//! Each `tests/*.rs` file is its own crate and compiles this whole module,
//! so helpers a given test binary doesn't use would trip dead_code — hence
//! the crate-wide allow on this shared harness.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// A running relay child process.
pub struct RelayProc {
    child: Option<Child>,
    pub port: u16,
}

impl RelayProc {
    pub fn base(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("relay child already collected")
    }

    pub fn pid(&self) -> u32 {
        self.child
            .as_ref()
            .expect("relay child already collected")
            .id()
    }

    /// SIGKILL — models a crash/power loss (INV-3: everything is lost).
    pub fn kill(&mut self) {
        let _ = self.child_mut().kill();
        let _ = self.child_mut().wait();
    }

    /// Kills the relay and returns everything it wrote to stdout+stderr.
    pub fn kill_and_collect_output(mut self) -> String {
        let mut child = self.child.take().expect("relay child already collected");
        let _ = child.kill();
        let out = child.wait_with_output().expect("collect relay output");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// Resident set size (kB) from /proc — for the flat-memory assertion.
    pub fn rss_kb(&self) -> u64 {
        let status =
            std::fs::read_to_string(format!("/proc/{}/status", self.pid())).expect("proc status");
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                return rest
                    .trim()
                    .trim_end_matches(" kB")
                    .trim()
                    .parse()
                    .expect("VmRSS");
            }
        }
        panic!("VmRSS not found");
    }

    /// Storage bytes written by the relay so far (/proc/<pid>/io) — INV-3.
    /// Returns `None` when /proc/<pid>/io is unreadable (some hardened
    /// sandboxes deny it even for same-uid children); callers fall back to
    /// the working-directory-empty check, which is the primary INV-3 signal.
    pub fn storage_write_bytes(&self) -> Option<u64> {
        let io = std::fs::read_to_string(format!("/proc/{}/io", self.pid())).ok()?;
        for line in io.lines() {
            if let Some(rest) = line.strip_prefix("write_bytes:") {
                return rest.trim().parse().ok();
            }
        }
        None
    }
}

impl Drop for RelayProc {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Picks a free loopback port (bind-then-drop).
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind :0");
    listener.local_addr().expect("local addr").port()
}

/// Spawns the relay on `port` with `extra` config flags, in `cwd`, and waits
/// until it accepts TCP connections. Panics (test failure) if it never does —
/// which is exactly the red state before the Phase 3 implementation exists.
pub fn spawn_relay_at(port: u16, extra: &[&str], cwd: &std::path::Path) -> RelayProc {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tezca-relay"));
    cmd.arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--plain-http")
        .args(extra)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let child = cmd.spawn().expect("spawn tezca-relay binary");
    let mut proc = RelayProc {
        child: Some(child),
        port,
    };

    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().expect("addr"),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return proc;
        }
        if let Ok(Some(status)) = proc.child_mut().try_wait() {
            panic!("relay exited before listening (status {status}) — Phase 3 not implemented?");
        }
        if Instant::now() > deadline {
            proc.kill();
            panic!("relay did not start listening on {port} within {STARTUP_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn spawn_relay(extra: &[&str]) -> (RelayProc, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let proc = spawn_relay_at(free_port(), extra, dir.path());
    (proc, dir)
}

/// Rate/capacity limits high enough that functional tests never trip them.
pub const GENEROUS_LIMITS: &[&str] = &[
    "--rate-create-per-min",
    "100000",
    "--rate-deposit-per-min-source",
    "1000000",
    "--rate-deposit-per-min-mailbox",
    "1000000",
    "--rate-ws-per-min-mailbox",
    "100000",
];

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 test client (loopback only). Hand-rolled so the test
// harness adds no HTTP dependency; correctness is cross-checked against the
// axum server it drives.
// ---------------------------------------------------------------------------

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub fn http_request(base: &str, method: &str, path: &str, body: &[u8]) -> HttpResponse {
    let mut stream = TcpStream::connect(base).expect("connect relay");
    stream.set_read_timeout(Some(IO_TIMEOUT)).expect("timeout");
    stream.set_write_timeout(Some(IO_TIMEOUT)).expect("timeout");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {base}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).expect("write request");
    stream.write_all(body).expect("write body");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response header terminator");
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.lines();
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    let mut body = raw[split + 4..].to_vec();
    // Tests use Connection: close; tolerate chunked encoding minimally.
    if headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"))
    {
        body = dechunk(&body);
    }
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") else {
            return out;
        };
        let size =
            usize::from_str_radix(String::from_utf8_lossy(&rest[..pos]).trim(), 16).unwrap_or(0);
        if size == 0 {
            return out;
        }
        let start = pos + 2;
        out.extend_from_slice(&rest[start..start + size]);
        rest = &rest[start + size + 2..];
    }
}

// ---------------------------------------------------------------------------
// Relay API helpers (the endpoint contract from the approved design)
// ---------------------------------------------------------------------------

pub fn create_mailbox(base: &str) -> HttpResponse {
    http_request(base, "POST", "/v1/mailboxes", &[])
}

/// Creates a mailbox and extracts the id (panics on unexpected shape).
pub fn create_mailbox_id(base: &str) -> String {
    let resp = create_mailbox(base);
    assert_eq!(resp.status, 201, "mailbox create must return 201");
    let body = String::from_utf8(resp.body.clone()).expect("utf8 body");
    // {"mailbox_id":"<43 chars base64url>"}
    let id = body
        .split("\"mailbox_id\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .expect("mailbox_id in response")
        .to_string();
    assert_eq!(
        id.len(),
        43,
        "mailbox id must be 43-char base64url (256-bit)"
    );
    id
}

pub fn deposit(base: &str, mailbox_id: &str, blob: &[u8]) -> HttpResponse {
    http_request(
        base,
        "POST",
        &format!("/v1/mailboxes/{mailbox_id}/messages"),
        blob,
    )
}

pub fn delete_mailbox(base: &str, mailbox_id: &str) -> HttpResponse {
    http_request(base, "DELETE", &format!("/v1/mailboxes/{mailbox_id}"), &[])
}

/// A valid-looking outer envelope whose ciphertext is opaque garbage — the
/// relay must accept it (it validates magic+version only; INV-2 blindness).
pub fn opaque_envelope(size: usize) -> Vec<u8> {
    tezca_core::envelope::Envelope {
        kind: tezca_core::envelope::EnvelopeKind::Ratchet,
        ciphertext: vec![0xAA; size],
    }
    .encode()
}

// ---------------------------------------------------------------------------
// WebSocket subscribe/delivery/ack (frames per the approved design:
// server→client 0x01 || message_id(16) || envelope; client→server ack
// 0x02 || message_id(16))
// ---------------------------------------------------------------------------

pub type WsClient = tungstenite::WebSocket<TcpStream>;

pub fn ws_subscribe(base: &str, mailbox_id: &str) -> Result<WsClient, String> {
    let stream = TcpStream::connect(base).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).expect("timeout");
    stream.set_write_timeout(Some(IO_TIMEOUT)).expect("timeout");
    let url = format!("ws://{base}/v1/mailboxes/{mailbox_id}/ws");
    let (ws, _resp) = tungstenite::client(url.as_str(), stream).map_err(|e| e.to_string())?;
    Ok(ws)
}

/// Reads one delivery frame; returns (message_id, envelope bytes).
pub fn ws_next_message(ws: &mut WsClient) -> Result<([u8; 16], Vec<u8>), String> {
    loop {
        let msg = ws.read().map_err(|e| e.to_string())?;
        match msg {
            tungstenite::Message::Binary(data) => {
                if data.len() < 17 || data[0] != 0x01 {
                    return Err(format!("malformed delivery frame ({} bytes)", data.len()));
                }
                let mut id = [0u8; 16];
                id.copy_from_slice(&data[1..17]);
                return Ok((id, data[17..].to_vec()));
            }
            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => continue,
            other => return Err(format!("unexpected ws message: {other:?}")),
        }
    }
}

pub fn ws_ack(ws: &mut WsClient, message_id: &[u8; 16]) -> Result<(), String> {
    let mut frame = Vec::with_capacity(17);
    frame.push(0x02);
    frame.extend_from_slice(message_id);
    ws.send(tungstenite::Message::Binary(frame.into()))
        .map_err(|e| e.to_string())
}
