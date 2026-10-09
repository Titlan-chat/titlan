// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! WebSocket transport to a relay inbox: subscribe, receive delivery frames,
//! send acks. Plain `ws://` (tests) and `wss://` (ring-rustls, with an
//! optional per-conversation SPKI pin) share one stream type.
//!
//! Wire frames (`proto/relay-api.md`): server→client delivery is
//! `0x01 || message_id(16) || envelope`; client→server ack is
//! `0x02 || message_id(16)`.
//!
//! Keepalive (unit 5e-1b, finding F-L): after [`KeepaliveTiming::interval`]
//! of silence the client sends a WebSocket Ping; a Pong not seen within
//! [`KeepaliveTiming::grace`] is a transport error, which the listener turns
//! into its ordinary reconnect. The relay answers Pings per RFC 6455 and
//! attaches no meaning to them (INV-2: an empty frame, no identity).

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::error::Error as WsError;

use crate::config::{HttpTimeouts, KeepaliveTiming};
use crate::{CoreError, Result};

mod pin;

/// Any byte stream we can run a WebSocket over (plain TCP or a TLS stream).
pub(crate) trait ClientIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientIo for T {}

/// An open subscription to a relay inbox.
pub(crate) struct Subscription {
    ws: WebSocketStream<Box<dyn ClientIo>>,
    timing: KeepaliveTiming,
    /// A Ping is in flight and its Pong is due within `timing.grace`.
    awaiting_pong: bool,
}

/// What [`Subscription::next`] yields.
pub(crate) enum Event {
    /// A delivery frame: `(message_id, envelope)`.
    Delivery([u8; 16], Vec<u8>),
    /// A keepalive round trip completed (Ping answered): the socket is live
    /// and idle. The listener uses it to retry pending sends.
    Idle,
}

/// Outcome of a subscribe attempt.
pub(crate) enum Connected {
    /// Subscribed (boxed — the WebSocket stream is large).
    Ok(Box<Subscription>),
    /// The relay answered 404 — the mailbox is gone (§10.7 loss signal).
    NotFound,
    /// The relay could not be reached (retry with backoff).
    Unreachable,
}

/// Connects and subscribes to `{relay_url}/v1/mailboxes/{mailbox_id}/ws`.
/// `pin` is an optional SPKI SHA-256 for the relay's TLS cert (wss only);
/// `timing` is the keepalive the subscription runs (production constants or
/// a test injection).
pub(crate) async fn subscribe(
    relay_url: &str,
    mailbox_id: &str,
    pin: Option<[u8; 32]>,
    timing: KeepaliveTiming,
) -> Connected {
    let Some((scheme, authority)) = relay_url.split_once("://") else {
        return Connected::Unreachable;
    };
    let host = authority.split(':').next().unwrap_or(authority).to_string();
    let ws_url = format!("{relay_url}/v1/mailboxes/{mailbox_id}/ws");

    let Ok(tcp) = TcpStream::connect(socket_authority(scheme, authority)).await else {
        return Connected::Unreachable;
    };

    let stream: Box<dyn ClientIo> = if scheme == "wss" {
        match pin::tls_connect(tcp, &host, pin).await {
            Ok(tls) => Box::new(tls),
            Err(_) => return Connected::Unreachable,
        }
    } else {
        Box::new(tcp)
    };

    match tokio_tungstenite::client_async(&ws_url, stream).await {
        Ok((ws, _resp)) => Connected::Ok(Box::new(Subscription::new(ws, timing))),
        Err(WsError::Http(resp)) if resp.status().as_u16() == 404 => Connected::NotFound,
        Err(_) => Connected::Unreachable,
    }
}

impl Subscription {
    fn new(ws: WebSocketStream<Box<dyn ClientIo>>, timing: KeepaliveTiming) -> Self {
        Subscription {
            ws,
            timing,
            awaiting_pong: false,
        }
    }

    /// Reads the next event: a delivery frame, or `Idle` once a keepalive
    /// Ping has been answered. `None` on a clean close; `Err` on a transport
    /// failure — including a Pong missing after `timing.grace` (F-L).
    ///
    /// Cancellation-safe between frames: state only changes after an await
    /// completes, and a Ping dropped mid-send is at worst re-sent.
    pub(crate) async fn next(&mut self) -> Result<Option<Event>> {
        loop {
            let wait = if self.awaiting_pong {
                self.timing.grace
            } else {
                self.timing.interval
            };
            match tokio::time::timeout(wait, self.ws.next()).await {
                Err(_elapsed) => {
                    if self.awaiting_pong {
                        return Err(CoreError::Network("keepalive timeout".into()));
                    }
                    // Silence for a whole interval: ask the relay to prove the
                    // socket is alive. Empty payload — nothing to correlate.
                    self.ws
                        .send(Message::Ping(Vec::new().into()))
                        .await
                        .map_err(|e| CoreError::Network(e.to_string()))?;
                    self.awaiting_pong = true;
                }
                Ok(Some(Ok(Message::Binary(data)))) => {
                    // Any delivery proves liveness; a late Pong is then
                    // unsolicited and ignored below.
                    self.awaiting_pong = false;
                    if data.len() < 17 || data[0] != 0x01 {
                        return Err(CoreError::Malformed("bad relay delivery frame"));
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&data[1..17]);
                    return Ok(Some(Event::Delivery(id, data[17..].to_vec())));
                }
                Ok(Some(Ok(Message::Pong(_)))) => {
                    if self.awaiting_pong {
                        self.awaiting_pong = false;
                        return Ok(Some(Event::Idle));
                    }
                }
                Ok(Some(Ok(Message::Ping(p)))) => {
                    let _ = self.ws.send(Message::Pong(p)).await;
                }
                Ok(Some(Ok(Message::Close(_))) | None) => return Ok(None),
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(e))) => return Err(CoreError::Network(e.to_string())),
            }
        }
    }

    /// Acks a delivered message so the relay deletes it.
    pub(crate) async fn ack(&mut self, message_id: &[u8; 16]) -> Result<()> {
        let mut frame = Vec::with_capacity(17);
        frame.push(0x02);
        frame.extend_from_slice(message_id);
        self.ws
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|e| CoreError::Network(e.to_string()))
    }
}

/// The `host:port` a relay URL's authority resolves to for `TcpStream::connect`:
/// an explicit port is kept, otherwise the scheme's default (443 for `wss`, 80
/// for `ws`). Finding F-F (release-checklist §0, 2026-09-26): the production
/// default `wss://relay.titlan.chat` carries no port, and
/// `TcpStream::connect("relay.titlan.chat")` fails as an invalid socket
/// address before any I/O — every WebSocket subscription failed, so no
/// pairing handoff and no message receipt. Single site (check-invariants 19a).
fn socket_authority(scheme: &str, authority: &str) -> String {
    if authority.contains(':') {
        authority.to_owned()
    } else {
        let port = if scheme == "wss" { 443 } else { 80 };
        format!("{authority}:{port}")
    }
}

/// Installs the ring crypto provider as the process default (idempotent).
/// Required by reqwest's `rustls-no-provider` and by our wss client config.
pub(crate) fn install_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Builds the engine's reqwest client over the SAME trust decision as the wss
/// leg: in `test-relay-anchor` builds with `TEZCA_TEST_RELAY_PIN` set, exactly
/// the pinned test-relay certificate; otherwise the bundled Mozilla root store
/// ([`pin::bundled_client_config`]). reqwest is always handed the config, so
/// its own verifier construction is never reached (family 18b). Every call
/// is bounded by `timeouts` (F-L, KA-D4): a black-holed route fails within
/// the request timeout instead of the OS's TCP give-up.
pub(crate) fn build_http_client(timeouts: HttpTimeouts) -> Result<reqwest::Client> {
    #[cfg(feature = "test-relay-anchor")]
    let config = match pin::env_test_pin() {
        Some(p) => pin::pinned_client_config(p)?,
        None => pin::bundled_client_config()?,
    };
    #[cfg(not(feature = "test-relay-anchor"))]
    let config = pin::bundled_client_config()?;
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.request)
        .build()
        .map_err(|e| CoreError::Network(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::ToSocketAddrs;

    #[test]
    fn socket_authority_defaults_wss_to_443() {
        assert_eq!(
            socket_authority("wss", "relay.titlan.chat"),
            "relay.titlan.chat:443"
        );
    }

    #[test]
    fn socket_authority_defaults_ws_to_80() {
        assert_eq!(socket_authority("ws", "relay.local"), "relay.local:80");
    }

    #[test]
    fn socket_authority_keeps_explicit_port() {
        assert_eq!(socket_authority("wss", "10.0.0.32:8443"), "10.0.0.32:8443");
        assert_eq!(socket_authority("ws", "127.0.0.1:41234"), "127.0.0.1:41234");
    }

    #[test]
    fn bare_authority_is_not_a_socket_address() {
        // The pre-5d-5 failure mode, pinned: no port, no socket address, no I/O.
        assert!("relay.titlan.chat".to_socket_addrs().is_err());
        assert!("127.0.0.1:443".to_socket_addrs().is_ok());
    }

    // ---- Keepalive (5e-1b, finding F-L) ------------------------------------
    //
    // A fake relay over an in-memory duplex pipe: the handshake completes, then
    // the server either reads frames (tungstenite answers Pings with Pongs as it
    // reads — the same RFC 6455 behaviour the real relay inherits from axum) or
    // never reads at all (a dead socket: bytes go in, nothing comes back). Real
    // time with short injected timing — the workspace tokio carries no
    // `test-util`, so paused time is not available without a manifest change.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use tokio::io::DuplexStream;

    const TEST_TIMING: KeepaliveTiming = KeepaliveTiming {
        interval: Duration::from_millis(300),
        grace: Duration::from_millis(300),
    };

    /// Client-side subscription over one end of a duplex pipe; the other end
    /// has already been handed to a server task.
    async fn client_over(end: DuplexStream, timing: KeepaliveTiming) -> Subscription {
        let io: Box<dyn ClientIo> = Box::new(end);
        let (ws, _resp) = tokio_tungstenite::client_async("ws://relay.test/v1/mailboxes/x/ws", io)
            .await
            .expect("client handshake");
        Subscription::new(ws, timing)
    }

    /// A server that answers everything: counts the Pings it reads and records
    /// when the first one arrived; optionally sends one delivery frame first.
    async fn answering_server(
        end: DuplexStream,
        pings: Arc<AtomicUsize>,
        first_ping_at: Arc<std::sync::Mutex<Option<Instant>>>,
        delivery_after: Option<Duration>,
    ) {
        let mut ws = tokio_tungstenite::accept_async(end)
            .await
            .expect("server handshake");
        if let Some(d) = delivery_after {
            tokio::time::sleep(d).await;
            let mut frame = vec![0x01u8];
            frame.extend_from_slice(&[7u8; 16]);
            frame.extend_from_slice(b"env");
            ws.send(Message::Binary(frame.into()))
                .await
                .expect("deliver");
        }
        while let Some(Ok(msg)) = ws.next().await {
            if let Message::Ping(_) = msg {
                pings.fetch_add(1, Ordering::SeqCst);
                first_ping_at
                    .lock()
                    .expect("ping instant")
                    .get_or_insert_with(Instant::now);
                // tungstenite queued the Pong on read; flushing sends it.
                ws.flush().await.expect("flush pong");
            }
        }
    }

    #[tokio::test]
    async fn keepalive_pings_after_interval_of_silence() {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let pings = Arc::new(AtomicUsize::new(0));
        let at = Arc::new(std::sync::Mutex::new(None));
        tokio::spawn(answering_server(
            server_end,
            pings.clone(),
            at.clone(),
            None,
        ));
        let mut sub = client_over(client_end, TEST_TIMING).await;

        let started = Instant::now();
        let event = tokio::time::timeout(Duration::from_secs(3), sub.next())
            .await
            .expect("a keepalive round trip must complete within 3 s")
            .expect("transport ok");
        assert!(
            matches!(event, Some(Event::Idle)),
            "silence must yield Event::Idle once the Ping is answered"
        );
        assert_eq!(
            pings.load(Ordering::SeqCst),
            1,
            "exactly one Ping per interval"
        );
        let ping_at = at.lock().expect("ping instant").expect("a Ping was seen");
        assert!(
            ping_at.duration_since(started) >= Duration::from_millis(250),
            "the Ping must wait for the interval of silence"
        );
    }

    #[tokio::test]
    async fn keepalive_missing_pong_is_a_transport_error() {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        // Dead socket: the server finishes the handshake and never reads again.
        tokio::spawn(async move {
            let _ws = tokio_tungstenite::accept_async(server_end)
                .await
                .expect("server handshake");
            std::future::pending::<()>().await;
        });
        let mut sub = client_over(client_end, TEST_TIMING).await;

        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(3), sub.next())
            .await
            .expect("a missing Pong must surface within 3 s");
        assert!(
            result.is_err(),
            "a Pong missing after the grace period is a transport error"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(550),
            "the error must come no earlier than interval + grace (got {elapsed:?})"
        );
    }

    #[tokio::test]
    async fn keepalive_resets_on_traffic() {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let pings = Arc::new(AtomicUsize::new(0));
        let at = Arc::new(std::sync::Mutex::new(None));
        // A delivery half an interval in: the silence clock restarts from it.
        tokio::spawn(answering_server(
            server_end,
            pings.clone(),
            at.clone(),
            Some(Duration::from_millis(150)),
        ));
        let mut sub = client_over(client_end, TEST_TIMING).await;

        let started = Instant::now();
        let first = tokio::time::timeout(Duration::from_secs(3), sub.next())
            .await
            .expect("delivery within 3 s")
            .expect("transport ok");
        assert!(matches!(first, Some(Event::Delivery(id, _)) if id == [7u8; 16]));
        let second = tokio::time::timeout(Duration::from_secs(3), sub.next())
            .await
            .expect("keepalive within 3 s")
            .expect("transport ok");
        assert!(matches!(second, Some(Event::Idle)));
        let ping_at = at.lock().expect("ping instant").expect("a Ping was seen");
        assert!(
            ping_at.duration_since(started) >= Duration::from_millis(400),
            "the Ping must be measured from the last traffic, not from subscribe"
        );
        assert_eq!(pings.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn http_client_times_out_on_a_silent_server() {
        // A listener that accepts and never answers: without a request timeout
        // a deposit here hangs for the OS's TCP give-up (F-L, KA-D4).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                held.push(stream);
            }
        });
        install_ring_provider();
        let client = build_http_client(HttpTimeouts {
            connect: Duration::from_millis(500),
            request: Duration::from_millis(500),
        })
        .expect("client");
        let relay_url = format!("ws://{addr}");
        let started = Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            crate::relay_client::http::deposit(&client, &relay_url, "mailbox", b"blob"),
        )
        .await
        .expect("the deposit must give up within 5 s");
        let elapsed = started.elapsed();
        let err = outcome.expect_err("a silent server must be a bounded error");
        assert!(
            matches!(err, CoreError::Network(_)),
            "expected a network error, got {err:?}"
        );
        // Not refused (that fails in microseconds) and not hung: the request
        // timeout itself is what returned.
        assert!(
            elapsed >= Duration::from_millis(450) && elapsed < Duration::from_secs(3),
            "bounded by the 500 ms request timeout, got {elapsed:?}"
        );
    }
}
