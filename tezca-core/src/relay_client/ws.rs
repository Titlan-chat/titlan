// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! WebSocket transport to a relay inbox: subscribe, receive delivery frames,
//! send acks. Plain `ws://` (tests) and `wss://` (ring-rustls, with an
//! optional per-conversation SPKI pin) share one stream type.
//!
//! Wire frames (`proto/relay-api.md`): server→client delivery is
//! `0x01 || message_id(16) || envelope`; client→server ack is
//! `0x02 || message_id(16)`.

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::error::Error as WsError;

use crate::{CoreError, Result};

mod pin;

/// Any byte stream we can run a WebSocket over (plain TCP or a TLS stream).
pub(crate) trait ClientIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientIo for T {}

/// An open subscription to a relay inbox.
pub(crate) struct Subscription {
    ws: WebSocketStream<Box<dyn ClientIo>>,
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
/// `pin` is an optional SPKI SHA-256 for the relay's TLS cert (wss only).
pub(crate) async fn subscribe(
    relay_url: &str,
    mailbox_id: &str,
    pin: Option<[u8; 32]>,
) -> Connected {
    let (scheme, authority) = match relay_url.split_once("://") {
        Some((s, a)) => (s, a),
        None => return Connected::Unreachable,
    };
    let host = authority.split(':').next().unwrap_or(authority).to_string();
    let ws_url = format!("{relay_url}/v1/mailboxes/{mailbox_id}/ws");

    let tcp = match TcpStream::connect(authority).await {
        Ok(s) => s,
        Err(_) => return Connected::Unreachable,
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
        Ok((ws, _resp)) => Connected::Ok(Box::new(Subscription { ws })),
        Err(WsError::Http(resp)) if resp.status().as_u16() == 404 => Connected::NotFound,
        Err(_) => Connected::Unreachable,
    }
}

impl Subscription {
    /// Reads the next delivery frame: `(message_id, envelope)`. `None` on a
    /// clean close; `Err` on a transport failure.
    pub(crate) async fn next(&mut self) -> Result<Option<([u8; 16], Vec<u8>)>> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(data))) => {
                    if data.len() < 17 || data[0] != 0x01 {
                        return Err(CoreError::Malformed("bad relay delivery frame"));
                    }
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&data[1..17]);
                    return Ok(Some((id, data[17..].to_vec())));
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = self.ws.send(Message::Pong(p)).await;
                }
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(CoreError::Network(e.to_string())),
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

/// Installs the ring crypto provider as the process default (idempotent).
/// Required by reqwest's `rustls-no-provider` and by our wss client config.
pub(crate) fn install_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
