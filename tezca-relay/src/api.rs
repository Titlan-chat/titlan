// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! HTTP/WebSocket API per proto/relay-api.md. INV-2 discipline throughout:
//! error bodies are EMPTY and byte-identical across unknown / expired /
//! deleted mailboxes; DELETE answers 204 unconditionally; handlers never
//! construct any value combining a mailbox id with a source address; and
//! nothing in this module (or crate) logs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures::FutureExt;
use rand::TryRngCore;

use crate::limits::retry_after_secs;
use crate::state::{AppState, Mailbox, QueuedMsg};
use crate::wire;

pub fn router(state: Arc<AppState>) -> Router {
    let max_blob = state.cfg.max_blob_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/mailboxes", post(create_mailbox))
        .route(
            "/v1/mailboxes/{id}/messages",
            post(deposit).layer(DefaultBodyLimit::max(max_blob)),
        )
        .route(
            "/v1/mailboxes/{id}",
            axum::routing::delete(delete_mailbox).put(put_mailbox),
        )
        .route("/v1/mailboxes/{id}/ws", get(subscribe))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

fn too_many_requests() -> Response {
    let mut headers = HeaderMap::new();
    let secs = retry_after_secs().to_string();
    headers.insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&secs).expect("numeric header"),
    );
    (StatusCode::TOO_MANY_REQUESTS, headers).into_response()
}

/// The one 404 in this service: empty body, no differentiating detail —
/// unknown, expired, deleted, and malformed ids are indistinguishable.
fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

async fn create_mailbox(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if !state.src_limiter.admit_create(addr.ip()) {
        return too_many_requests();
    }
    match state.create_mailbox() {
        Some(id) => (
            StatusCode::CREATED,
            [(header::CONTENT_TYPE, "application/json")],
            format!("{{\"mailbox_id\":\"{id}\"}}"),
        )
            .into_response(),
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn deposit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if !wire::mailbox_id_shape_ok(&id) {
        return not_found();
    }
    if !state.src_limiter.admit_deposit(addr.ip()) {
        return too_many_requests();
    }
    // Blind admission: magic + version + minimum length, nothing further.
    if !wire::deposit_admissible(&body) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let mut boxes = state.boxes.lock().expect("boxes lock");
    let Some(mailbox) = boxes.get_mut(&id) else {
        return not_found();
    };
    if !state.box_limiter.admit_deposit(&id) {
        return too_many_requests();
    }
    if mailbox.queue.len() >= state.cfg.mailbox_max_messages
        || mailbox.queued_bytes + body.len() > state.cfg.mailbox_max_bytes
    {
        return StatusCode::INSUFFICIENT_STORAGE.into_response();
    }

    let mut msg_id = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut msg_id)
        .expect("OS CSPRNG unavailable");
    mailbox.queued_bytes += body.len();
    state.global_bytes.fetch_add(body.len(), Ordering::Relaxed);
    mailbox.queue.push_back(QueuedMsg {
        id: msg_id,
        bytes: body,
        deposited_at: Instant::now(),
    });
    mailbox.last_activity = Some(Instant::now());
    if let Some(notify) = &mailbox.notify {
        let _ = notify.send(());
    }
    StatusCode::ACCEPTED.into_response()
}

/// `PUT /v1/mailboxes/{id}` — idempotent create-at-client-specified-256-bit-id
/// (frozen §8, for §10.7 derived-recovery mailboxes). The response is
/// BYTE-IDENTICAL whether the mailbox was created or already existed (no
/// existence oracle, DELETE precedent); at the global cap it returns the
/// uniform capacity error regardless of existence. Per-source rate limit
/// (30/min default); NO per-mailbox limit (the id is caller-chosen and may not
/// exist yet). Counts against the global mailbox cap identically to POST.
async fn put_mailbox(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
) -> Response {
    // A malformed id is not a 256-bit mailbox id; reject on shape alone (no
    // server state consulted, so this leaks no existence information).
    if !wire::mailbox_id_shape_ok(&id) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if !state.src_limiter.admit_put(addr.ip()) {
        return too_many_requests();
    }
    if state.put_mailbox(&id) {
        // 201 + empty body for BOTH created and already-existing — identical.
        StatusCode::CREATED.into_response()
    } else {
        // Uniform capacity error at cap, regardless of id existence.
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

async fn delete_mailbox(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    // F3 (maintainer-approved): 204 unconditionally — the response is
    // byte-identical whether or not the mailbox existed. Note the capability
    // semantics documented in proto/relay-api.md: the only depositor to a
    // mailbox is the conversation peer, so peer-deletion harms only the
    // deleting party's own channel.
    if wire::mailbox_id_shape_ok(&id) {
        let removed = state.boxes.lock().expect("boxes lock").remove(&id);
        if let Some(mailbox) = removed {
            state
                .global_bytes
                .fetch_sub(mailbox.queued_bytes, Ordering::Relaxed);
            state.box_limiter.forget(&id);
            // A live subscriber discovers deletion on its next wake.
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn subscribe(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !wire::mailbox_id_shape_ok(&id) {
        return not_found();
    }
    {
        let boxes = state.boxes.lock().expect("boxes lock");
        if !boxes.contains_key(&id) {
            return not_found();
        }
    }
    if !state.box_limiter.admit_ws(&id) {
        return too_many_requests();
    }
    upgrade.on_upgrade(move |socket| deliver(state, id, socket))
}

/// Delivery loop: replay everything queued (at-least-once until acked),
/// then stream new deposits; acks delete. A newer subscriber replaces this
/// one (its notify sender is swapped out; we end on next wake).
async fn deliver(state: Arc<AppState>, id: String, mut socket: WebSocket) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    {
        let mut boxes = state.boxes.lock().expect("boxes lock");
        let Some(mailbox) = boxes.get_mut(&id) else {
            return;
        };
        mailbox.notify = Some(tx.clone());
        mailbox.last_activity = Some(Instant::now());
    }

    // Message ids already sent on THIS connection (avoid same-conn dupes;
    // a reconnect intentionally resends unacked messages). HashSet keeps the
    // per-iteration unsent scan O(queue), not O(queue·sent).
    let mut sent: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();

    loop {
        // Collect frames to send under the lock, send outside it.
        let frames: Vec<Vec<u8>> = {
            let mut boxes = state.boxes.lock().expect("boxes lock");
            let Some(mailbox) = boxes.get_mut(&id) else {
                return; // mailbox deleted or expired: close silently
            };
            if !mailbox.notify.as_ref().is_some_and(|n| n.same_channel(&tx)) {
                return; // replaced by a newer subscriber
            }
            mailbox
                .queue
                .iter()
                .filter(|m| !sent.contains(&m.id))
                .map(|m| wire::delivery_frame(&m.id, &m.bytes))
                .collect()
        };
        for frame in frames {
            let mut msg_id = [0u8; 16];
            msg_id.copy_from_slice(&frame[1..17]);
            if socket.send(Message::Binary(frame.into())).await.is_err() {
                return;
            }
            sent.insert(msg_id);
        }

        tokio::select! {
            wake = rx.recv() => {
                if wake.is_none() {
                    return;
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Binary(data))) => {
                        if !handle_ack(&state, &id, &data) {
                            // Non-ack binary frames are ignored: a blind relay
                            // has nothing useful to say about garbage.
                        }
                        // Drain any further acks already buffered on the socket
                        // so ack processing keeps pace with rapid delivery
                        // (bounds queue growth under sustained load).
                        while let Ok(Some(msg)) =
                            socket.recv().now_or_never().flatten().transpose()
                        {
                            match msg {
                                Message::Binary(more) => {
                                    handle_ack(&state, &id, &more);
                                }
                                Message::Close(_) => return,
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                    Some(Ok(_)) => {} // ping/pong/text: ignore
                }
            }
        }
    }
}

/// Removes an acked message from its mailbox. Returns true if `data` was a
/// well-formed ack (regardless of whether the id was still queued).
fn handle_ack(state: &Arc<AppState>, id: &str, data: &[u8]) -> bool {
    let Some(acked) = wire::parse_ack_frame(data) else {
        return false;
    };
    let mut boxes = state.boxes.lock().expect("boxes lock");
    if let Some(mailbox) = boxes.get_mut(id)
        && let Some(pos) = mailbox.queue.iter().position(|m| m.id == acked)
    {
        let removed = mailbox.queue.remove(pos).expect("indexed message");
        mailbox.queued_bytes -= removed.bytes.len();
        state
            .global_bytes
            .fetch_sub(removed.bytes.len(), Ordering::Relaxed);
        mailbox.last_activity = Some(Instant::now());
    }
    true
}

/// Registers a fresh mailbox entry — used only by tests via the public
/// binary; kept here to keep `Mailbox` construction local.
#[allow(dead_code)]
fn _mailbox_shape(_m: &Mailbox) {}
