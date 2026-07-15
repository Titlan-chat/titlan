// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! The relay client: per-conversation receive-sync over WebSocket, HTTP send
//! with pending-retry, reconnect/backoff, pairing, and §10.7 recovery. All
//! networking is async (tokio); crypto and storage are the synchronous
//! Phase-2 primitives. Kotlin drives this through [`crate::client`] (A3).

mod backoff;
mod http;
mod ws;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::TryRngCore;
use tokio::runtime::Handle;

use crate::client::{ConnectionObserver, ConnectionState, ConversationId, MessageReceiver};
use crate::config::PaddingProfile;
use crate::envelope::{InnerFrame, PayloadType};
use crate::storage::{Direction, Store, StoredMessage};
use crate::{CoreError, Result, identity, pairing, session};

use self::http::DepositOutcome;
use self::ws::Connected;

/// Shared sync state; cloned (via `Arc`) into every listener task.
pub(crate) struct Engine {
    store: Arc<Store>,
    my_relay: String,
    http: reqwest::Client,
    profile: PaddingProfile,
    handle: Handle,
    receiver: Mutex<Option<Arc<dyn MessageReceiver>>>,
    observer: Mutex<Option<Arc<dyn ConnectionObserver>>>,
    listening: Mutex<HashSet<ConversationId>>,
}

/// Outcome of a §10.7 recovery attempt.
enum Recovery {
    OneSided,
    Total,
    Failed,
}

impl Engine {
    pub(crate) fn new(store: Arc<Store>, my_relay: String, handle: Handle) -> Result<Arc<Self>> {
        ws::install_ring_provider();
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| CoreError::Network(e.to_string()))?;
        Ok(Arc::new(Engine {
            store,
            my_relay,
            http,
            profile: PaddingProfile::default_profile(),
            handle,
            receiver: Mutex::new(None),
            observer: Mutex::new(None),
            listening: Mutex::new(HashSet::new()),
        }))
    }

    pub(crate) fn set_callbacks(
        &self,
        observer: Arc<dyn ConnectionObserver>,
        receiver: Arc<dyn MessageReceiver>,
    ) {
        *self.observer.lock().expect("observer") = Some(observer);
        *self.receiver.lock().expect("receiver") = Some(receiver);
    }

    fn emit_state(&self, conv: ConversationId, state: ConnectionState) {
        if let Some(o) = self.observer.lock().expect("observer").clone() {
            o.on_state(conv, state);
        }
    }

    /// Spawns a receive listener for a conversation (idempotent).
    pub(crate) fn spawn_conversation(self: &Arc<Self>, conv: ConversationId) {
        if !self.listening.lock().expect("listening").insert(conv) {
            return;
        }
        let engine = self.clone();
        self.handle
            .spawn(async move { conversation_listener(engine, conv).await });
    }

    /// Spawns a listener on an exported pairing inbox.
    pub(crate) fn spawn_pairing(self: &Arc<Self>, pairing_inbox: String) {
        let engine = self.clone();
        self.handle
            .spawn(async move { pairing_listener(engine, pairing_inbox).await });
    }

    // ---- HTTP helpers ----

    pub(crate) async fn create_mailbox(&self) -> Result<String> {
        http::create_mailbox(&self.http, &self.my_relay).await
    }

    async fn deposit(&self, relay: &str, mailbox: &str, blob: &[u8]) -> Result<DepositOutcome> {
        http::deposit(&self.http, relay, mailbox, blob).await
    }

    // ---- pairing (initiator side) ----

    /// Processes a scanned payload and completes the pairing handshake,
    /// blocking until the peer's `mailbox-update/1` reply is received (so the
    /// conversation is fully routed on return). Returns the conversation id.
    pub(crate) async fn begin_pairing(&self, payload: &[u8]) -> Result<ConversationId> {
        let (bundle, peer_relay, pairing_inbox) = pairing::parse_pairing_payload(payload)?;
        let peer_addr = session::establish_session(&self.store, &bundle)?;
        let my_inbox = self.create_mailbox().await?;
        let conv =
            self.store
                .create_routed_conversation(&peer_addr, &peer_relay, None, &my_inbox)?;

        // Send pair-ack to the peer's single-use pairing inbox.
        let my_addr = identity::local_address(&self.store)?;
        let ack = InnerFrame {
            payload_type: PayloadType::PairAck,
            type_version: 1,
            payload: pairing::encode_pair_ack(&self.my_relay, &my_inbox, &my_addr),
        };
        let wire = session::encrypt_message(&self.store, &peer_addr, &ack, &self.profile)?;
        match self.deposit(&peer_relay, &pairing_inbox, &wire).await? {
            DepositOutcome::Accepted => {}
            DepositOutcome::NotFound => return Err(CoreError::PairingUnavailable),
            DepositOutcome::Other(s) => {
                return Err(CoreError::Network(format!("pair-ack deposit status {s}")));
            }
        }

        // Wait inline for the peer's mailbox-update (their conversation inbox).
        self.await_mailbox_update(&conv, &peer_addr, &my_inbox)
            .await?;

        // Hand the conversation to the ongoing sync.
        // (self is &Engine here; the client re-enters via spawn after return.)
        Ok(conv)
    }

    async fn await_mailbox_update(
        &self,
        conv: &ConversationId,
        peer_addr: &str,
        my_inbox: &str,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match ws::subscribe(&self.my_relay, my_inbox, None).await {
                Connected::Ok(mut sub) => loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(CoreError::Network("pairing reply timed out".into()));
                    }
                    match tokio::time::timeout(remaining, sub.next()).await {
                        Ok(Ok(Some((msg_id, envelope)))) => {
                            if let Ok(frame) = session::decrypt_message(
                                &self.store,
                                peer_addr,
                                &envelope,
                                &self.profile,
                            ) && frame.payload_type == PayloadType::MailboxUpdate
                                && let Ok((relay, inbox)) =
                                    pairing::parse_mailbox_update(&frame.payload)
                            {
                                self.store.set_conversation_send(conv, &relay, &inbox)?;
                                let _ = sub.ack(&msg_id).await;
                                return Ok(());
                            }
                            let _ = sub.ack(&msg_id).await;
                        }
                        Ok(Ok(None)) | Ok(Err(_)) => break, // reconnect
                        Err(_) => return Err(CoreError::Network("pairing reply timed out".into())),
                    }
                },
                Connected::NotFound => return Err(CoreError::PairingUnavailable),
                Connected::Unreachable => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(CoreError::Network(
                            "relay unreachable during pairing".into(),
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    // ---- pairing (responder side) ----

    /// Handles a `pair-ack/1` on a pairing inbox: creates the conversation and
    /// this side's inbox, retires the pairing inbox, and replies with a
    /// `mailbox-update/1`. Returns the new conversation id if handled.
    async fn handle_pair_ack(
        self: &Arc<Self>,
        pairing_inbox: &str,
        envelope: &[u8],
    ) -> Result<Option<ConversationId>> {
        let (peer_addr, frame) =
            session::decrypt_setup_from_unknown(&self.store, envelope, &self.profile)?;
        if frame.payload_type != PayloadType::PairAck {
            return Ok(None);
        }
        let coords = pairing::parse_pair_ack(&frame.payload)?;
        let my_inbox = self.create_mailbox().await?;
        let conv = self.store.create_routed_conversation(
            &peer_addr,
            &coords.relay_url,
            Some(&coords.inbox_id),
            &my_inbox,
        )?;

        // Retire the pairing inbox BEFORE replying, so a re-scan 404s
        // deterministically (stale-QR-dead).
        let _ = http::delete_mailbox(&self.http, &self.my_relay, pairing_inbox).await;

        // Announce this side's conversation inbox to the peer.
        let update = InnerFrame {
            payload_type: PayloadType::MailboxUpdate,
            type_version: 1,
            payload: pairing::encode_mailbox_update(&self.my_relay, &my_inbox),
        };
        let wire = session::encrypt_message(&self.store, &peer_addr, &update, &self.profile)?;
        let _ = self
            .deposit(&coords.relay_url, &coords.inbox_id, &wire)
            .await?;

        self.spawn_conversation(conv);
        Ok(Some(conv))
    }

    // ---- send / pending ----

    /// Queues a chat message (persisted `pending`) and attempts delivery.
    pub(crate) async fn send_chat(&self, conv: &ConversationId, text: &str) -> Result<()> {
        let frame = InnerFrame::chat_v1(text);
        self.store.save_outgoing(conv, &frame)?;
        let _ = self.flush_pending(conv).await; // best-effort; retried on reconnect
        Ok(())
    }

    async fn flush_pending(&self, conv: &ConversationId) -> Result<()> {
        let Some(convo) = self.store.get_conversation(conv)? else {
            return Ok(());
        };
        let (Some(relay_mailbox), relay) = (convo.mailbox_send, convo.relay_url) else {
            return Ok(()); // peer inbox not learned yet
        };
        for (msg_id, frame) in self.store.pending_chat(conv)? {
            let wire =
                session::encrypt_message(&self.store, &convo.peer_address, &frame, &self.profile)?;
            match self.deposit(&relay, &relay_mailbox, &wire).await? {
                DepositOutcome::Accepted => self.store.mark_message_sent(&msg_id)?,
                _ => break, // relay down / peer inbox gone → leave pending
            }
        }
        Ok(())
    }

    // ---- receive / dispatch ----

    async fn handle_incoming(&self, conv: &ConversationId, peer_addr: &str, envelope: &[u8]) {
        let Ok(frame) = session::decrypt_message(&self.store, peer_addr, envelope, &self.profile)
        else {
            return; // undecryptable / replay → drop
        };
        match frame.payload_type {
            PayloadType::Chat => {
                if let Ok(id) = self.store.save_incoming(conv, &frame) {
                    let msg = StoredMessage {
                        id,
                        conversation_id: *conv,
                        direction: Direction::Incoming,
                        payload_type: frame.payload_type as u8,
                        type_version: frame.type_version,
                        body: frame.payload,
                    };
                    if let Some(r) = self.receiver.lock().expect("receiver").clone() {
                        r.on_message(*conv, msg);
                    }
                }
            }
            PayloadType::MailboxUpdate => {
                if let Ok((relay, inbox)) = pairing::parse_mailbox_update(&frame.payload) {
                    let _ = self.store.set_conversation_send(conv, &relay, &inbox);
                    let _ = self.flush_pending(conv).await;
                }
            }
            _ => {} // pair-ack / reserved types are not expected on a conv inbox
        }
    }

    // ---- §10.7 recovery ----

    async fn recover(&self, conv: &ConversationId) -> Recovery {
        let Ok(Some(convo)) = self.store.get_conversation(conv) else {
            return Recovery::Failed;
        };
        let Ok(new_inbox) = self.create_mailbox().await else {
            return Recovery::Failed;
        };
        if self.store.set_conversation_recv(conv, &new_inbox).is_err() {
            return Recovery::Failed;
        }
        let Some(send) = convo.mailbox_send else {
            return Recovery::Total; // never learned the peer's inbox
        };
        let update = InnerFrame {
            payload_type: PayloadType::MailboxUpdate,
            type_version: 1,
            payload: pairing::encode_mailbox_update(&self.my_relay, &new_inbox),
        };
        let Ok(wire) =
            session::encrypt_message(&self.store, &convo.peer_address, &update, &self.profile)
        else {
            return Recovery::Failed;
        };
        match self.deposit(&convo.relay_url, &send, &wire).await {
            Ok(DepositOutcome::Accepted) => Recovery::OneSided,
            Ok(DepositOutcome::NotFound) => Recovery::Total, // peer inbox also gone
            _ => Recovery::Failed,
        }
    }
}

/// Per-conversation receive loop: subscribe → deliver/ack → reconnect, with
/// §10.7 recovery on a 404 for this side's inbox.
async fn conversation_listener(engine: Arc<Engine>, conv: ConversationId) {
    let mut backoff = backoff::Backoff::new(random_seed());
    loop {
        let Ok(Some(convo)) = engine.store.get_conversation(&conv) else {
            return;
        };
        let Some(recv) = convo.mailbox_recv.clone() else {
            return;
        };
        engine.emit_state(conv, ConnectionState::Connecting);
        match ws::subscribe(&engine.my_relay, &recv, convo.relay_pin).await {
            Connected::Ok(mut sub) => {
                backoff.reset();
                engine.emit_state(conv, ConnectionState::Online);
                let _ = engine.flush_pending(&conv).await;
                while let Ok(Some((msg_id, envelope))) = sub.next().await {
                    engine
                        .handle_incoming(&conv, &convo.peer_address, &envelope)
                        .await;
                    let _ = sub.ack(&msg_id).await;
                }
                engine.emit_state(conv, ConnectionState::Offline);
                let d = backoff.next_delay();
                engine.emit_state(
                    conv,
                    ConnectionState::Backoff {
                        secs: backoff.current_secs(),
                    },
                );
                tokio::time::sleep(d).await;
            }
            Connected::NotFound => match engine.recover(&conv).await {
                Recovery::OneSided => {
                    engine.emit_state(conv, ConnectionState::Recovering);
                    backoff.reset();
                }
                Recovery::Total => {
                    engine.emit_state(conv, ConnectionState::RePairRequired);
                    return;
                }
                Recovery::Failed => {
                    let d = backoff.next_delay();
                    tokio::time::sleep(d).await;
                }
            },
            Connected::Unreachable => {
                engine.emit_state(conv, ConnectionState::Offline);
                let d = backoff.next_delay();
                engine.emit_state(
                    conv,
                    ConnectionState::Backoff {
                        secs: backoff.current_secs(),
                    },
                );
                tokio::time::sleep(d).await;
            }
        }
    }
}

/// Listens on an exported pairing inbox for the first `pair-ack/1`, then stops.
async fn pairing_listener(engine: Arc<Engine>, pairing_inbox: String) {
    loop {
        match ws::subscribe(&engine.my_relay, &pairing_inbox, None).await {
            Connected::Ok(mut sub) => {
                while let Ok(Some((msg_id, envelope))) = sub.next().await {
                    let handled = matches!(
                        engine.handle_pair_ack(&pairing_inbox, &envelope).await,
                        Ok(Some(_))
                    );
                    let _ = sub.ack(&msg_id).await;
                    if handled {
                        return; // pairing complete
                    }
                }
            }
            Connected::NotFound => return, // inbox retired
            Connected::Unreachable => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

fn random_seed() -> u64 {
    let mut b = [0u8; 8];
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .expect("OS CSPRNG unavailable");
    u64::from_le_bytes(b)
}
