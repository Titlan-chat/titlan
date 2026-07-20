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
use crate::pairing::{PAIRING_SECRET_LEN, RECOVERY_CONTRIB_LEN};
use crate::storage::{Direction, Store, StoredMessage};
use crate::{CoreError, Result, identity, pairing, session};

use self::http::DepositOutcome;
use self::ws::Connected;

/// Recovery/pairing role codes stored in schema v3 (`recovery_role`) and mixed
/// into the derived-mailbox `role_label` (`crate::recovery::Role`).
const ROLE_OFFERER: u8 = 0;
const ROLE_RESPONDER: u8 = 1;

/// Per-conversation ring of seen `(generation, nonce)` recovery-hello pairs.
type HelloSeen =
    std::collections::HashMap<ConversationId, std::collections::VecDeque<(u32, [u8; 16])>>;

/// Offerer-side rotation state (frozen §8 Rotation ordering). After the offerer
/// sends `/3{F_A}` it STAYS on its derived inbox (draining any in-flight chat)
/// and awaits the responder's `/3{F_B}` THERE; on receipt it switches receives
/// to `F_A`, points sends at `F_B`, and deletes the derived inbox.
struct OffererAwaitingFb {
    /// The fresh relay-generated inbox the offerer will receive on after F_B.
    f_a: String,
    /// The offerer's derived inbox, kept subscribed until the second leg lands.
    derived_recv: String,
}

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
    /// In-flight offerer rotations (per conversation).
    rotation: Mutex<std::collections::HashMap<ConversationId, OffererAwaitingFb>>,
    /// `recovery-hello` replay dedup by `(generation, nonce)`, per conversation
    /// (ratified retention: bounded ring, oldest-evicted).
    hello_seen: Mutex<HelloSeen>,
    /// Per-conversation §8 exhaustion tracking: probe cycles with no verified
    /// peer contact (3 → needs-repair); relay 429s are pacing, never counted.
    exhaustion:
        Mutex<std::collections::HashMap<ConversationId, crate::recovery::ExhaustionTracker>>,
}

/// Outcome of a §10.7 recovery attempt.
enum Recovery {
    OneSided,
    Total,
    /// v2 derived-mailbox recovery is exhausted (generation offset ≥ W): the
    /// conversation needs re-pair (frozen §8).
    NeedsRepair,
    Failed,
}

impl Engine {
    pub(crate) fn new(store: Arc<Store>, my_relay: String, handle: Handle) -> Result<Arc<Self>> {
        ws::install_ring_provider();
        let http = ws::build_http_client()?;
        Ok(Arc::new(Engine {
            store,
            my_relay,
            http,
            profile: PaddingProfile::default_profile(),
            handle,
            receiver: Mutex::new(None),
            observer: Mutex::new(None),
            listening: Mutex::new(HashSet::new()),
            rotation: Mutex::new(std::collections::HashMap::new()),
            hello_seen: Mutex::new(std::collections::HashMap::new()),
            exhaustion: Mutex::new(std::collections::HashMap::new()),
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

    fn emit_needs_repair(&self, conv: ConversationId) {
        if let Some(o) = self.observer.lock().expect("observer").clone() {
            o.on_conversation_needs_repair(conv);
        }
    }

    fn emit_permanent_send_failure(&self, conv: ConversationId, msg_id: [u8; 16]) {
        if let Some(o) = self.observer.lock().expect("observer").clone() {
            o.on_permanent_send_failure(conv, msg_id);
        }
    }

    fn emit_storage_error(&self, detail: &str) {
        if let Some(o) = self.observer.lock().expect("observer").clone() {
            o.on_storage_error(detail);
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

    // ---- HTTP helpers ----

    pub(crate) async fn create_mailbox(&self) -> Result<String> {
        http::create_mailbox(&self.http, &self.my_relay).await
    }

    async fn deposit(&self, relay: &str, mailbox: &str, blob: &[u8]) -> Result<DepositOutcome> {
        http::deposit(&self.http, relay, mailbox, blob).await
    }

    // ---- pairing v2 (offer + proof-of-scan; frozen §3, B1/B2) ----

    /// Offerer (A): create the single-use pairing inbox, mint a 256-bit pairing
    /// secret, spawn the v2 listener bound to that secret, and return the offer
    /// bytes (bundle + relay + inbox + secret). B2: the recovery-root
    /// contribution is NOT in the offer.
    pub(crate) async fn export_offer(self: &Arc<Self>, bundle: &[u8]) -> Result<Vec<u8>> {
        let pairing_inbox = self.create_mailbox().await?;
        let secret = random_32();
        self.spawn_pairing_v2(pairing_inbox.clone(), secret);
        Ok(pairing::encode_pairing_offer(
            bundle,
            &self.my_relay,
            &pairing_inbox,
            &secret,
        ))
    }

    /// Spawns the v2 pairing listener bound to the offer's secret.
    fn spawn_pairing_v2(self: &Arc<Self>, pairing_inbox: String, secret: [u8; PAIRING_SECRET_LEN]) {
        let engine = self.clone();
        self.handle
            .spawn(async move { pairing_listener_v2(engine, pairing_inbox, secret).await });
    }

    /// Responder (B): consume a scanned offer — PQXDH against A's bundle, create
    /// B's inbox, mint B's recovery contribution, send `pair-ack/2` (bundle +
    /// coords + contribution + proof-of-scan MAC) to A's pairing inbox, then
    /// await A's `inbox-handoff` (`mailbox-update/2`, carrying A's contribution)
    /// and compute the shared recovery root. Returns the conversation id.
    pub(crate) async fn begin_pairing_from_offer(&self, payload: &[u8]) -> Result<ConversationId> {
        let (bundle, peer_relay, pairing_inbox, secret) = pairing::parse_pairing_offer(payload)?;
        let peer_addr = session::establish_session(&self.store, &bundle)?;
        let my_inbox = self.create_mailbox().await?;
        let conv =
            self.store
                .create_routed_conversation(&peer_addr, &peer_relay, None, &my_inbox)?;

        // B is the responder. Persist role + B's recovery-root contribution.
        let b_contrib = random_32();
        self.store
            .set_recovery_pairing(&conv, ROLE_RESPONDER, &b_contrib)?;

        // pair-ack/2: B's own bundle + reply coords + contribution + proof.
        let my_bundle = identity::export_prekey_bundle(&self.store)?;
        let ack = InnerFrame {
            payload_type: PayloadType::PairAck,
            type_version: pairing::PAIR_ACK_V2,
            payload: pairing::encode_pair_ack_v2(
                &my_bundle,
                &self.my_relay,
                &my_inbox,
                &b_contrib,
                &secret,
            ),
        };
        let wire = session::encrypt_message(&self.store, &peer_addr, &ack, &self.profile)?;
        match self.deposit(&peer_relay, &pairing_inbox, &wire).await? {
            DepositOutcome::Accepted => {}
            DepositOutcome::NotFound => return Err(CoreError::PairingUnavailable),
            DepositOutcome::Other(s) => {
                return Err(CoreError::Network(format!("pair-ack/2 deposit status {s}")));
            }
        }

        self.await_inbox_handoff_v2(&conv, &peer_addr, &my_inbox, &b_contrib)
            .await?;
        Ok(conv)
    }

    /// Offerer (A) side: handle a `pair-ack/2` on the pairing inbox. Verifies
    /// proof-of-scan (constant-time; `ProofOfScanFailed` burns the offer),
    /// creates the conversation, computes+persists the recovery root, retires
    /// the pairing inbox, and hands off A's inbox + contribution via
    /// `inbox-handoff` (`mailbox-update/2`).
    async fn handle_pair_ack_v2(
        self: &Arc<Self>,
        pairing_inbox: &str,
        secret: &[u8; PAIRING_SECRET_LEN],
        envelope: &[u8],
    ) -> Result<Option<ConversationId>> {
        let (peer_addr, frame) =
            session::decrypt_setup_from_unknown(&self.store, envelope, &self.profile)?;
        if frame.payload_type != PayloadType::PairAck || frame.type_version != pairing::PAIR_ACK_V2
        {
            return Ok(None);
        }
        let ack = pairing::parse_pair_ack_v2(&frame.payload)?;
        // Proof-of-scan: mismatch ⇒ ProofOfScanFailed (caller burns the offer).
        pairing::verify_proof_of_scan(
            secret,
            &ack.responder_bundle,
            &ack.root_contribution,
            &ack.proof,
        )?;

        let my_inbox = self.create_mailbox().await?;
        let conv = self.store.create_routed_conversation(
            &peer_addr,
            &ack.relay_url,
            Some(&ack.inbox_id),
            &my_inbox,
        )?;

        // A is the offerer. Persist role + A's contribution, compute the shared
        // root = HMAC(A_contribution, B_contribution).
        let a_contrib = random_32();
        self.store
            .set_recovery_pairing(&conv, ROLE_OFFERER, &a_contrib)?;
        let root = crate::recovery::derive_root(&a_contrib, &ack.root_contribution);
        self.store
            .set_recovery_root(&conv, &ack.root_contribution, &root)?;

        // Retire the pairing inbox (stale-QR-dead) before handing off.
        let _ = http::delete_mailbox(&self.http, &self.my_relay, pairing_inbox).await;

        // inbox-handoff (mailbox-update/2): A's long-lived inbox + A's contrib.
        let handoff = InnerFrame {
            payload_type: PayloadType::MailboxUpdate,
            type_version: pairing::MAILBOX_UPDATE_V2,
            payload: pairing::encode_mailbox_update_v2(&self.my_relay, &my_inbox, &a_contrib),
        };
        let wire = session::encrypt_message(&self.store, &peer_addr, &handoff, &self.profile)?;
        let _ = self.deposit(&ack.relay_url, &ack.inbox_id, &wire).await?;

        self.spawn_conversation(conv);
        Ok(Some(conv))
    }

    /// Responder (B): wait inline for A's `inbox-handoff` (`mailbox-update/2`)
    /// on B's inbox, record A's send coordinates, and compute+persist the shared
    /// recovery root from A's contribution and B's own.
    async fn await_inbox_handoff_v2(
        &self,
        conv: &ConversationId,
        peer_addr: &str,
        my_inbox: &str,
        b_contrib: &[u8; RECOVERY_CONTRIB_LEN],
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match ws::subscribe(&self.my_relay, my_inbox, None).await {
                Connected::Ok(mut sub) => loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(CoreError::Network("pairing handoff timed out".into()));
                    }
                    match tokio::time::timeout(remaining, sub.next()).await {
                        Ok(Ok(Some((msg_id, envelope)))) => {
                            if let Ok(frame) = session::decrypt_message(
                                &self.store,
                                peer_addr,
                                &envelope,
                                &self.profile,
                            ) && frame.payload_type == PayloadType::MailboxUpdate
                                && frame.type_version == pairing::MAILBOX_UPDATE_V2
                                && let Ok((relay, inbox, a_contrib)) =
                                    pairing::parse_mailbox_update_v2(&frame.payload)
                            {
                                self.store.set_conversation_send(conv, &relay, &inbox)?;
                                let root = crate::recovery::derive_root(&a_contrib, b_contrib);
                                self.store.set_recovery_root(conv, &a_contrib, &root)?;
                                let _ = sub.ack(&msg_id).await;
                                return Ok(());
                            }
                            let _ = sub.ack(&msg_id).await;
                        }
                        Ok(Ok(None)) | Ok(Err(_)) => break,
                        Err(_) => {
                            return Err(CoreError::Network("pairing handoff timed out".into()));
                        }
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

    // ---- send / pending ----

    /// Queues a chat message (persisted `pending`) and attempts delivery.
    pub(crate) async fn send_chat(&self, conv: &ConversationId, text: &str) -> Result<()> {
        let frame = InnerFrame::chat_v1(text);
        self.store.save_outgoing(conv, &frame)?;
        let _ = self.flush_pending(conv).await; // best-effort; retried on reconnect
        Ok(())
    }

    async fn flush_pending(&self, conv: &ConversationId) -> Result<()> {
        let convo = match self.store.get_conversation(conv) {
            Ok(Some(c)) => c,
            Ok(None) => return Ok(()),
            Err(e) => {
                self.emit_storage_error(&e.to_string());
                return Err(e);
            }
        };
        let (Some(relay_mailbox), relay) = (convo.mailbox_send, convo.relay_url) else {
            return Ok(()); // peer inbox not learned yet
        };
        let pending = match self.store.pending_chat(conv) {
            Ok(p) => p,
            Err(e) => {
                self.emit_storage_error(&e.to_string());
                return Err(e);
            }
        };
        for (msg_id, frame) in pending {
            let wire =
                session::encrypt_message(&self.store, &convo.peer_address, &frame, &self.profile)?;
            match self.deposit(&relay, &relay_mailbox, &wire).await? {
                DepositOutcome::Accepted => self.store.mark_message_sent(&msg_id)?,
                // 400 (malformed) / 413 (too large): the relay will NEVER accept
                // this blob — permanent failure. Mark it sent so it stops
                // retrying, and surface it (frozen §1). NotFound / other = a
                // transient outage → leave pending, retry on reconnect.
                DepositOutcome::Other(400) | DepositOutcome::Other(413) => {
                    let _ = self.store.mark_message_sent(&msg_id);
                    self.emit_permanent_send_failure(*conv, msg_id);
                }
                _ => break,
            }
        }
        Ok(())
    }

    // ---- receive / dispatch ----

    /// Dispatches a decrypted inbound frame. Returns `true` when this side's
    /// `mailbox_recv` changed (recovery generation adoption or rotation) and the
    /// listener must re-subscribe immediately.
    async fn handle_incoming(
        &self,
        conv: &ConversationId,
        peer_addr: &str,
        envelope: &[u8],
    ) -> bool {
        let Ok(frame) = session::decrypt_message(&self.store, peer_addr, envelope, &self.profile)
        else {
            return false; // undecryptable / replay → drop
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
                false
            }
            PayloadType::MailboxUpdate => {
                if frame.type_version == pairing::MAILBOX_UPDATE_V3 {
                    self.handle_rotation(conv, &frame.payload).await
                } else {
                    // v1 mailbox-update/1 (one-sided recovery for v1 conversations).
                    if let Ok((relay, inbox)) = pairing::parse_mailbox_update(&frame.payload) {
                        let _ = self.store.set_conversation_send(conv, &relay, &inbox);
                        let _ = self.flush_pending(conv).await;
                    }
                    false
                }
            }
            PayloadType::RecoveryHello => self.handle_recovery_hello(conv, &frame.payload).await,
            _ => false, // pair-ack / reserved types are not expected on a conv inbox
        }
    }

    // ---- §10.7 recovery ----

    /// Recovery dispatch (frozen §8, ratified branching): a conversation with a
    /// recovery ROOT present (v2) recovers via derived mailboxes; one without
    /// (v1) keeps the Phase-4a one-sided `mailbox-update/1` behavior, and total
    /// loss surfaces re-pair (v1 conversations are re-pair-only, permanently).
    async fn recover(&self, conv: &ConversationId) -> Recovery {
        let Ok(Some(convo)) = self.store.get_conversation(conv) else {
            return Recovery::Failed;
        };
        match self.store.recovery_state(conv) {
            Ok(Some(rec)) => match (rec.role, rec.root) {
                (Some(role), Some(root)) => {
                    self.recover_v2(conv, &convo, role, &root, rec.own_gen, rec.peer_gen)
                        .await
                }
                _ => self.recover_v1(conv, &convo).await,
            },
            _ => self.recover_v1(conv, &convo).await,
        }
    }

    /// v1 (Phase 4a) one-sided in-band recovery via `mailbox-update/1`; total
    /// loss → re-pair.
    async fn recover_v1(
        &self,
        conv: &ConversationId,
        convo: &crate::storage::Conversation,
    ) -> Recovery {
        let Ok(new_inbox) = self.create_mailbox().await else {
            return Recovery::Failed;
        };
        if self.store.set_conversation_recv(conv, &new_inbox).is_err() {
            return Recovery::Failed;
        }
        let Some(send) = convo.mailbox_send.clone() else {
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

    /// v2 derived-mailbox recovery (frozen §8). Both parties, on loss, bump
    /// their generation and switch routing to the per-conversation DERIVED
    /// inboxes for that generation — the sender's `role_label` inbox is the
    /// peer's receive target, the receiver's own `role_label` inbox is where it
    /// subscribes. Both PUT-CREATE the derived inboxes before use (deposit and
    /// subscribe 404 on unknown ids and never create), so whichever side
    /// recovers first makes both inboxes real; then an idempotent
    /// `recovery-hello` announces verified contact + generation. Same-generation
    /// convergence (the single-total-loss case) needs no further coordination;
    /// generation windowing for double-restart desync and rotation-to-fresh are
    /// the remaining §8 work (flagged).
    async fn recover_v2(
        &self,
        conv: &ConversationId,
        convo: &crate::storage::Conversation,
        own_role: u8,
        root: &[u8; RECOVERY_CONTRIB_LEN],
        own_gen: u32,
        peer_gen: u32,
    ) -> Recovery {
        // Exhaustion (frozen §8), two conditions → conversation-needs-repair:
        //  (1) relative generation offset ≥ W (unrecoverable in-band); or
        //  (2) 3 probe cycles with no verified peer contact (peer offline).
        //      A verified recovery-hello resets the cycle counter; relay 429s
        //      are pacing and never counted (they are absorbed by put_create).
        let exhausted_cycles = {
            let mut map = self.exhaustion.lock().expect("exhaustion");
            let t = map
                .entry(*conv)
                .or_insert_with(crate::recovery::ExhaustionTracker::new);
            t.note_probe_cycle();
            t.is_exhausted()
        };
        if exhausted_cycles
            || (crate::recovery::GenerationState {
                own: own_gen,
                peer: peer_gen,
            })
            .is_exhausted()
        {
            return Recovery::NeedsRepair;
        }

        // Bump generation on loss, then enter recovery at the new generation.
        let g = own_gen.saturating_add(1);
        if self
            .enter_recovery_gen(conv, convo, own_role, root, g, peer_gen)
            .await
        {
            Recovery::OneSided
        } else {
            Recovery::Failed
        }
    }

    /// Sets up derived-mailbox routing at generation `g`: PUT-create + subscribe
    /// (via `mailbox_recv`) this side's derived inbox, PUT-create the peer's
    /// derived inboxes across `[peer_g … peer_g+(W-1)]` and deposit an idempotent
    /// `recovery-hello` into each (429 = pacing, never fatal), and point sends at
    /// the peer's derived inbox at `g`. Shared by loss detection and generation
    /// adoption. `false` on a storage/PUT failure of this side's own inbox.
    async fn enter_recovery_gen(
        &self,
        conv: &ConversationId,
        convo: &crate::storage::Conversation,
        own_role: u8,
        root: &[u8; RECOVERY_CONTRIB_LEN],
        g: u32,
        peer_gen: u32,
    ) -> bool {
        let own = role_from_u8(own_role);
        let peer = role_from_u8(peer_role_u8(own_role));
        let own_recv = crate::recovery::derive_mailbox_id(root, own, g);
        if !self.put_create(&self.my_relay, &own_recv).await
            || self.store.set_conversation_recv(conv, &own_recv).is_err()
        {
            return false;
        }
        let mut nonce = [0u8; crate::recovery::RECOVERY_HELLO_NONCE_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .expect("OS CSPRNG unavailable");
        let hello = InnerFrame {
            payload_type: PayloadType::RecoveryHello,
            type_version: crate::recovery::RECOVERY_HELLO_VERSION,
            payload: crate::recovery::encode_recovery_hello(g, &nonce),
        };
        let window = (crate::recovery::GenerationState {
            own: g,
            peer: peer_gen,
        })
        .outbound_window();
        for k in &window {
            let peer_inbox = crate::recovery::derive_mailbox_id(root, peer, *k);
            if self.put_create(&convo.relay_url, &peer_inbox).await
                && let Ok(wire) = session::encrypt_message(
                    &self.store,
                    &convo.peer_address,
                    &hello,
                    &self.profile,
                )
            {
                let _ = self.deposit(&convo.relay_url, &peer_inbox, &wire).await;
            }
        }
        let peer_send = crate::recovery::derive_mailbox_id(root, peer, g);
        let _ = self
            .store
            .set_conversation_send(conv, &convo.relay_url, &peer_send);
        let _ = self.store.set_recovery_generations(conv, g, peer_gen);
        true
    }

    /// Records a `(generation, nonce)` and returns `true` if it is NEW (not a
    /// replay). Bounded ring per conversation (ratified retention; oldest-evicted).
    fn mark_hello_seen(&self, conv: &ConversationId, generation: u32, nonce: [u8; 16]) -> bool {
        let mut map = self.hello_seen.lock().expect("hello_seen");
        let ring = map.entry(*conv).or_default();
        if ring.iter().any(|(g, n)| *g == generation && *n == nonce) {
            return false;
        }
        ring.push_back((generation, nonce));
        while ring.len() > 512 {
            ring.pop_front();
        }
        true
    }

    /// Handles a verified `recovery-hello`: dedup, adopt `max(g)`, and — once
    /// converged — the OFFERER initiates the role-ordered rotation. Returns
    /// `true` when this side's `mailbox_recv` changed and the listener must
    /// re-subscribe.
    async fn handle_recovery_hello(&self, conv: &ConversationId, payload: &[u8]) -> bool {
        let Ok((reported_gen, nonce)) = crate::recovery::parse_recovery_hello(payload) else {
            return false;
        };
        if !self.mark_hello_seen(conv, reported_gen, nonce) {
            return false; // replay
        }
        let Ok(Some(rec)) = self.store.recovery_state(conv) else {
            return false;
        };
        let (Some(role), Some(root)) = (rec.role, rec.root) else {
            return false;
        };
        // Verified in-band contact → reset the exhaustion cycle counter.
        if let Some(t) = self.exhaustion.lock().expect("exhaustion").get_mut(conv) {
            t.reset();
        }
        // Convergence: adopt max(own, reported). `bumped` = own generation moved.
        let mut gs = crate::recovery::GenerationState {
            own: rec.own_gen,
            peer: rec.peer_gen,
        };
        let bumped = gs.converge(reported_gen);
        let _ = self.store.set_recovery_generations(conv, gs.own, gs.peer);
        let Ok(Some(convo)) = self.store.get_conversation(conv) else {
            return false;
        };
        if bumped {
            // Behind the peer: adopt the higher generation and re-run recovery.
            return self
                .enter_recovery_gen(conv, &convo, role, &root, gs.own, gs.peer)
                .await;
        }
        if reported_gen == gs.own && role == ROLE_OFFERER {
            return self
                .initiate_rotation(conv, &convo, role, &root, gs.own)
                .await;
        }
        let _ = self.flush_pending(conv).await;
        false
    }

    /// Offerer-only: mint `F_A`, send `mailbox-update/3{F_A}` into the
    /// responder's derived inbox at `generation`, and STAY subscribed on the
    /// offerer's own derived inbox (draining in-flight chat) awaiting `F_B`
    /// there. Returns `false` — the offerer does NOT re-subscribe yet.
    async fn initiate_rotation(
        &self,
        conv: &ConversationId,
        convo: &crate::storage::Conversation,
        own_role: u8,
        root: &[u8; RECOVERY_CONTRIB_LEN],
        generation: u32,
    ) -> bool {
        let derived_recv =
            crate::recovery::derive_mailbox_id(root, role_from_u8(own_role), generation);
        let peer_derived = crate::recovery::derive_mailbox_id(
            root,
            role_from_u8(peer_role_u8(own_role)),
            generation,
        );
        let Ok(f_a) = self.create_mailbox().await else {
            return false;
        };
        let handoff = InnerFrame {
            payload_type: PayloadType::MailboxUpdate,
            type_version: pairing::MAILBOX_UPDATE_V3,
            payload: pairing::encode_mailbox_update_v3(&self.my_relay, &f_a),
        };
        if let Ok(wire) =
            session::encrypt_message(&self.store, &convo.peer_address, &handoff, &self.profile)
        {
            let _ = self.deposit(&convo.relay_url, &peer_derived, &wire).await;
        }
        self.rotation
            .lock()
            .expect("rotation")
            .insert(*conv, OffererAwaitingFb { f_a, derived_recv });
        false // stay on the derived inbox until F_B lands
    }

    /// Handles a `mailbox-update/3` rotation handoff.
    /// - Offerer (awaiting `F_B`, still on its derived inbox): adopt `F_B` as the
    ///   send target, switch receives to `F_A`, delete the derived inbox
    ///   (implicit ack), re-subscribe to `F_A`.
    /// - Responder (first leg `F_A`, on its derived inbox): adopt `F_A`, mint
    ///   `F_B`, reply `/3{F_B}` to the OFFERER'S derived inbox (so the offerer
    ///   drains in-flight chat before switching), delete its own derived inbox,
    ///   re-subscribe to `F_B`.
    async fn handle_rotation(&self, conv: &ConversationId, payload: &[u8]) -> bool {
        let Ok((relay, inbox)) = pairing::parse_mailbox_update_v3(payload) else {
            return false;
        };
        let awaiting = self.rotation.lock().expect("rotation").remove(conv);
        if let Some(OffererAwaitingFb { f_a, derived_recv }) = awaiting {
            let _ = self.store.set_conversation_send(conv, &relay, &inbox); // send → F_B
            let _ = self.store.set_conversation_recv(conv, &f_a); // recv → F_A
            let _ = http::delete_mailbox(&self.http, &self.my_relay, &derived_recv).await;
            let _ = self.flush_pending(conv).await;
            return true; // re-subscribe to F_A
        }
        // Responder path.
        let Ok(Some(rec)) = self.store.recovery_state(conv) else {
            return false;
        };
        let (Some(role), Some(root)) = (rec.role, rec.root) else {
            return false;
        };
        let Ok(Some(convo)) = self.store.get_conversation(conv) else {
            return false;
        };
        let own_derived_recv = convo.mailbox_recv.clone();
        // The offerer's derived inbox at the converged generation (where it is
        // still subscribed) — reply there, NOT to F_A.
        let offerer_derived = crate::recovery::derive_mailbox_id(
            &root,
            role_from_u8(peer_role_u8(role)),
            rec.own_gen,
        );
        let _ = self.store.set_conversation_send(conv, &relay, &inbox); // send → F_A
        let Ok(f_b) = self.create_mailbox().await else {
            return false;
        };
        if self.store.set_conversation_recv(conv, &f_b).is_err() {
            return false;
        }
        let reply = InnerFrame {
            payload_type: PayloadType::MailboxUpdate,
            type_version: pairing::MAILBOX_UPDATE_V3,
            payload: pairing::encode_mailbox_update_v3(&self.my_relay, &f_b),
        };
        if let Ok(wire) =
            session::encrypt_message(&self.store, &convo.peer_address, &reply, &self.profile)
        {
            let _ = self
                .deposit(&convo.relay_url, &offerer_derived, &wire)
                .await;
        }
        if let Some(dr) = own_derived_recv {
            let _ = http::delete_mailbox(&self.http, &self.my_relay, &dr).await;
        }
        let _ = self.flush_pending(conv).await;
        true // re-subscribe to F_B
    }

    /// PUT-creates a mailbox at `id`; `true` iff it exists after (201). A 429 is
    /// pacing (returns false → the caller backs off, NOT an exhaustion count).
    async fn put_create(&self, relay: &str, id: &str) -> bool {
        matches!(
            http::put_mailbox(&self.http, relay, id).await,
            Ok(http::PutOutcome::Created)
        )
    }
}

/// Maps the stored `recovery_role` code to the derived-mailbox role.
fn role_from_u8(role: u8) -> crate::recovery::Role {
    if role == ROLE_OFFERER {
        crate::recovery::Role::Offerer
    } else {
        crate::recovery::Role::Responder
    }
}

fn peer_role_u8(own_role: u8) -> u8 {
    if own_role == ROLE_OFFERER {
        ROLE_RESPONDER
    } else {
        ROLE_OFFERER
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
                let mut reconnect = false;
                while let Ok(Some((msg_id, envelope))) = sub.next().await {
                    let changed = engine
                        .handle_incoming(&conv, &convo.peer_address, &envelope)
                        .await;
                    let _ = sub.ack(&msg_id).await;
                    if changed {
                        reconnect = true;
                        break;
                    }
                }
                if reconnect {
                    // recovery generation adoption / rotation moved mailbox_recv;
                    // re-read the conversation and re-subscribe immediately.
                    continue;
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
                    // v1 total loss → re-pair (v1 conversations are re-pair-only).
                    engine.emit_state(conv, ConnectionState::RePairRequired);
                    engine.emit_needs_repair(conv);
                    return;
                }
                Recovery::NeedsRepair => {
                    // v2 exhaustion (offset ≥ W, or 3-cycle bound): re-pair is
                    // the surfaced last resort (frozen §1/§8).
                    engine.emit_state(conv, ConnectionState::RePairRequired);
                    engine.emit_needs_repair(conv);
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

/// v2 pairing listener: waits for a `pair-ack/2` on the offer's pairing inbox,
/// verifies proof-of-scan, and completes the handshake. A proof-of-scan failure
/// BURNS the offer (retire the inbox, stop). Otherwise a completed pairing ends
/// the listener; unrelated frames are ignored (the offer stands until TTL).
async fn pairing_listener_v2(
    engine: Arc<Engine>,
    pairing_inbox: String,
    secret: [u8; PAIRING_SECRET_LEN],
) {
    loop {
        match ws::subscribe(&engine.my_relay, &pairing_inbox, None).await {
            Connected::Ok(mut sub) => {
                while let Ok(Some((msg_id, envelope))) = sub.next().await {
                    match engine
                        .handle_pair_ack_v2(&pairing_inbox, &secret, &envelope)
                        .await
                    {
                        Ok(Some(_)) => {
                            let _ = sub.ack(&msg_id).await;
                            return; // pairing complete
                        }
                        Err(CoreError::ProofOfScanFailed) => {
                            // Burn the offer: a bad return is evidence of leak.
                            let _ = sub.ack(&msg_id).await;
                            let _ = http::delete_mailbox(
                                &engine.http,
                                &engine.my_relay,
                                &pairing_inbox,
                            )
                            .await;
                            return;
                        }
                        _ => {
                            let _ = sub.ack(&msg_id).await; // ignore; keep listening
                        }
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

/// 32 fresh CSPRNG bytes — a pairing secret or a recovery-root contribution.
fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .expect("OS CSPRNG unavailable");
    b
}
