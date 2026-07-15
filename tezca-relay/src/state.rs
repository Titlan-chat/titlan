// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! In-memory relay state (INV-3: RAM only — losing this on restart is a
//! design guarantee, not a bug). Mailboxes hold opaque blobs and timing;
//! nothing else exists to hold (INV-2).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;
use rand::TryRngCore;
use tokio::sync::mpsc::UnboundedSender;

use crate::config::Config;
use crate::limits::{BoxLimiter, SourceLimiter};
use crate::wire;

/// One queued opaque blob.
pub struct QueuedMsg {
    pub id: [u8; 16],
    pub bytes: Bytes,
    pub deposited_at: Instant,
}

/// A mailbox: a queue of opaque blobs plus delivery plumbing.
#[derive(Default)]
pub struct Mailbox {
    pub queue: VecDeque<QueuedMsg>,
    pub queued_bytes: usize,
    pub last_activity: Option<Instant>,
    /// Wakes the (single) live subscriber on new deposits. A new subscriber
    /// replaces this sender; the old task ends on its next wake attempt.
    pub notify: Option<UnboundedSender<()>>,
}

/// Whole-process state.
pub struct AppState {
    pub cfg: Config,
    pub boxes: Mutex<HashMap<String, Mailbox>>,
    pub global_bytes: AtomicUsize,
    pub src_limiter: SourceLimiter,
    pub box_limiter: BoxLimiter,
}

impl AppState {
    pub fn new(cfg: Config) -> Self {
        AppState {
            src_limiter: SourceLimiter::new(&cfg),
            box_limiter: BoxLimiter::new(&cfg),
            cfg,
            boxes: Mutex::new(HashMap::new()),
            global_bytes: AtomicUsize::new(0),
        }
    }

    /// Creates a mailbox with a relay-generated unguessable id (256-bit OS
    /// CSPRNG; server-side generation so clients cannot choose
    /// fingerprintable ids).
    pub fn create_mailbox(&self) -> Option<String> {
        let mut boxes = self.boxes.lock().expect("boxes lock");
        if boxes.len() >= self.cfg.max_mailboxes {
            return None;
        }
        loop {
            let mut raw = [0u8; 32];
            rand::rngs::OsRng
                .try_fill_bytes(&mut raw)
                .expect("OS CSPRNG unavailable");
            let id = wire::encode_mailbox_id(&raw);
            if !boxes.contains_key(&id) {
                boxes.insert(
                    id.clone(),
                    Mailbox {
                        last_activity: Some(Instant::now()),
                        ..Mailbox::default()
                    },
                );
                return Some(id);
            }
        }
    }

    /// Periodic sweep: message TTL, idle-mailbox TTL, limiter hygiene.
    pub fn sweep(&self) {
        let now = Instant::now();
        let ttl = self.cfg.ttl;
        {
            let mut boxes = self.boxes.lock().expect("boxes lock");
            boxes.retain(|_, mailbox| {
                let mut dropped = 0usize;
                while let Some(front) = mailbox.queue.front() {
                    if now.duration_since(front.deposited_at) > ttl {
                        dropped += front.bytes.len();
                        mailbox.queue.pop_front();
                    } else {
                        break;
                    }
                }
                if dropped > 0 {
                    mailbox.queued_bytes -= dropped;
                    self.global_bytes.fetch_sub(dropped, Ordering::Relaxed);
                }
                match mailbox.last_activity {
                    Some(at) => now.duration_since(at) <= ttl,
                    None => true,
                }
            });
        }
        self.src_limiter.prune(now);
        self.box_limiter.prune(now);
    }
}
