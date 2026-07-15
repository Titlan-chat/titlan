// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Rate limiting under INV-2: two STRUCTURALLY DISJOINT limiters. The
//! per-source map is keyed by a per-boot keyed hash of the source address
//! (std `RandomState` = SipHash with process-random keys) and holds no
//! mailbox data; the per-mailbox map is keyed by mailbox id and holds no
//! source data. The mailbox↔source join never exists as a data structure,
//! so it cannot be logged (nothing logs anyway) or usefully dumped.
//! Everything here is RAM-only, minutes-lived, and resets on restart.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::config::Config;

fn current_minute() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
        / 60
}

/// Seconds until the current fixed window rolls over (Retry-After value).
pub fn retry_after_secs() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs();
    60 - (secs % 60)
}

struct Window {
    minute: u64,
    count_a: u32,
    count_b: u32,
    touched: Instant,
}

impl Window {
    fn fresh(minute: u64) -> Self {
        Window {
            minute,
            count_a: 0,
            count_b: 0,
            touched: Instant::now(),
        }
    }

    /// Increments counter `a`/`b` for this window; true if within `limit`.
    fn admit(&mut self, use_a: bool, limit: u32) -> bool {
        let minute = current_minute();
        if self.minute != minute {
            *self = Window::fresh(minute);
        }
        self.touched = Instant::now();
        let count = if use_a {
            &mut self.count_a
        } else {
            &mut self.count_b
        };
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    }
}

/// Per-source limiter. Key: SipHash(boot-random keys, IP) — IPv6 sources are
/// coarsened to /64 before hashing so one host can't rotate a whole prefix.
pub struct SourceLimiter {
    hasher: RandomState,
    map: Mutex<HashMap<u64, Window>>,
    create_limit: u32,
    deposit_limit: u32,
    idle: std::time::Duration,
    max_entries: usize,
}

impl SourceLimiter {
    pub fn new(cfg: &Config) -> Self {
        SourceLimiter {
            hasher: RandomState::new(),
            map: Mutex::new(HashMap::new()),
            create_limit: cfg.rate_create_per_min,
            deposit_limit: cfg.rate_deposit_per_min_source,
            idle: cfg.limiter_idle,
            max_entries: cfg.limiter_max_sources,
        }
    }

    fn key(&self, ip: IpAddr) -> u64 {
        let coarse = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets()[..8].to_vec(), // /64
        };
        self.hasher.hash_one(&coarse)
    }

    fn admit(&self, ip: IpAddr, use_a: bool, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        let key = self.key(ip);
        let mut map = self.map.lock().expect("limiter lock");
        if map.len() >= self.max_entries && !map.contains_key(&key) {
            let now = Instant::now();
            map.retain(|_, w| now.duration_since(w.touched) < self.idle);
            if map.len() >= self.max_entries {
                // Saturated by active sources: shed the new source's request
                // rather than evicting an active tracker.
                return false;
            }
        }
        map.entry(key)
            .or_insert_with(|| Window::fresh(current_minute()))
            .admit(use_a, limit)
    }

    pub fn admit_create(&self, ip: IpAddr) -> bool {
        self.admit(ip, true, self.create_limit)
    }

    pub fn admit_deposit(&self, ip: IpAddr) -> bool {
        self.admit(ip, false, self.deposit_limit)
    }

    pub fn prune(&self, now: Instant) {
        self.map
            .lock()
            .expect("limiter lock")
            .retain(|_, w| now.duration_since(w.touched) < self.idle);
    }
}

/// Per-mailbox limiter. Key: mailbox id string. No source data (INV-2).
pub struct BoxLimiter {
    map: Mutex<HashMap<String, Window>>,
    deposit_limit: u32,
    ws_limit: u32,
    idle: std::time::Duration,
}

impl BoxLimiter {
    pub fn new(cfg: &Config) -> Self {
        BoxLimiter {
            map: Mutex::new(HashMap::new()),
            deposit_limit: cfg.rate_deposit_per_min_mailbox,
            ws_limit: cfg.rate_ws_per_min_mailbox,
            idle: cfg.limiter_idle,
        }
    }

    fn admit(&self, mailbox: &str, use_a: bool, limit: u32) -> bool {
        if limit == 0 {
            return false;
        }
        self.map
            .lock()
            .expect("limiter lock")
            .entry(mailbox.to_owned())
            .or_insert_with(|| Window::fresh(current_minute()))
            .admit(use_a, limit)
    }

    pub fn admit_deposit(&self, mailbox: &str) -> bool {
        self.admit(mailbox, true, self.deposit_limit)
    }

    pub fn admit_ws(&self, mailbox: &str) -> bool {
        self.admit(mailbox, false, self.ws_limit)
    }

    pub fn prune(&self, now: Instant) {
        self.map
            .lock()
            .expect("limiter lock")
            .retain(|_, w| now.duration_since(w.touched) < self.idle);
    }

    /// Forget a mailbox's counters when it is deleted (hygiene).
    pub fn forget(&self, mailbox: &str) {
        self.map.lock().expect("limiter lock").remove(mailbox);
    }
}
