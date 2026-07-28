// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Flag-based configuration. Defaults are the maintainer-approved values
//! (work order §10.2 ledger, 2026-07-14). The flag names are the contract
//! the acceptance tests pin.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Relay configuration (all limits are config, nothing is cemented).
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub plain_http: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub ttl: Duration,
    pub sweep: Duration,
    pub max_blob_bytes: usize,
    pub mailbox_max_messages: usize,
    pub mailbox_max_bytes: usize,
    pub max_mailboxes: usize,
    pub rate_create_per_min: u32,
    /// Per-source `PUT /v1/mailboxes/{id}` create-at-id rate (frozen §8).
    pub rate_put_per_min_source: u32,
    pub rate_deposit_per_min_source: u32,
    pub rate_deposit_per_min_mailbox: u32,
    pub rate_ws_per_min_mailbox: u32,
    /// Rate-limiter source entries: idle expiry and LRU cap (INV-2: IPs — as
    /// keyed hashes — live in RAM for minutes, not days).
    pub limiter_idle: Duration,
    pub limiter_max_sources: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "127.0.0.1:8443".parse().expect("static addr"),
            plain_http: false,
            tls_cert: None,
            tls_key: None,
            ttl: Duration::from_secs(14 * 24 * 3600),
            sweep: Duration::from_secs(3600),
            max_blob_bytes: 16 * 1024,
            mailbox_max_messages: 1000,
            mailbox_max_bytes: 4 * 1024 * 1024,
            max_mailboxes: 100_000,
            rate_create_per_min: 10,
            rate_put_per_min_source: 30,
            rate_deposit_per_min_source: 60,
            rate_deposit_per_min_mailbox: 120,
            rate_ws_per_min_mailbox: 6,
            limiter_idle: Duration::from_secs(600),
            limiter_max_sources: 65_536,
        }
    }
}

impl Config {
    /// Parses command-line flags. Returns a human-readable error for the
    /// startup path (the only place the relay is allowed to be talkative).
    pub fn parse(args: impl Iterator<Item = String>) -> Result<Config, String> {
        let mut cfg = Config::default();
        let mut args = args.peekable();
        while let Some(flag) = args.next() {
            let mut value = |name: &str| {
                args.next()
                    .ok_or_else(|| format!("missing value for {name}"))
            };
            match flag.as_str() {
                "--listen" => {
                    cfg.listen = value("--listen")?
                        .parse()
                        .map_err(|e| format!("--listen: {e}"))?;
                }
                "--plain-http" => cfg.plain_http = true,
                "--tls-cert" => cfg.tls_cert = Some(PathBuf::from(value("--tls-cert")?)),
                "--tls-key" => cfg.tls_key = Some(PathBuf::from(value("--tls-key")?)),
                "--ttl-secs" => {
                    cfg.ttl = Duration::from_secs(parse_num(&flag, &value("--ttl-secs")?)?)
                }
                "--sweep-secs" => {
                    cfg.sweep = Duration::from_secs(parse_num(&flag, &value("--sweep-secs")?)?)
                }
                "--max-blob-bytes" => {
                    cfg.max_blob_bytes = parse_num(&flag, &value("--max-blob-bytes")?)? as usize
                }
                "--mailbox-max-messages" => {
                    cfg.mailbox_max_messages =
                        parse_num(&flag, &value("--mailbox-max-messages")?)? as usize
                }
                "--mailbox-max-bytes" => {
                    cfg.mailbox_max_bytes =
                        parse_num(&flag, &value("--mailbox-max-bytes")?)? as usize
                }
                "--max-mailboxes" => {
                    cfg.max_mailboxes = parse_num(&flag, &value("--max-mailboxes")?)? as usize
                }
                "--rate-create-per-min" => {
                    cfg.rate_create_per_min =
                        parse_num(&flag, &value("--rate-create-per-min")?)? as u32
                }
                "--rate-put-per-min-source" => {
                    cfg.rate_put_per_min_source =
                        parse_num(&flag, &value("--rate-put-per-min-source")?)? as u32
                }
                "--rate-deposit-per-min-source" => {
                    cfg.rate_deposit_per_min_source =
                        parse_num(&flag, &value("--rate-deposit-per-min-source")?)? as u32
                }
                "--rate-deposit-per-min-mailbox" => {
                    cfg.rate_deposit_per_min_mailbox =
                        parse_num(&flag, &value("--rate-deposit-per-min-mailbox")?)? as u32
                }
                "--rate-ws-per-min-mailbox" => {
                    cfg.rate_ws_per_min_mailbox =
                        parse_num(&flag, &value("--rate-ws-per-min-mailbox")?)? as u32
                }
                other => return Err(format!("unknown flag: {other}")),
            }
        }
        if !cfg.plain_http && (cfg.tls_cert.is_none() || cfg.tls_key.is_none()) {
            return Err("TLS is required: pass --tls-cert and --tls-key, or --plain-http".into());
        }
        Ok(cfg)
    }
}

fn parse_num(flag: &str, s: &str) -> Result<u64, String> {
    s.parse().map_err(|e| format!("{flag}: {e}"))
}
