// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! Relay HTTP operations (reqwest): mailbox create, blob deposit, mailbox
//! retire. TLS (for `wss://`/`https://`) runs on the ring provider; the tests
//! use plain `http://`. See `proto/relay-api.md`.

use reqwest::Client;

use crate::{CoreError, Result};

/// Result of a blob deposit — the relay's status, mapped to actions.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DepositOutcome {
    /// 202 — queued.
    Accepted,
    /// 404 — mailbox unknown / expired / retired (a clean "gone" signal).
    NotFound,
    /// Any other non-success status.
    Other(u16),
}

/// Maps a relay URL (`ws://`/`wss://`) to its HTTP origin.
fn to_http(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if let Some(rest) = url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else {
        url.to_string()
    }
}

fn net_err(e: reqwest::Error) -> CoreError {
    CoreError::Network(e.to_string())
}

/// Creates a mailbox on `relay_url`, returning its 43-char id.
pub(crate) async fn create_mailbox(client: &Client, relay_url: &str) -> Result<String> {
    let base = to_http(relay_url);
    let resp = client
        .post(format!("{base}/v1/mailboxes"))
        .send()
        .await
        .map_err(net_err)?;
    if resp.status() != reqwest::StatusCode::CREATED {
        return Err(CoreError::Network(format!(
            "mailbox create failed: {}",
            resp.status()
        )));
    }
    let body = resp.text().await.map_err(net_err)?;
    body.split("\"mailbox_id\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .map(|s| s.to_string())
        .ok_or(CoreError::Malformed("malformed mailbox-create response"))
}

/// Deposits an opaque blob to a mailbox.
pub(crate) async fn deposit(
    client: &Client,
    relay_url: &str,
    mailbox_id: &str,
    blob: &[u8],
) -> Result<DepositOutcome> {
    let base = to_http(relay_url);
    let resp = client
        .post(format!("{base}/v1/mailboxes/{mailbox_id}/messages"))
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .body(blob.to_vec())
        .send()
        .await
        .map_err(net_err)?;
    Ok(match resp.status().as_u16() {
        202 => DepositOutcome::Accepted,
        404 => DepositOutcome::NotFound,
        other => DepositOutcome::Other(other),
    })
}

/// Outcome of a `PUT /v1/mailboxes/{id}` create-at-id (frozen §8).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PutOutcome {
    /// 201 — the mailbox exists after the call (created or already present).
    Created,
    /// 503 — global capacity reached (recovery-blocked-at-cap; accepted).
    AtCap,
    /// 429 — per-source pacing. During recovery this is a PACING signal and
    /// MUST NOT count toward exhaustion (frozen §8).
    RateLimited,
    /// Any other non-success status.
    Other(u16),
}

/// PUT-creates a mailbox at a client-specified 256-bit id (idempotent, §8).
/// Used before subscribing to an own derived inbox and before depositing into a
/// peer derived inbox (deposit/subscribe both 404 on unknown ids, never create).
pub(crate) async fn put_mailbox(
    client: &Client,
    relay_url: &str,
    mailbox_id: &str,
) -> Result<PutOutcome> {
    let base = to_http(relay_url);
    let resp = client
        .put(format!("{base}/v1/mailboxes/{mailbox_id}"))
        .send()
        .await
        .map_err(net_err)?;
    Ok(match resp.status().as_u16() {
        201 => PutOutcome::Created,
        503 => PutOutcome::AtCap,
        429 => PutOutcome::RateLimited,
        other => PutOutcome::Other(other),
    })
}

/// Retires (deletes) a mailbox. Best-effort: a 404 is already the goal state.
pub(crate) async fn delete_mailbox(
    client: &Client,
    relay_url: &str,
    mailbox_id: &str,
) -> Result<()> {
    let base = to_http(relay_url);
    client
        .delete(format!("{base}/v1/mailboxes/{mailbox_id}"))
        .send()
        .await
        .map_err(net_err)?;
    Ok(())
}
