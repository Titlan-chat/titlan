// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

//! `tezca-relay` binary: parse flags, harden the process, serve.
//!
//! Output policy (INV-2): the startup path may print fixed strings and
//! usage errors to stderr; the serving path prints NOTHING, ever. The
//! zero_knowledge acceptance tests and scripts/check-invariants.sh enforce
//! this mechanically.

use std::net::SocketAddr;
use std::sync::Arc;

use tezca_relay::{api, config::Config, hardening, state::AppState};

fn main() {
    let cfg = match Config::parse(std::env::args().skip(1)) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("tezca-relay: {err}");
            std::process::exit(2);
        }
    };

    hardening::apply();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(serve(cfg));
}

async fn serve(cfg: Config) {
    let plain = cfg.plain_http;
    let listen = cfg.listen;
    let tls = (cfg.tls_cert.clone(), cfg.tls_key.clone());
    let state = Arc::new(AppState::new(cfg));

    // TTL sweep task (message TTL, idle mailboxes, limiter hygiene).
    let sweeper = state.clone();
    let sweep_every = sweeper.cfg.sweep;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(sweep_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            sweeper.sweep();
        }
    });

    let app = api::router(state).into_make_service_with_connect_info::<SocketAddr>();

    // Fixed string only — no address, no config echo (zero-logging policy
    // allows exactly this one line plus usage errors).
    eprintln!("tezca-relay listening");

    if plain {
        axum_server::bind(listen)
            .serve(app)
            .await
            .expect("serve (plain)");
    } else {
        let (cert, key) = (
            tls.0.expect("checked in Config::parse"),
            tls.1.expect("checked in Config::parse"),
        );
        // rustls with the ring provider (INV-6 names ring as approved).
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install ring crypto provider");
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .expect("load TLS certificate/key");
        axum_server::bind_rustls(listen, tls_config)
            .serve(app)
            .await
            .expect("serve (tls)");
    }
}
