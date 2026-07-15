# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: 2026 Oculux Technologies LLC
#
# Static musl build of tezca-relay on distroless (nonroot). Single binary,
# no shell, no package manager — minimal attack surface for a blind relay.

FROM rust:1.97-bookworm AS build
RUN rustup target add x86_64-unknown-linux-musl \
    && apt-get update && apt-get install -y --no-install-recommends musl-tools protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p tezca-relay --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/tezca-relay /tezca-relay
# Mailboxes are RAM-only; the container needs no writable filesystem.
# Run with: --read-only --memory 1g --memory-swap 1g (see deploy/README.md).
EXPOSE 8443
ENTRYPOINT ["/tezca-relay"]
CMD ["--listen", "0.0.0.0:8443", "--tls-cert", "/certs/fullchain.pem", "--tls-key", "/certs/privkey.pem"]
