<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Deploying tezca-relay

The relay is a single stateless binary. It holds mailboxes in RAM only
(INV-3): restarting loses queued messages, and clients recover by
reconnecting and resending. Run as many as you like — clients address relays
per-conversation (INV-5); a relay never assumes it is the only one.

## Docker (self-hosted, one-liner)

```sh
docker run -d --name tezca-relay \
  --read-only --memory 1g --memory-swap 1g \
  -p 443:8443 -v /etc/relay-certs:/certs:ro \
  ghcr.io/titlan-chat/titlan-relay:v0.2.0 \
  --tls-cert /certs/fullchain.pem --tls-key /certs/privkey.pem
```

`--memory-swap == --memory` disables swap for the container (INV-3: mailbox
memory never hits disk). `--read-only` because the relay writes nothing.

## systemd (bare metal / VM)

```sh
install -m0755 tezca-relay /usr/local/bin/
mkdir -p /etc/tezca-relay   # place fullchain.pem + privkey.pem here
cp deploy/tezca-relay.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tezca-relay
```

The unit disables swap (`MemorySwapMax=0`) and core dumps (`LimitCORE=0`),
runs read-only, and drops privileges. Verify the hardening with
`systemd-analyze verify /etc/systemd/system/tezca-relay.service`.

## TLS certificates

The relay terminates its own TLS; bring your own cert + key (PEM).

- Public host: `certbot certonly --standalone -d relay.example.org`, then
  point `--tls-cert`/`--tls-key` at the issued `fullchain.pem`/`privkey.pem`.
  Renewal replaces the files; restart the relay to pick them up (hot reload
  is post-MVP).
- Air-gapped / on-prem OT site: generate a self-signed cert and pin it in the
  client's per-conversation relay config (certificate pinning is designed on
  the client side in Phase 4).

## Sizing

Memory is bounded by config: `--max-mailboxes` × `--mailbox-max-bytes`
(defaults: 100k × 4 MiB ceiling, though real usage is far lower — mailboxes
hold only in-flight blobs). A 1 GiB container comfortably serves a small
deployment; raise `--memory` and caps together for larger ones.
