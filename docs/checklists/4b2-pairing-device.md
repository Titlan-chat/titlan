<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Device pairing procedure — harness-as-offerer (operational)

Authority: ratified FLAG-B (harness as offerer, QR on the VM screen), distilled
from the first successful physical-device pairing (2026-07-27/28; probe
evidence `device-evidence/pairing/first-pair-20260728-probes.txt`). This is
the supporting procedure for checklist (f) P3 step 5 and for any
pairing-dependent device run. Build, install, and TLS-pin prep are checklist
(f) P0/P2/P2b — run those first; this document begins where the app is
installed and pinned.

Every trap below was hit live on the night of 2026-07-27/28; the steps exist
to make each one structurally impossible, not to assign blame to operator
error.

## 0. Precondition — LAN reachability (checked FIRST, always)

The device must be on the same LAN as the relay, VERIFIED before any pairing
or checklist-(f) run: open

```
https://<LAN-IP>:8443/healthz
```

in the PHONE's browser. A certificate warning — or any response at all — means
the relay is reachable (the relay serves `GET /healthz`; the phone does not
trust the test certificate, and does not need to). A hang of ~30 s means it is
NOT reachable: STOP and fix the network first (wrong Wi-Fi network, AP client
isolation, VM bridge mode, firewall).

This is checked FIRST for a specific reason: an unreachable relay currently
surfaces in the app as the MISLEADING "Pairing failed — the offer may be
stale or malformed." dialog (the accept path maps every failure, including
the `Network` error variant, onto that one string; the UI mapping fix is
ledgered for 4b-3). Without this precondition, a plain network problem reads
as an offer/codec failure and burns hours of misdirected debugging.

## 1. Terminal layout — the offerer BLOCKS

`deposit_harness offer` mints the offer and then BLOCKS, listening as the
live offerer until the pair-ack arrives or its wait fuse expires. Commands
pasted into that terminal while it listens are NOT executed — they queue
until the harness exits and then run against a dead offer, silently stale.
Use three terminals:

| Terminal | Role | Rule |
|---|---|---|
| A | relay (checklist (f) P3 step 2) | untouched for the whole session |
| B | mint — `deposit_harness offer`, output teed to `/tmp/offer-out.txt` | left running; NOTHING is ever typed here |
| C | working terminal — link extraction, hashes, QR render, logcat | all operator commands happen here |

## 2. Mint fresh — the offer has a 600 s fuse

The harness offer is single-use with a **600 s wait fuse from mint**
(`DEFAULT_WAIT_SECS`, `tezca-core/examples/deposit_harness.rs`): mint
IMMEDIATELY before the scan, never minutes ahead. (The 600 s harness fuse vs
the design's 1 h offer TTL is ledgered separately — deliberately not resolved
here.)

Terminal B:

```
TEZCA_TEST_RELAY_PIN=$(cat relay-certs/pin.hex) \
  cargo run -p tezca-core --locked --features test-relay-anchor \
  --example deposit_harness -- offer --dir ~/titlan-harness \
  --relay wss://<LAN-IP>:8443 | tee /tmp/offer-out.txt
```

Terminal C — extract the link (strips the trailing newline) and print the
expected probe hash:

```
grep -o 'titlan://pair#[A-Za-z0-9_-]*' /tmp/offer-out.txt | tr -d '\n' > /tmp/link.txt
wc -c /tmp/link.txt      # current-format offers: 2677 (no trailing newline)
sha256sum /tmp/link.txt  # EXPECTED TitlanScanProbe value — keep on screen
```

## 3. Render the QR — unique filename, every time

ALWAYS render to a UNIQUE timestamped filename, never a fixed name — image
viewers happily keep showing yesterday's `pair.png`, and a stale QR scans
"successfully" into a dead offer. Verify the viewer's TITLE BAR shows the
exact new filename before scanning.

```
QR=/tmp/pair-$(date +%H%M%S).png
qrencode -o "$QR" -s 10 -m 4 -8 "$(cat /tmp/link.txt)"
xdg-open "$QR"   # check the title bar shows THIS filename before scanning
```

This invocation is the settled safe form: the scan-hash probe proved the
`qrencode` → camera → ZXing transport byte-perfect at this density
(`-s 10 -m 4`), and `-8` argument-mode is fine.

## 4. Verify by probe, not by eyeball

Start the probe reader (Terminal C) BEFORE scanning, then scan once:

```
adb logcat -c && adb logcat -s TitlanScanProbe:I TitlanDecodeProbe:I TitlanFfiProbe:I TitlanFfiError:I
```

- `TitlanScanProbe` (`sha256=… len=2677`) MUST equal the `sha256sum
  /tmp/link.txt` value from step 2 exactly. If it does not, the WRONG QR was
  scanned (stale viewer, stale file) — STOP, do not interpret any subsequent
  failure, and redo from step 2.
- `TitlanDecodeProbe` and `TitlanFfiProbe` carry the decoded-offer hash
  (`len=1997`) and must equal each other.
- Any `TitlanFfiError` line: match its `variant`/`msgSha256` against the
  candidate table in `~/4b2-ffi-bisect.md` before theorizing.

## 5. Post-pairing state — the harness is one-shot

The harness exits after printing `paired: conversation <hex>` BY DESIGN
(one-shot). The paired offerer state lives in the harness `--dir`
(`~/titlan-harness` above):

- NEVER delete the `--dir` while the pairing is in use — it is the peer's
  entire session state; every later `send` needs it.
- A relay RESTART voids the pairing: mailboxes are RAM-only (INV-3), and the
  one-shot harness runs no receive loop, so it cannot participate in §10.7
  recovery. Re-pair fresh per the RELAY-LIFETIME PRECONDITION in checklist
  (f) (`docs/checklists/4b2-f-doze-latency.md`).

## 6. Scan-path status (operator notes)

- The CAMERA SCAN is the validated pairing path (first-pair evidence above:
  three deterministic scan decodes, byte-perfect through the FFI seam,
  pairing established).
- The §5 link-PASTE field is NOT currently a reliable operational path: it is
  reachable only via the camera-permission-denied degradation trigger, and
  with a ~2.6 KB link pasted its accept button can sit off-screen. Both
  limitations are 4b-3 ledger items; until they land, use the camera path —
  no paste-path workaround is documented as reliable.
