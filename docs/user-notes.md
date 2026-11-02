<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Oculux Technologies LLC -->

# Titlan — user notes

Short notes on behaviour you may notice in day-to-day use. Each note names
the project document where the behaviour is decided and recorded, so it can
be checked against the source rather than taken on trust.

## Messages waiting while your phone stays locked

Messages sent to you while your device cannot receive them are held for you
by the relay. The relay keeps a waiting mailbox for 14 d (its idle-mailbox
TTL) and does not hold queued messages longer than that.

Titlan can only collect those messages once your device has been unlocked
after a restart; until then its sync cannot run. A device that is rebooted
and then never unlocked for 14 d or longer therefore loses whatever was
queued for it in that window.

Source: `docs/threat-model.md` TM-C4 (the "TTL edge" register row; 4b-2
freeze §2).

## Battery optimization and delivery delay

Titlan does not ask you for a battery-optimization exemption. Delivery relies
on Titlan's sync service, which shows a persistent notification while it
runs, and Android's power management (Doze) may delay it. In acceptance
testing under deep Doze, measured delivery latency was 1271 / 932 / 1660 ms.
The operating system may defer or stop the sync service beyond what that
measurement covered.

If you want to exempt Titlan from battery optimization yourself, the setting
is: Settings → Apps → Titlan → Battery → Unrestricted (wording varies by
Android build). This is your choice; the app never prompts for it.

Source: `docs/threat-model.md` TM-C7 (register row);
`docs/checklists/4b2-f-doze-latency.md`.

## What the connection label on a conversation means

Each conversation shows the state of its own link to the relay: "Connecting…",
"Online", "Offline", "Reconnecting…" or "Recovering…". All but "Offline" mean
Titlan is working on it and no action is needed; "Offline" means this device
has no network path right now. A separate banner — "This conversation can no
longer reach the other device. Pair again to continue." — means the relay-side
mailboxes for that conversation were lost on both sides (for example after a
relay restart during a long outage) and in-band recovery ran out; pairing
again is the only way forward.

Messages carry no delivery ticks and no times in this version. A message in
your list has been handed to Titlan for delivery, not necessarily delivered;
one the relay refused for good is marked "Not delivered".

Source: `docs/design/2026-09-conversation-ui-freeze.md` CU-D6 (states, the
no-ticks decision); `docs/threat-model.md` TM-R4 (restart loss and recovery).

## Delivery after your network comes back

When your device regains a network (airplane mode off, a change of network,
a device that slept), the first connection Titlan makes can be unusable
while the label still reads "Online". Titlan notices through its keepalive
and reconnects on its own; a message sent in that window arrives after the
reconnect, up to about five minutes later. Nothing is lost, duplicated or
refused — the wait is the only effect.

Source: release notes v0.1.0 (Known issues, finding F-O);
`docs/design/2026-10-transport-keepalive-freeze.md` (the keepalive that
detects the dead connection).

## An empty conversation after a pairing that did not finish

If a pairing stops partway (a link that was no longer valid, a device that
lost its network during the exchange), the list can show a conversation
that no one can message in. Pair again; the empty one can be ignored.
Removing it automatically is planned.

Source: release notes v0.1.0 (Known issues, findings F-K/F-I).
