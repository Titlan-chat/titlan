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
