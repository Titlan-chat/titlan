// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import java.time.Instant
import java.time.ZoneId
import java.util.Locale

/**
 * The one time format the chat bubbles and the list rows share (1.1, L-D2):
 * a message from today (in [ZoneId]) shows its local time only; any other
 * day shows a short date and time. Both forms are `java.time`
 * `FormatStyle.SHORT`, so they follow the device locale (12- or 24-hour
 * clock, day/month order). Pure — no Android types — so the plain-JVM suite
 * pins it with a fixed clock and zone.
 */
object MessageTime {
    /**
     * Formats the Unix-seconds instant [epochSeconds] for a reader whose
     * clock reads [now] in zone [zone], in [locale].
     */
    fun format(epochSeconds: Long, now: Instant, zone: ZoneId, locale: Locale): String =
        TODO("1.1 GREEN: time format")
}
