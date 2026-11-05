// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 1.1 red suite (gate L-D2): the one time format — today shows the local
 * time only, any other day a short date and time; both locale-aware
 * (`FormatStyle.SHORT`); "today" is decided in the reader's zone. Plain-JVM
 * with a fixed clock, zone and locale, so nothing here depends on the
 * machine running the suite.
 *
 * RED expectation: every method fails with `kotlin.NotImplementedError` at
 * the stub [MessageTime.format]. GREEN turns them green.
 */
class MessageTimeTest {

    private val us = Locale.US
    private val utc = ZoneId.of("UTC")
    private val now = Instant.parse("2026-11-02T15:05:00Z")

    @Test
    fun todayShowsTheTimeOnly() {
        val at = Instant.parse("2026-11-02T09:07:00Z")
        val shown = MessageTime.format(at.epochSecond, now, utc, us)
        assertEquals(
            "today is the localized short time",
            DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).withLocale(us).format(at.atZone(utc)),
            shown,
        )
        assertTrue("carries the time", shown.contains("9:07"))
        assertFalse("carries no date", shown.contains("11/2") || shown.contains("2026") || shown.contains("26"))
    }

    @Test
    fun otherDaysShowDateAndTime() {
        val yesterday = Instant.parse("2026-11-01T09:07:00Z")
        val shown = MessageTime.format(yesterday.epochSecond, now, utc, us)
        assertEquals(
            "another day is the localized short date and time",
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT, FormatStyle.SHORT)
                .withLocale(us)
                .format(yesterday.atZone(utc)),
            shown,
        )
        assertTrue("carries the date", shown.contains("11/1"))
        assertTrue("carries the time", shown.contains("9:07"))
    }

    @Test
    fun todayIsDecidedInTheReadersZone() {
        val at = Instant.parse("2026-11-02T23:30:00Z")
        val later = Instant.parse("2026-11-03T00:10:00Z")
        val inUtc = MessageTime.format(at.epochSecond, later, utc, us)
        assertTrue("in UTC the message is from yesterday: dated", inUtc.contains("11/2"))
        val kolkata = ZoneId.of("Asia/Kolkata") // UTC+05:30: 05:00 and 05:40 on the same local day
        val inKolkata = MessageTime.format(at.epochSecond, later, kolkata, us)
        assertFalse("in Kolkata the message is from today: no date", inKolkata.contains("11/"))
        assertTrue(inKolkata.contains("5:00"))
    }

    @Test
    fun followsTheLocale() {
        val at = Instant.parse("2026-11-02T09:07:00Z")
        val german = MessageTime.format(at.epochSecond, now, utc, Locale.GERMANY)
        assertEquals(
            DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).withLocale(Locale.GERMANY).format(at.atZone(utc)),
            german,
        )
        assertTrue("a 24-hour locale shows 09:07", german.contains("09:07"))
    }
}
