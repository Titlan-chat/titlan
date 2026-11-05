// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 1.1 red suite (gate L-D5): the dialog-side label rule mirrors core's
 * `normalize_label` (L-D3) — trim, blank clears, a cap counted in Unicode
 * scalar values, no control characters — plain-JVM, pure functions.
 *
 * RED expectation: every method reaches not-yet-implemented production code
 * and fails with `kotlin.NotImplementedError` at the first stub,
 * [LabelRules.check] or [LabelRules.scalarCount]; [capMatchesCore] fails
 * there too. GREEN turns them green.
 */
class LabelRulesTest {

    @Test
    fun blankClears() {
        assertEquals("empty clears", LabelCheck.Clear, LabelRules.check(""))
        assertEquals("whitespace-only clears", LabelCheck.Clear, LabelRules.check("   \n\t "))
    }

    @Test
    fun trimmedTextWithinTheCapIsOk() {
        assertEquals(LabelCheck.Ok("Alice at work"), LabelRules.check("  Alice at work  "))
        assertEquals("inner spaces are kept", LabelCheck.Ok("Team  Ops"), LabelRules.check("Team  Ops"))
    }

    @Test
    fun capCountsScalarValuesNotUnitsOrBytes() {
        val accented = "é".repeat(LabelRules.MAX_SCALARS) // 64 scalars, 128 UTF-8 bytes
        assertEquals(64, LabelRules.scalarCount(accented))
        assertEquals(LabelCheck.Ok(accented), LabelRules.check(accented))
        val emoji = "🙂".repeat(LabelRules.MAX_SCALARS) // 64 scalars, 128 UTF-16 units
        assertEquals("surrogate pairs count once", 64, LabelRules.scalarCount(emoji))
        assertEquals(LabelCheck.Ok(emoji), LabelRules.check(emoji))
        assertEquals(
            "one over the cap is rejected with its count, never truncated",
            LabelCheck.TooLong(65),
            LabelRules.check("a".repeat(LabelRules.MAX_SCALARS + 1)),
        )
        assertEquals("the count is taken after trimming", LabelCheck.Ok("a".repeat(64)), LabelRules.check(" " + "a".repeat(64) + " "))
    }

    @Test
    fun controlCharactersAreInvalid() {
        for (bad in listOf("tab\tinside", "line\nbreak", "nul\u0000", "bell\u0007", "esc\u001b[0m")) {
            assertEquals("control character in '${bad.take(4)}…' must be invalid", LabelCheck.Invalid, LabelRules.check(bad))
        }
    }

    @Test
    fun capMatchesCore() {
        val storage = repoFile("tezca-core/src/storage/mod.rs").readText(Charsets.UTF_8)
        val stated = Regex("""pub const MAX_LABEL_SCALARS: usize = (\d+);""").find(storage)
        assertTrue("tezca-core must state MAX_LABEL_SCALARS", stated != null)
        assertEquals(
            "the dialog cap must equal core's MAX_LABEL_SCALARS",
            stated!!.groupValues[1].toInt(),
            LabelRules.MAX_SCALARS,
        )
        assertEquals("the cap is 64 (L-D3)", 64, LabelRules.MAX_SCALARS)
        assertEquals("64 scalar values are exactly the cap", LabelCheck.Ok("x".repeat(64)), LabelRules.check("x".repeat(64)))
    }

    /** Resolves a repo path by walking up from the test working directory. */
    private fun repoFile(path: String): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (dir != null) {
            val candidate = File(dir, path)
            if (candidate.exists()) return candidate
            dir = dir.parentFile
        }
        error("$path not found above ${System.getProperty("user.dir")}")
    }
}
