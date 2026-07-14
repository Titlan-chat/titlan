// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import org.junit.Assert.assertTrue
import org.junit.Test

/** Proves unit tests and BuildConfig codegen are wired into CI (Phase 1). */
class ScaffoldSanityTest {

    @Test
    fun buildConfigIsGeneratedAndVersioned() {
        assertTrue(BuildConfig.VERSION_NAME.matches(Regex("""\d+\.\d+\.\d+""")))
    }
}
