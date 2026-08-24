// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * F7 (5a-3 conformance, ratified 2026-08-20): `proto/pairing.md`
 * "Per-path security claims (NORMATIVE)" requires that link pairing be
 * presented as "a convenience path with strictly weaker guarantees than QR,
 * and the UI states so". Before 5a-3 the paste affordance carried no security
 * statement at all.
 *
 * This test pins PRESENCE, non-emptiness, the QR-is-stronger KEYWORD, and the
 * wiring into the paste path — never the sentence. The wording is drafted by
 * 5a-3 and enumerated in its report for maintainer copy-review, the same
 * split 5a-2 used for the failure vocabulary.
 *
 * Plain-JVM on purpose (the CI "Android — lint, unit tests" job): resources
 * are read straight off the repo tree, so no Android runtime is needed.
 */
class LinkPathDisclosureTest {

    private val resourceName = "pairing_link_path_security"

    @Test
    fun linkPathSecurityCopyExistsAndNamesQrAsStronger() {
        val strings = repoFile("titlan-android/app/src/main/res/values/strings.xml")
            .readText(Charsets.UTF_8)
        val match = Regex(
            "<string\\s+name=\"$resourceName\"\\s*>(.*?)</string>",
            RegexOption.DOT_MATCHES_ALL,
        ).find(strings)
        assertTrue(
            "no <string name=\"$resourceName\"> in app/src/main/res/values/strings.xml " +
                "— the link path must carry the NORMATIVE per-path security " +
                "statement (proto/pairing.md)",
            match != null,
        )

        val copy = match!!.groupValues[1].trim()
        assertTrue("the $resourceName copy must not be empty", copy.isNotEmpty())
        assertTrue(
            "the link-path copy must name QR, got: $copy",
            copy.contains("QR"),
        )
        assertTrue(
            "the link-path copy must state that the link path is weaker than QR " +
                "(keyword 'weaker' or 'stronger'), got: $copy",
            Regex("weaker|stronger").containsMatchIn(copy),
        )

        val screen = repoFile(
            "titlan-android/app/src/main/kotlin/app/titlan/pairing/PairingScreen.kt",
        ).readText(Charsets.UTF_8)
        assertTrue(
            "PairingScreen must render R.string.$resourceName on the link-paste path " +
                "— an unreferenced resource states nothing to the user",
            screen.contains("R.string.$resourceName"),
        )
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
