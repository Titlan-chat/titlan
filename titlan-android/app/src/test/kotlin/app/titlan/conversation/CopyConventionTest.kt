// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.conversation

import app.titlan.R
import app.titlan.pairing.PairingFailure
import app.titlan.pairing.PairingFailureClass
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 5e-1 red suite (freeze CU-D9, FLAG-2 discharged): one copy convention —
 * every user-visible string is a resource in strings.xml, Kotlin carries no
 * user-facing literal, the frozen wordings are verbatim where they live now,
 * and the failure vocabulary maps classes to DISTINCT resources.
 *
 * Plain-JVM on purpose (the CI "Android — lint, unit tests" job): resources
 * are read straight off the repo tree (the LinkPathDisclosureTest pattern).
 *
 * RED expectation: [everyInventoryNameIsAResourceAndMapped],
 * [frozenExpiredCopyIsVerbatimInResources] and
 * [fiveClassesMapToFiveDistinctResources] reach the unimplemented
 * [PairingFailure.userMessageRes] and fail with `kotlin.NotImplementedError`;
 * [fixedNotificationTextIsVerbatim] and [noUserFacingLiteralInKotlinSources]
 * fail at their assertions because the literals still live in Kotlin.
 */
class CopyConventionTest {

    private val inventory = listOf(
        "app_name",
        "pairing_show_offer", "pairing_mint_failed", "pairing_offer_expired", "pairing_new_offer",
        "pairing_scan_title", "pairing_qr_content_description", "pairing_offer_validity",
        "pairing_dismiss", "pairing_non_default_relay", "pairing_confirm_and_pair",
        "pairing_paste_prompt_scanning", "pairing_paste_prompt", "pairing_pair_from_link",
        "pairing_link_path_security",
        "pairing_failure_network", "pairing_failure_expired", "pairing_failure_malformed",
        "pairing_failure_crypto", "pairing_failure_internal",
        "sync_notification_title",
        "conversations_title", "conversations_row_label", "conversations_pair_device",
        "chat_empty_paired", "chat_compose_hint", "chat_send", "chat_too_long",
        "chat_message_unsupported", "chat_message_undecodable", "chat_message_not_delivered",
        "chat_state_connecting", "chat_state_online", "chat_state_offline",
        "chat_state_backoff", "chat_state_recovering",
        "chat_needs_repair", "chat_pair_again", "chat_storage_error", "nav_back",
    )

    // The pair-offer v3 freeze §5 copy (V3-D2): one surface for both expiry details.
    private val frozenExpiredCopy =
        "offer expired or not yet valid — check both devices' clocks, then re-mint"

    @Test
    fun everyInventoryNameIsAResourceAndMapped() {
        val res = resources()
        val missing = inventory.filter { it !in res }
        assertTrue("strings.xml must carry every 5e-1 resource name; missing: $missing", missing.isEmpty())
        val blank = inventory.filter { res[it].isNullOrBlank() }
        assertTrue("no 5e-1 resource may be blank; blank: $blank", blank.isEmpty())
        assertEquals(
            "the NETWORK_UNREACHABLE class must resolve to its resource",
            R.string.pairing_failure_network,
            PairingFailure.userMessageRes(PairingFailureClass.NETWORK_UNREACHABLE),
        )
    }

    @Test
    fun frozenExpiredCopyIsVerbatimInResources() {
        assertEquals(
            "pairing_failure_expired must be the pair-offer v3 freeze §5 wording VERBATIM",
            frozenExpiredCopy,
            resources()["pairing_failure_expired"],
        )
        assertEquals(
            "the EXPIRED class must resolve to that resource",
            R.string.pairing_failure_expired,
            PairingFailure.userMessageRes(PairingFailureClass.EXPIRED),
        )
    }

    @Test
    fun fiveClassesMapToFiveDistinctResources() {
        val ids = PairingFailureClass.entries.map { PairingFailure.userMessageRes(it) }
        assertEquals(
            "the five failure classes must map to five DISTINCT resources, got $ids",
            5,
            ids.toSet().size,
        )
    }

    @Test
    fun fixedNotificationTextIsVerbatim() {
        val res = resources()
        assertEquals(
            "sync_notification_title must be the frozen §7 fixed text verbatim",
            "Titlan sync active",
            res["sync_notification_title"],
        )
        assertTrue(
            "chat_empty_paired must begin with the checklist evidence literal",
            res["chat_empty_paired"]!!.startsWith("Paired — conversation established"),
        )
        val service = repoFile("titlan-android/app/src/main/kotlin/app/titlan/sync/SyncService.kt")
            .readText(Charsets.UTF_8)
        assertFalse(
            "SyncService.kt must not carry the notification literal — the text is a resource (FLAG-2)",
            service.contains("\"Titlan sync active\""),
        )
    }

    @Test
    fun noUserFacingLiteralInKotlinSources() {
        val srcMain = repoFile("titlan-android/app/src/main/kotlin")
        val pattern = Regex("""Text\(\s*"|^\s*(text|contentDescription|label|placeholder)\s*=\s*"""")
        val offenders = srcMain.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .toList()
            .flatMap { f ->
                f.readLines(Charsets.UTF_8).withIndex()
                    .filter { (_, line) -> pattern.containsMatchIn(line) }
                    .map { (i, line) -> "${f.relativeTo(srcMain).path}:${i + 1}: ${line.trim()}" }
            }
        assertTrue(
            "no Text(\"…\") or text/contentDescription/label/placeholder string literal may " +
                "remain in app sources (FLAG-2: every user-visible string is a resource); found: $offenders",
            offenders.isEmpty(),
        )
    }

    /**
     * strings.xml as name → value, with exactly one enclosing double-quote
     * pair stripped (the Android form that keeps apostrophes verbatim).
     */
    private fun resources(): Map<String, String> {
        val xml = repoFile("titlan-android/app/src/main/res/values/strings.xml").readText(Charsets.UTF_8)
        return Regex("""<string\s+name="([^"]+)"\s*>(.*?)</string>""", RegexOption.DOT_MATCHES_ALL)
            .findAll(xml)
            .associate { m ->
                val raw = m.groupValues[2].trim()
                val value = if (raw.length >= 2 && raw.startsWith("\"") && raw.endsWith("\"")) {
                    raw.substring(1, raw.length - 1)
                } else {
                    raw
                }
                m.groupValues[1] to value
            }
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
