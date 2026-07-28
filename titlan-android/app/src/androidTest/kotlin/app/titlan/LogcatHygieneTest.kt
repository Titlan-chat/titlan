// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan

import android.util.Base64
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.titlan.core.CoreClientFactory
import app.titlan.crypto.DbKeyManager
import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * 4b-1 acceptance (INV-1, log surface): the raw DB key never appears in
 * logcat in any common encoding across its full lifecycle — birth, wrap,
 * unwrap, and core open. Red until the 4b-1 green commit.
 */
@RunWith(AndroidJUnit4::class)
class LogcatHygieneTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    // This suite's OWN store — never the shared AppCore filesDir/titlan.db.
    // AppCore keeps one process-wide connection to that file open for the whole
    // run; unlinking it under the live connection triggers
    // SQLITE_READONLY_DBMOVED on the next write through it (CI #64–#66;
    // ~/4b2-readonly-invest.md).
    private val dbFile = File(context.cacheDir, "logcat-hygiene.db")

    @Before
    fun freshState() {
        // Reset this suite's OWN store + key state coherently for a fresh
        // birth/wrap/unwrap/open lifecycle: the own store is deleted so a fresh
        // Keystore wrapping key can open it without a stale-key mismatch (the
        // original cross-test pollution guarantee, run 29613625849), while the
        // shared titlan.db is left untouched.
        for (suffix in listOf("", "-journal", "-wal", "-shm")) {
            File("${dbFile.path}$suffix").delete()
        }
        for (name in listOf(DbKeyManager.WRAP_FILE, "${DbKeyManager.WRAP_FILE}.tmp")) {
            File(context.filesDir, name).delete()
        }
    }

    @Test
    fun dbKeyNeverAppearsInLogcat() {
        // -b all: the default buffer set misses non-default buffers (crash,
        // system, events…) — a key leaked there would otherwise be invisible
        // to this test while the canary (which lands in main) still passed.
        shell("logcat -b all -c")

        // Positive control: prove the scanner can see what this process
        // logs, so the absence assertions below cannot be vacuously green.
        val canary = "TITLAN_LOGCAT_CANARY_7f3a9c"
        Log.w("LogcatHygieneTest", canary)

        // Full lifecycle: birth+wrap (fresh), unwrap (second instance), open.
        File(context.filesDir, DbKeyManager.WRAP_FILE).delete()
        val key = DbKeyManager(context).getOrCreateDbKey()
        DbKeyManager(context).getOrCreateDbKey()
        CoreClientFactory.open(
            dbFile.path,
            key,
            "wss://relay.invalid",
        ).use { it.initializeIdentity() }

        val log = shell("logcat -b all -d")
        assertTrue(
            "positive control failed: the logcat scanner did not see the " +
                "deliberate canary — absence results below would be meaningless",
            log.contains(canary),
        )
        val hex = key.joinToString("") { "%02x".format(it) }
        val encodings = listOf(
            hex,
            hex.uppercase(),
            Base64.encodeToString(key, Base64.NO_WRAP),
            key.joinToString(", "), // ByteArray.contentToString() form
        )
        for (encoding in encodings) {
            assertFalse(
                "raw DB key leaked to logcat (INV-1), encoding: ${encoding.take(8)}…",
                log.contains(encoding),
            )
        }
    }

    private fun shell(cmd: String): String =
        instrumentation.uiAutomation.executeShellCommand(cmd).use { pfd ->
            java.io.FileInputStream(pfd.fileDescriptor).readBytes()
                .toString(Charsets.UTF_8)
        }
}
