// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.sync

import java.io.BufferedInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger

/**
 * Minimal in-process HTTP double of the relay API (test harness ONLY — it
 * drives the REAL core over real loopback sockets; no production hooks).
 *
 * It models a relay that has LOST all mailbox state — exactly the §10.7 loss
 * signal: every WS subscribe answers a plain-HTTP 404 (the core maps a 404
 * upgrade response to `Connected::NotFound`). `PUT /v1/mailboxes/{id}`
 * answers [putStatus]: 201 = an amnesiac-but-serving relay (recovery probes
 * complete), 429 = a pacing relay (probes are rate-limited and must never
 * count toward exhaustion). Deposits answer 202. [putRequests] counts PUT
 * attempts so pacing tests can assert observed attempts instead of sleeping.
 */
class FakeRelay(private val putStatus: Int) : AutoCloseable {

    private val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())

    /** PUT create-at-id attempts served (the recovery probe's first leg). */
    val putRequests = AtomicInteger(0)

    @Volatile
    private var running = true

    val url: String
        get() = "ws://127.0.0.1:${server.localPort}"

    init {
        Thread(
            {
                while (running) {
                    val socket = try {
                        server.accept()
                    } catch (_: Exception) {
                        break
                    }
                    Thread({ handle(socket) }, "fake-relay-conn")
                        .apply { isDaemon = true }
                        .start()
                }
            },
            "fake-relay-accept",
        ).apply { isDaemon = true }.start()
    }

    private fun handle(socket: Socket) {
        socket.use { s ->
            s.soTimeout = 5_000
            val input = BufferedInputStream(s.getInputStream())
            val head = readHead(input) ?: return
            val parts = head.lineSequence().first().split(" ")
            val method = parts.getOrNull(0) ?: return
            val path = parts.getOrNull(1) ?: return

            // Drain any request body so the client never sees a reset mid-write.
            var remaining = head.lineSequence()
                .firstOrNull { it.startsWith("content-length:", ignoreCase = true) }
                ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0
            val buf = ByteArray(8192)
            while (remaining > 0) {
                val n = input.read(buf, 0, minOf(remaining, buf.size))
                if (n <= 0) break
                remaining -= n
            }

            val status = when {
                method == "GET" && path.endsWith("/ws") -> "404 Not Found"
                method == "PUT" && path.startsWith("/v1/mailboxes/") -> {
                    putRequests.incrementAndGet()
                    if (putStatus == 201) "201 Created" else "429 Too Many Requests"
                }
                method == "POST" && path.endsWith("/messages") -> "202 Accepted"
                else -> "404 Not Found"
            }
            val pacing = if (status.startsWith("429")) "Retry-After: 1\r\n" else ""
            s.getOutputStream().write(
                "HTTP/1.1 $status\r\n${pacing}Content-Length: 0\r\nConnection: close\r\n\r\n"
                    .toByteArray(),
            )
            s.getOutputStream().flush()
        }
    }

    private fun readHead(input: BufferedInputStream): String? {
        val out = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return null
            out.append(b.toInt().toChar())
            if (out.endsWith("\r\n\r\n")) return out.toString()
            if (out.length > 65_536) return null
        }
    }

    override fun close() {
        running = false
        server.close()
    }
}
