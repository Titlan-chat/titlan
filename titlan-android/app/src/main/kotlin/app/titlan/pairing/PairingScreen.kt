// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Oculux Technologies LLC

package app.titlan.pairing

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.util.Size
import android.view.WindowManager
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.titlan.BuildConfig
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The three lifecycle states of a shown offer (frozen design §3: single-use,
 * 1 h TTL). [Active] while the QR/link is live; [Paired] once a peer completes
 * the handshake; [Expired] once the TTL lapses with no peer.
 */
sealed interface OfferLifecycle {
    data class Active(val offer: PairingOffer) : OfferLifecycle
    data class Paired(val conversationId: ByteArray) : OfferLifecycle
    data object Expired : OfferLifecycle
}

/**
 * Minimal pairing screen (frozen design §3/§5). Two roles share one screen:
 *
 *  - Offerer: mints an offer and shows it as a QR + `titlan://pair#` link,
 *    cycling through the three [OfferLifecycle] states.
 *  - Responder: scans with CameraX; a non-default relay in the scanned offer is
 *    surfaced for confirmation BEFORE the session is established (§3). If the
 *    camera has not decoded within [SCAN_TIMEOUT_MS] (20 s) the proactive link-
 *    paste path is offered (§5 fallback), so a slow/failed scan is never a dead
 *    end.
 *
 * A3: no crypto/framing here — everything routes through [PairingCoordinator].
 */
@Composable
fun PairingScreen() {
    var offer by remember { mutableStateOf<OfferLifecycle?>(null) }
    var mintFailed by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        when (val state = offer) {
            null -> {
                Button(onClick = {
                    // Minting creates the pairing mailbox on the relay — a
                    // network round-trip, kept off the main thread.
                    scope.launch {
                        mintFailed = false
                        runCatching {
                            withContext(Dispatchers.IO) { PairingCoordinator.createOffer() }
                        }
                            .onSuccess { offer = OfferLifecycle.Active(it) }
                            .onFailure { mintFailed = true }
                    }
                }) {
                    Text("Show pairing offer")
                }
                if (mintFailed) Text("Could not create an offer — check connectivity and retry.")
                ScanSection(onPaired = { offer = OfferLifecycle.Paired(it) })
            }

            is OfferLifecycle.Active -> OfferSection(
                offer = state.offer,
                onExpired = { offer = OfferLifecycle.Expired },
                onCancel = {
                    PairingCoordinator.cancelOffer(state.offer)
                    offer = null
                },
            )

            is OfferLifecycle.Paired ->
                Text("Paired — conversation established (${state.conversationId.size}-byte id).")

            OfferLifecycle.Expired -> {
                Text("Offer expired. Start a new one.")
                Button(onClick = { offer = null }) { Text("New offer") }
            }
        }
    }
}

/** Offerer view: the QR + link, with a TTL watch that flips to Expired. */
@Composable
private fun OfferSection(offer: PairingOffer, onExpired: () -> Unit, onCancel: () -> Unit) {
    val qr = remember(offer) { renderQr(QrCodec.encodeQr(offer.bytes)) }

    // Force max screen brightness while the QR is on screen; restore on
    // dismiss (frozen design §5).
    val window = LocalActivity.current?.window
    DisposableEffect(window) {
        val previous = window?.attributes?.screenBrightness
        window?.let {
            it.attributes = it.attributes.apply {
                screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL
            }
        }
        onDispose {
            if (window != null && previous != null) {
                window.attributes = window.attributes.apply { screenBrightness = previous }
            }
        }
    }

    Text("Scan this to pair", style = androidx.compose.material3.MaterialTheme.typography.titleMedium)
    Image(bitmap = qr.asImageBitmap(), contentDescription = "Pairing QR code")
    Text(QrCodec.encodeLink(offer.bytes))
    Button(onClick = onCancel) { Text("Cancel offer") }

    LaunchedEffect(offer) {
        val remaining = offer.expiresAtEpochMillis - System.currentTimeMillis()
        if (remaining > 0) delay(remaining)
        onExpired()
    }
}

/**
 * Responder view: CameraX preview with QR analysis, a non-default-relay
 * confirmation gate, and complete degradation to the link-paste flow on any of
 * the three §5 triggers — camera permission denied, no camera hardware, or a
 * 20 s decode timeout. The link path is offered proactively, never as an error.
 */
@Composable
private fun ScanSection(onPaired: (ByteArray) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var timedOut by remember { mutableStateOf(false) }
    var pendingRelay by remember { mutableStateOf<Pair<String, ByteArray>?>(null) }
    var scanned by remember { mutableStateOf<ByteArray?>(null) }

    val hasCamera = remember {
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
    }
    var cameraGranted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    var cameraDenied by remember { mutableStateOf(false) }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        cameraGranted = granted
        cameraDenied = !granted
    }
    LaunchedEffect(Unit) {
        if (hasCamera && !cameraGranted) permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    val scope = rememberCoroutineScope()
    var acceptFailed by remember { mutableStateOf(false) }

    // Establishing the session is a relay round-trip (pair-ack → inbox
    // handoff) — kept off the main thread. Failure re-arms the scanner.
    fun establish(bytes: ByteArray) {
        scope.launch {
            acceptFailed = false
            runCatching {
                withContext(Dispatchers.IO) { PairingCoordinator.acceptScannedOffer(bytes) }
            }
                .onSuccess(onPaired)
                .onFailure {
                    acceptFailed = true
                    scanned = null
                    pendingRelay = null
                }
        }
    }

    // Decode → confirm-relay-if-non-default → establish. The relay peek runs
    // off the main thread too: the first core touch opens the encrypted store.
    fun onOfferBytes(bytes: ByteArray) {
        if (scanned != null) return
        scanned = bytes
        scope.launch {
            val relay = withContext(Dispatchers.IO) { offerRelay(bytes) }
            if (relay != null && relay != BuildConfig.RELAY_URL) {
                pendingRelay = relay to bytes
            } else {
                establish(bytes)
            }
        }
    }

    if (acceptFailed) Text("Pairing failed — the offer may be stale or malformed. Try a fresh one.")

    val relayPending = pendingRelay
    if (relayPending != null) {
        Text("This offer uses a non-default relay:")
        Text(relayPending.first)
        Button(onClick = { establish(relayPending.second) }) {
            Text("Confirm and pair")
        }
        return
    }

    val scanning = hasCamera && cameraGranted
    if (scanning) {
        AndroidView(
            modifier = Modifier.fillMaxWidth(),
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val future = ProcessCameraProvider.getInstance(ctx)
                future.addListener({
                    val provider = future.get()
                    val preview = Preview.Builder().build().also {
                        it.surfaceProvider = previewView.surfaceProvider
                    }
                    val analysis = ImageAnalysis.Builder()
                        // §5: analysis resolution pinned 1920x1080 minimum
                        // (lower only if the hardware offers nothing higher).
                        .setResolutionSelector(
                            ResolutionSelector.Builder()
                                .setResolutionStrategy(
                                    ResolutionStrategy(
                                        Size(1920, 1080),
                                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                                    ),
                                )
                                .build(),
                        )
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                        .also { it.setAnalyzer(ContextCompat.getMainExecutor(ctx), QrAnalyzer(::onOfferBytes)) }
                    provider.unbindAll()
                    provider.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        analysis,
                    )
                }, ContextCompat.getMainExecutor(ctx))
                previewView
            },
        )
    }

    // §5 degradation: any of the three triggers reveals the link-paste path.
    if (!hasCamera || cameraDenied || timedOut) {
        var pasted by remember { mutableStateOf("") }
        Text(
            if (scanning) "Trouble scanning? Paste the titlan://pair# link:"
            else "Paste the titlan://pair# link to pair:",
        )
        OutlinedTextField(value = pasted, onValueChange = { pasted = it }, modifier = Modifier.fillMaxWidth())
        Button(onClick = {
            // A malformed paste must not crash the screen — surface the same
            // failed state the session path uses.
            runCatching { QrCodec.decodeLink(pasted.trim()) }
                .onSuccess(::onOfferBytes)
                .onFailure { acceptFailed = true }
        }) { Text("Pair from link") }
    }

    LaunchedEffect(scanning) {
        if (scanning) {
            delay(SCAN_TIMEOUT_MS)
            if (scanned == null) timedOut = true
        }
    }
}

/** CameraX analyzer: runs ZXing over each frame's luminance plane. */
private class QrAnalyzer(private val onBytes: (ByteArray) -> Unit) : ImageAnalysis.Analyzer {
    private val reader = QRCodeReader()

    override fun analyze(image: ImageProxy) {
        try {
            val plane = image.planes.firstOrNull() ?: return
            val data = ByteArray(plane.buffer.remaining()).also { plane.buffer.get(it) }
            val source = PlanarYUVLuminanceSource(
                data, image.width, image.height, 0, 0, image.width, image.height, false,
            )
            val bitmap = BinaryBitmap(HybridBinarizer(source))
            // §5 scanner config: TRY_HARDER on, possible formats QR only.
            val hints = mapOf(
                DecodeHintType.TRY_HARDER to true,
                DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE),
            )
            val text = reader.decode(bitmap, hints).text
            onBytes(QrCodec.decodeLink(qrTextToLink(text)))
        } catch (_: Exception) {
            // No QR in this frame (or not a titlan offer) — keep scanning.
        } finally {
            image.close()
        }
    }

    // A scanned QR carries the base64url payload directly; wrap it back into a
    // link so the single decodeLink path validates + decodes it.
    private fun qrTextToLink(text: String): String =
        if (text.startsWith("titlan://pair#")) text else "titlan://pair#$text"
}

private const val SCAN_TIMEOUT_MS = 20_000L

/** Best-effort read of the relay URL from an offer, for the §3 confirm gate. */
private fun offerRelay(offerBytes: ByteArray): String? =
    runCatching { app.titlan.core.AppCore.get().peekOfferRelay(offerBytes) }.getOrNull()

/** Renders a [QrMatrix] to a black/white [Bitmap] for display. */
private fun renderQr(matrix: QrMatrix): Bitmap {
    val bytes = matrix.modules
    val w = intBe(bytes, 0)
    val h = intBe(bytes, 4)
    val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
    var i = 8
    for (y in 0 until h) {
        for (x in 0 until w) {
            bmp.setPixel(x, y, if (bytes[i++].toInt() != 0) Color.BLACK else Color.WHITE)
        }
    }
    return bmp
}

private fun intBe(a: ByteArray, off: Int): Int =
    (a[off].toInt() and 0xFF shl 24) or
        (a[off + 1].toInt() and 0xFF shl 16) or
        (a[off + 2].toInt() and 0xFF shl 8) or
        (a[off + 3].toInt() and 0xFF)
