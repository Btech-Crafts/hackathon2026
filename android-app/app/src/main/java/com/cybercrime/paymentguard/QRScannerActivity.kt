package com.cybercrime.paymentguard

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

/**
 * Dedicated QR scanner: CameraX preview + ML Kit barcode reader, plus a
 * gallery-image picker for screenshots / forwarded QR images.
 *
 * Flow:
 *  1. Decodes the QR string (live or gallery).
 *  2. Runs the client-side [QrPayloadClassifier] pre-check — short-links and
 *     URL redirects get an instant local warning banner.
 *  3. Scores the payload fully on-device with [RiskEngine] using the user's
 *     `expected_action` context (RECEIVE vs PAY toggle). No network calls.
 *  4. Renders the verdict (score / severity / risk factors) and launches
 *     [OverlayAlertService] on HIGH / CRITICAL (small banner on MEDIUM).
 *
 * Privacy: the QR string never leaves the phone.
 */
class QRScannerActivity : AppCompatActivity() {

    private lateinit var previewView: PreviewView
    private lateinit var statusText: TextView
    private lateinit var verdictText: TextView
    private lateinit var expectedToggle: MaterialButton

    /** What the user believes will happen — drives reverse-collect detection. */
    private var expectedAction: String = "PAY"

    private var lastScanned: String? = null
    private var lastScannedAt: Long = 0L

    private val cameraExecutor = Executors.newSingleThreadExecutor()

    private val requestCameraPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) startCamera() else toast("Camera permission is needed to scan QR codes.")
        }

    private val pickGalleryImage =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
            if (uri == null) return@registerForActivityResult
            lifecycleScope.launch {
                statusText.text = "Decoding gallery image…"
                val values = QRImageDecoder.decodeFromUri(this@QRScannerActivity, uri)
                if (values.isEmpty()) {
                    statusText.text = "No QR code found in that image."
                } else {
                    onPayloadDecoded(values.first(), fromGallery = true)
                }
            }
        }

    // ------------------------------------------------------------------ //

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_scanner)

        previewView = findViewById(R.id.previewView)
        statusText = findViewById(R.id.statusText)
        verdictText = findViewById(R.id.verdictText)
        expectedToggle = findViewById<MaterialButton>(R.id.expectedButton).apply {
            setOnClickListener {
                expectedAction = if (expectedAction == "PAY") "RECEIVE" else "PAY"
                text = "I expect: $expectedAction"
            }
        }
        findViewById<View>(R.id.galleryButton).setOnClickListener {
            pickGalleryImage.launch("image/*")
        }

        // Warm the offline caches so QR payloads are intercepted without
        // any network. Everything below is on-device.
        OfflineThreatCache.initialize(this)
        TrustedStore.init(this)
        try {
            assets.open("threat_bloom.bin").use {
                OfflineThreatCache.attachBloom(VpaBloomFilter.load(it.readBytes()))
            }
        } catch (e: Exception) {
            Log.w(TAG, "Bloom sketch unavailable: ${e.message}")
        }

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            startCamera()
        } else {
            requestCameraPermission.launch(Manifest.permission.CAMERA)
        }
    }

    override fun onDestroy() {
        cameraExecutor.shutdown()
        super.onDestroy()
    }

    // ------------------------------------------------------------------ //
    // CameraX + ML Kit
    // ------------------------------------------------------------------ //

    private fun startCamera() {
        val providerFuture = ProcessCameraProvider.getInstance(this)
        providerFuture.addListener(
            {
                try {
                    val provider = providerFuture.get()
                    val preview = Preview.Builder().build().also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }
                    val options = BarcodeScannerOptions.Builder()
                        .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                        .build()
                    val scanner = BarcodeScanning.getClient(options)
                    val analysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                        .also { ia ->
                            ia.setAnalyzer(cameraExecutor) { imageProxy ->
                                processFrame(scanner, imageProxy)
                            }
                        }
                    provider.unbindAll()
                    provider.bindToLifecycle(
                        this, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis,
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Camera start failed", e)
                    statusText.text = "Camera unavailable: ${e.message}"
                }
            },
            ContextCompat.getMainExecutor(this),
        )
    }

    @androidx.annotation.OptIn(ExperimentalGetImage::class)
    private fun processFrame(
        scanner: com.google.mlkit.vision.barcode.BarcodeScanner,
        imageProxy: ImageProxy,
    ) {
        val mediaImage = imageProxy.image
        if (mediaImage == null) {
            imageProxy.close()
            return
        }
        val input = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
        scanner.process(input)
            .addOnSuccessListener { barcodes ->
                val raw = barcodes.firstOrNull()?.rawValue
                if (raw != null) {
                    // Debounce identical frames (1.5 s) to avoid request storms.
                    val now = System.currentTimeMillis()
                    if (raw != lastScanned || now - lastScannedAt > 1_500) {
                        lastScanned = raw
                        lastScannedAt = now
                        runOnUiThread { onPayloadDecoded(raw, fromGallery = false) }
                    }
                }
            }
            .addOnFailureListener { e -> Log.w(TAG, "Frame scan failed: ${e.message}") }
            .addOnCompleteListener { imageProxy.close() }
    }

    // ------------------------------------------------------------------ //
    // Evaluation pipeline
    // ------------------------------------------------------------------ //

    private fun onPayloadDecoded(raw: String, fromGallery: Boolean) {
        // ---- Offline interception FIRST (<5 ms, no I/O) ----------------------
        // Known scam VPA or high-risk URI (short-link / MCC-less mandate):
        // warn instantly, then still confirm with the backend below.
        val embeddedVpa = VPA_IN_QR.find(raw)?.value
        val offlineHit = OfflineThreatCache.isKnownScamVpa(embeddedVpa) ||
            OfflineThreatCache.isHighRiskUri(raw)
        if (offlineHit) {
            statusText.text = "⛔ Offline threat match — do NOT pay. Confirming with server…"
            Toast.makeText(
                this, "⛔ Offline threat match — suspected scam QR.", Toast.LENGTH_LONG,
            ).show()
        }
        val kind = QrPayloadClassifier.classify(raw)
        if (!offlineHit) {
            if (kind == QrPayloadClassifier.Kind.SHORT_LINK ||
                kind == QrPayloadClassifier.Kind.URL_REDIRECT
            ) {
                statusText.text =
                    "⚠️ This QR is a web link, not a UPI payment intent ($kind). Verifying…"
            } else {
                statusText.text = "Evaluating ${if (fromGallery) "gallery" else "camera"} QR…"
            }
        }
        // On-device verdict is instantaneous — no coroutine needed.
        evaluateWithBackend(raw)
    }

    private fun evaluateWithBackend(rawPayload: String) {
        // Fully on-device verdict — no network. Runs inline (microseconds).
        val vpa = VPA_IN_QR.find(rawPayload)?.value
        val verdict = RiskEngine.evaluateQr(
            rawPayload = rawPayload,
            expectedAction = expectedAction,
            isKnownSuspect = OfflineThreatCache.isKnownScamVpa(vpa),
            isSketchMatch = OfflineThreatCache.isSketchMatch(vpa),
            isTrusted = TrustedStore.isTrusted(vpa),
        )
        statusText.text = "Scanned ${if (verdict.vpa.isNotEmpty()) verdict.vpa else "QR"} • ${verdict.factors.size} signal(s)"
        verdictText.visibility = View.VISIBLE
        verdictText.text =
            "Score ${verdict.score} (${verdict.severity})\n${verdict.factors.joinToString(", ")}"
        verdictText.setTextColor(
            ContextCompat.getColor(
                this,
                when (verdict.severity) {
                    "CRITICAL", "HIGH" -> R.color.risk_critical
                    "MEDIUM" -> R.color.risk_medium_text
                    else -> R.color.risk_safe
                },
            ),
        )

        if (verdict.severity == "HIGH" || verdict.severity == "CRITICAL") {
            launchOverlayFromQr(verdict)
        } else if (verdict.severity == "MEDIUM") {
            launchBannerFromQr(verdict)
        }
        if (verdict.isReverseCollectScam || verdict.isMandateHijack ||
            verdict.guidance == "DO_NOT_SCAN_OR_PAY"
        ) {
            Toast.makeText(
                this@QRScannerActivity,
                "⛔ DO NOT PAY — suspected scam QR.",
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    /** Small MEDIUM-risk banner for QR verdicts. */
    private fun launchBannerFromQr(verdict: RiskEngine.QrVerdict) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            !Settings.canDrawOverlays(this)
        ) {
            return
        }
        val intent = Intent(this, OverlayAlertService::class.java).apply {
            putExtra(OverlayAlertService.EXTRA_COMPACT, true)
            putExtra(OverlayAlertService.EXTRA_VPA, verdict.vpa.ifEmpty { "QR payee" })
            putExtra(OverlayAlertService.EXTRA_SCORE, verdict.score)
            putStringArrayListExtra(
                OverlayAlertService.EXTRA_REASONS,
                ArrayList(verdict.reasons.take(1)),
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun launchOverlayFromQr(verdict: RiskEngine.QrVerdict) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            !Settings.canDrawOverlays(this)
        ) {
            toast("Enable 'Display over other apps' for full-screen warnings.")
            return
        }
        val intent = Intent(this, OverlayAlertService::class.java).apply {
            putExtra(OverlayAlertService.EXTRA_VPA, verdict.vpa.ifEmpty { "QR payee" })
            putExtra(OverlayAlertService.EXTRA_SCORE, verdict.score)
            putExtra(OverlayAlertService.EXTRA_LEVEL, verdict.severity)
            putStringArrayListExtra(
                OverlayAlertService.EXTRA_REASONS,
                ArrayList(verdict.reasons.take(3)),
            )
            putStringArrayListExtra(
                OverlayAlertService.EXTRA_GUIDANCE,
                arrayListOf(verdict.guidance),
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun toast(msg: String) =
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    companion object {
        private const val TAG = "QRScanner"

        /** VPA embedded in a `pa=` tag or bare-VPA QR payload. */
        private val VPA_IN_QR = Regex("[a-zA-Z0-9.\\-_]{2,256}@[a-zA-Z]{2,64}")
    }
}
