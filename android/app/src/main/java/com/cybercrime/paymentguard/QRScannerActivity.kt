package com.cybercrime.paymentguard

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
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
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.concurrent.Executors

/**
 * Dedicated QR scanner: CameraX preview + ML Kit barcode reader, plus a
 * gallery-image picker for screenshots / forwarded QR images.
 *
 * Flow:
 *  1. Decodes the QR string (live or gallery).
 *  2. Runs the client-side [QrPayloadClassifier] pre-check — short-links and
 *     URL redirects get an instant local warning banner.
 *  3. Forwards the raw payload to `POST /api/v1/qr/decode-and-evaluate`
 *     with the user's `expected_action` context (RECEIVE vs PAY toggle).
 *  4. Renders the backend verdict (score / severity / risk factors) and
 *     launches [OverlayAlertService] on HIGH / CRITICAL.
 *
 * Privacy: only the decoded QR *string* is transmitted — never the raw image.
 */
class QRScannerActivity : AppCompatActivity() {

    private lateinit var previewView: PreviewView
    private lateinit var statusText: TextView
    private lateinit var expectedToggle: Button

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

        previewView = PreviewView(this)
        statusText = TextView(this).apply {
            text = "Point the camera at a UPI QR…"
            textSize = 14f
            gravity = Gravity.CENTER
            setPadding(24, 24, 24, 24)
        }
        expectedToggle = Button(this).apply {
            text = "I expect: PAY (tap → RECEIVE)"
            setOnClickListener {
                expectedAction = if (expectedAction == "PAY") "RECEIVE" else "PAY"
                text = "I expect: $expectedAction (tap to toggle)"
            }
        }
        val galleryButton = Button(this).apply {
            text = "Pick from gallery"
            setOnClickListener { pickGalleryImage.launch("image/*") }
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(
                previewView,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f,
                ),
            )
            addView(statusText)
            addView(expectedToggle)
            addView(galleryButton)
        }
        setContentView(FrameLayout(this).apply { addView(layout) })

        // Warm the offline cache so QR payloads are intercepted without network.
        OfflineThreatCache.initialize(this)

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
        lifecycleScope.launch { evaluateWithBackend(raw) }
    }

    private suspend fun evaluateWithBackend(rawPayload: String) {
        val result = postQrEvaluate(rawPayload, expectedAction)
        withContext(Dispatchers.Main) {
            if (result == null) {
                statusText.text = "Evaluation failed — check network / server."
                return@withContext
            }
            val score = result.optInt("risk_score", 0)
            val severity = result.optString("severity", "UNKNOWN")
            val isRc = result.optBoolean("is_reverse_collect_scam", false)
            val factors = result.optJSONArray("risk_factors")?.let { arr ->
                (0 until arr.length()).joinToString(", ") { arr.optString(it) }
            }.orEmpty()
            statusText.text =
                "Score $score ($severity) • reverse-collect=$isRc\nFactors: $factors"

            if (severity == "HIGH" || severity == "CRITICAL") {
                launchOverlayFromQr(result)
            }
            if (kindRequiresHardStop(result)) {
                Toast.makeText(
                    this@QRScannerActivity,
                    "⛔ DO NOT PAY — suspected scam QR.",
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    private fun kindRequiresHardStop(result: JSONObject): Boolean =
        result.optBoolean("is_reverse_collect_scam", false) ||
            result.optString("guidance", "") == "DO_NOT_SCAN_OR_PAY"

    /** POSTs the raw QR string; images are never uploaded (privacy). */
    private suspend fun postQrEvaluate(rawPayload: String, expected: String): JSONObject? =
        withContext(Dispatchers.IO) {
            var conn: HttpURLConnection? = null
            try {
                // Send as form-encoded (server also accepts JSON).
                val body = "payload=${URLEncoder.encode(rawPayload, "UTF-8")}" +
                    "&expected_action=${URLEncoder.encode(expected, "UTF-8")}"
                conn = (URL(QR_ENDPOINT).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 6_000
                    readTimeout = 8_000
                    doOutput = true
                    setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                }
                OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }
                if (conn.responseCode != HttpURLConnection.HTTP_OK) {
                    Log.w(TAG, "QR backend HTTP ${conn.responseCode}")
                    // Fallback: retry as JSON (older server builds).
                    return@withContext postQrEvaluateJson(rawPayload, expected)
                }
                JSONObject(conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() })
            } catch (e: Exception) {
                Log.e(TAG, "QR evaluate failed", e)
                null
            } finally {
                conn?.disconnect()
            }
        }

    private suspend fun postQrEvaluateJson(rawPayload: String, expected: String): JSONObject? =
        withContext(Dispatchers.IO) {
            var conn: HttpURLConnection? = null
            try {
                val body = JSONObject()
                    .put("payload", rawPayload)
                    .put("expected_action", expected)
                    .toString()
                conn = (URL(QR_ENDPOINT).openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 6_000
                    readTimeout = 8_000
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                }
                OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }
                if (conn.responseCode != HttpURLConnection.HTTP_OK) return@withContext null
                JSONObject(conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() })
            } catch (e: Exception) {
                Log.w(TAG, "QR JSON fallback failed: ${e.message}")
                null
            } finally {
                conn?.disconnect()
            }
        }

    private fun launchOverlayFromQr(result: JSONObject) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            !Settings.canDrawOverlays(this)
        ) {
            toast("Enable 'Display over other apps' for full-screen warnings.")
            return
        }
        val reasons = result.optJSONArray("reasons")?.let { arr ->
            arrayListOf<String>().also { list ->
                for (i in 0 until arr.length()) list.add(arr.optString(i))
            }
        } ?: arrayListOf()
        val intent = Intent(this, OverlayAlertService::class.java).apply {
            putExtra(OverlayAlertService.EXTRA_VPA, result.optString("vpa", "QR payee"))
            putExtra(OverlayAlertService.EXTRA_SCORE, result.optInt("risk_score", 0))
            putExtra(OverlayAlertService.EXTRA_LEVEL, result.optString("severity", "HIGH"))
            putStringArrayListExtra(OverlayAlertService.EXTRA_REASONS, ArrayList(reasons.take(3)))
            putStringArrayListExtra(
                OverlayAlertService.EXTRA_GUIDANCE,
                arrayListOf(result.optString("guidance", "")),
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
        private const val QR_ENDPOINT = "http://10.0.2.2:8000/api/v1/qr/decode-and-evaluate"

        /** VPA embedded in a `pa=` tag or bare-VPA QR payload. */
        private val VPA_IN_QR = Regex("[a-zA-Z0-9.\\-_]{2,256}@[a-zA-Z]{2,64}")
    }
}
