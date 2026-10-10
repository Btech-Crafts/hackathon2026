package com.cybercrime.paymentguard

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.Log
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Utility for decoding QR codes from gallery screenshots / saved images.
 *
 * Uses Google ML Kit Barcode Scanning (same engine as the live camera
 * scanner, so behaviour is consistent). Runs off the main thread and
 * downscales oversized bitmaps to bound memory use.
 *
 * Returns every decoded raw string (usually 0 or 1 for payment QRs).
 * Callers decide how to handle URL-redirect vs `upi://` payloads —
 * see [QrPayloadClassifier] for the client-side pre-check.
 */
object QRImageDecoder {

    private const val TAG = "QRImageDecoder"
    private const val MAX_DIMENSION_PX = 1600

    /**
     * Decodes QR/barcode strings from a content [uri] (gallery picker result).
     *
     * @return list of raw decoded values; empty when none found or on error.
     */
    suspend fun decodeFromUri(context: Context, uri: Uri): List<String> =
        withContext(Dispatchers.IO) {
            try {
                context.contentResolver.openInputStream(uri)?.use { stream ->
                    val bitmap = BitmapFactory.decodeStream(stream) ?: return@withContext emptyList<String>()
                    decodeFromBitmap(context, bitmap)
                } ?: emptyList()
            } catch (e: IOException) {
                Log.w(TAG, "Gallery decode I/O failed: ${e.message}")
                emptyList()
            } catch (e: Exception) {
                Log.w(TAG, "Gallery decode failed: ${e.message}")
                emptyList()
            }
        }

    /**
     * Decodes QR strings from an in-memory [bitmap].
     */
    suspend fun decodeFromBitmap(context: Context, bitmap: Bitmap): List<String> =
        withContext(Dispatchers.IO) {
            try {
                val scaled = downscale(bitmap)
                val image = InputImage.fromBitmap(scaled, 0)
                val options = BarcodeScannerOptions.Builder()
                    .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                    .build()
                val scanner = BarcodeScanning.getClient(options)
                try {
                    scanner.process(image).await().mapNotNull { it.rawValue }
                } finally {
                    scanner.close()
                }
            } catch (e: Exception) {
                Log.w(TAG, "Bitmap decode failed: ${e.message}")
                emptyList()
            }
        }

    private fun downscale(src: Bitmap): Bitmap {
        val w = src.width
        val h = src.height
        val longest = maxOf(w, h)
        if (longest <= MAX_DIMENSION_PX) return src
        val scale = MAX_DIMENSION_PX.toFloat() / longest
        return Bitmap.createScaledBitmap(
            src,
            (w * scale).toInt().coerceAtLeast(1),
            (h * scale).toInt().coerceAtLeast(1),
            true,
        )
    }
}

/**
 * Lightweight client-side pre-classifier so obvious redirect vectors can be
 * flagged instantly without a network round-trip.
 */
object QrPayloadClassifier {

    private val SHORT_LINK_HOSTS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
        "cutt.ly", "rebrand.ly", "shorturl.at", "ow.ly", "rb.gy",
    )

    enum class Kind { UPI_PAY, UPI_MANDATE, URL_REDIRECT, SHORT_LINK, UNKNOWN }

    /** Best-effort local classification of a decoded QR string. */
    fun classify(raw: String): Kind {
        val t = raw.trim()
        if (t.startsWith("http://", ignoreCase = true) ||
            t.startsWith("https://", ignoreCase = true)
        ) {
            val host = runCatching {
                android.net.Uri.parse(t).host?.lowercase().orEmpty()
            }.getOrDefault("")
            return if (host in SHORT_LINK_HOSTS) Kind.SHORT_LINK else Kind.URL_REDIRECT
        }
        if (t.startsWith("upi://pay", ignoreCase = true) || t.startsWith("upi:pay", ignoreCase = true)) {
            return Kind.UPI_PAY
        }
        if (t.startsWith("upi://mandate", ignoreCase = true) || t.startsWith("upi:mandate", ignoreCase = true)) {
            return Kind.UPI_MANDATE
        }
        // Bare VPA stickers (shop counters) behave like a pay intent.
        if (Regex("^[a-zA-Z0-9.\\-_]{2,256}@[a-zA-Z]{2,64}$").matches(t)) return Kind.UPI_PAY
        return Kind.UNKNOWN
    }
}
