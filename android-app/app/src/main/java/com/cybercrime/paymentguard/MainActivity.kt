package com.cybercrime.paymentguard

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.card.MaterialCardView
import com.google.android.material.textfield.TextInputEditText

/**
 * Launcher entry point for Payment Guard (fully on-device build).
 *
 * Two verification flows:
 *  1. **Check UPI ID** — paste any VPA: exact threat-cache + national sketch
 *     first, then the local [RiskEngine] verdict, color-coded in a result
 *     card. HIGH/CRITICAL pops the full overlay; MEDIUM pops the banner.
 *  2. **QR Scanner** — [QRScannerActivity] (CameraX + ML Kit + gallery).
 *
 * Only needs Display-over-apps (pop-ups) and Camera (scanner). No network.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var upiInput: TextInputEditText
    private lateinit var resultCard: MaterialCardView
    private lateinit var checkResult: TextView
    private lateinit var trustButton: Button
    private var lastCheckedVpa: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        upiInput = findViewById(R.id.upiInput)
        resultCard = findViewById(R.id.resultCard)
        checkResult = findViewById(R.id.checkResult)
        trustButton = findViewById<Button>(R.id.trustButton).apply {
            visibility = View.GONE
            setOnClickListener {
                if (lastCheckedVpa.isEmpty()) return@setOnClickListener
                val nowTrusted = !TrustedStore.isTrusted(lastCheckedVpa)
                TrustedStore.setTrusted(this@MainActivity, lastCheckedVpa, nowTrusted)
                Toast.makeText(
                    this@MainActivity,
                    if (nowTrusted) "Trusted — future checks will pass."
                    else "Trust removed.",
                    Toast.LENGTH_SHORT,
                ).show()
                checkUpiId(lastCheckedVpa)
            }
        }
        TrustedStore.init(this)

        findViewById<View>(R.id.scanButton).setOnClickListener {
            startActivity(Intent(this, QRScannerActivity::class.java))
        }
        findViewById<View>(R.id.overlayButton).setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                startActivity(
                    Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:$packageName"),
                    ),
                )
            }
        }
        findViewById<View>(R.id.checkButton).setOnClickListener {
            val vpa = upiInput.text.toString().trim()
            if (!vpa.contains("@")) {
                lastCheckedVpa = ""
                trustButton.visibility = View.GONE
                showResult("LOW", "Type a full UPI ID like name@ybl.", "")
            } else {
                checkUpiId(vpa)
            }
        }
    }

    /**
     * Fires [OverlayAlertService] with the *actual* verdict data — the same
     * card a live detection raises. Requires the overlay permission.
     */
    private fun fireVerdictOverlay(
        vpa: String,
        score: Int,
        level: String,
        reasons: List<String>,
        guidance: List<String>,
        compact: Boolean,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            !Settings.canDrawOverlays(this)
        ) {
            Toast.makeText(this, "Grant 'Display over other apps' first.", Toast.LENGTH_LONG).show()
            return
        }
        val intent = Intent(this, OverlayAlertService::class.java).apply {
            putExtra(OverlayAlertService.EXTRA_COMPACT, compact)
            putExtra(OverlayAlertService.EXTRA_VPA, vpa)
            putExtra(OverlayAlertService.EXTRA_SCORE, score)
            putExtra(OverlayAlertService.EXTRA_LEVEL, level)
            putStringArrayListExtra(OverlayAlertService.EXTRA_REASONS, ArrayList(reasons.take(3)))
            putStringArrayListExtra(OverlayAlertService.EXTRA_GUIDANCE, ArrayList(guidance.take(3)))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    override fun onResume() {
        super.onResume()
        val overlay = Build.VERSION.SDK_INT < Build.VERSION_CODES.M ||
            Settings.canDrawOverlays(this)
        val bloom = try {
            val filter = VpaBloomFilter.load(assets.open("threat_bloom.bin").use { it.readBytes() })
            OfflineThreatCache.attachBloom(filter)
            "✅ threat filter ready"
        } catch (e: Exception) {
            "⚠️ threat filter missing: ${e.message}"
        }
        statusText.text =
            "Overlay: ${if (overlay) "granted ✅" else "not granted ❌"}\n$bloom\nEngine: on-device 🔒"
    }

    /**
     * Judges a bare UPI ID fully on-device and paints the verdict card.
     * HIGH/CRITICAL also pops the full overlay; MEDIUM pops the banner.
     */
    private fun checkUpiId(vpa: String) {
        lastCheckedVpa = vpa
        val trusted = TrustedStore.isTrusted(vpa)
        val verdict = RiskEngine.evaluateVpa(
            rawVpa = vpa,
            isKnownSuspect = OfflineThreatCache.isKnownScamVpa(vpa),
            isSketchMatch = OfflineThreatCache.isSketchMatch(vpa),
            isTrusted = trusted,
        )
        val headline = "$vpa → ${verdict.level} (${verdict.score}/100)"
        val detail = verdict.reasons.take(2).joinToString("\n")
        showResult(verdict.level, headline, detail)
        trustButton.visibility = View.VISIBLE
        trustButton.text = if (trusted) "Trusted ✓ — tap to remove" else "Trust this ID"
        if (verdict.level == "HIGH" || verdict.level == "CRITICAL") {
            fireVerdictOverlay(vpa, verdict.score, verdict.level, verdict.reasons, verdict.guidance, compact = false)
        } else if (verdict.level == "MEDIUM") {
            fireVerdictOverlay(vpa, verdict.score, verdict.level, verdict.reasons, verdict.guidance, compact = true)
        } else if (!trusted) {
            Toast.makeText(
                this,
                "No known risk — pay only if you trust this ID.",
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    /** Paints the verdict card: green / amber / orange-red by severity. */
    private fun showResult(level: String, headline: String, detail: String) {
        val (bg, fg) = when (level) {
            "CRITICAL", "HIGH" -> R.color.risk_critical to android.R.color.white
            "MEDIUM" -> R.color.risk_medium to R.color.risk_medium_text
            else -> R.color.risk_safe to android.R.color.white
        }
        val icon = when (level) {
            "CRITICAL", "HIGH" -> "🛑 "
            "MEDIUM" -> "⚠️ "
            else -> "✅ "
        }
        resultCard.setCardBackgroundColor(ContextCompat.getColor(this, bg))
        resultCard.visibility = View.VISIBLE
        checkResult.setTextColor(ContextCompat.getColor(this, fg))
        checkResult.text = if (detail.isBlank()) "$icon$headline" else "$icon$headline\n\n$detail"
    }
}
