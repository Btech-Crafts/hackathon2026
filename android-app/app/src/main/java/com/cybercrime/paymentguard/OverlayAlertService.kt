package com.cybercrime.paymentguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.app.NotificationCompat

/**
 * Foreground [Service] rendering a non-intrusive floating warning over the
 * payment interface when the backend returns HIGH / CRITICAL risk.
 *
 * Uses `WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY` (requires
 * `SYSTEM_ALERT_WINDOW`). The card shows the risk severity colour band,
 * masked payee id, score, top reasons and guidance, plus two actions:
 *  - **Go Back** (dismiss, user returns to the payment app to cancel)
 *  - **Dismiss** (minimise; the notification persists while at risk)
 *
 * The overlay never auto-performs clicks inside the payment app and never
 * captures credentials — it is purely informational.
 */
class OverlayAlertService : Service() {

    private var windowManager: WindowManager? = null
    private var overlayView: LinearLayout? = null
    private val handler = Handler(Looper.getMainLooper())
    private var autoDismiss: Runnable? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        startAsForeground()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        removeOverlay()
        if (intent.getBooleanExtra(EXTRA_COMPACT, false)) {
            showCompactBanner(
                vpa = intent.getStringExtra(EXTRA_VPA).orEmpty(),
                score = intent.getIntExtra(EXTRA_SCORE, 0),
                reason = intent.getStringArrayListExtra(EXTRA_REASONS)?.firstOrNull()
                    ?: "This payee looks suspicious. Verify before paying.",
            )
        } else {
            showOverlay(
                vpa = intent.getStringExtra(EXTRA_VPA).orEmpty(),
                amount = if (intent.hasExtra(EXTRA_AMOUNT)) intent.getDoubleExtra(EXTRA_AMOUNT, 0.0) else null,
                score = intent.getIntExtra(EXTRA_SCORE, 0),
                level = intent.getStringExtra(EXTRA_LEVEL) ?: "HIGH",
                reasons = intent.getStringArrayListExtra(EXTRA_REASONS) ?: arrayListOf(),
                guidance = intent.getStringArrayListExtra(EXTRA_GUIDANCE) ?: arrayListOf(),
            )
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        removeOverlay()
        super.onDestroy()
    }

    // ------------------------------------------------------------------ //

    private fun startAsForeground() {
        val channelId = "payment_guard_alerts"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId, "Payment Safety Alerts", NotificationManager.IMPORTANCE_LOW,
            )
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
        val notification: Notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("Payment Guard active")
            .setContentText("Monitoring payment screens for scam risk.")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun showOverlay(
        vpa: String,
        amount: Double?,
        score: Int,
        level: String,
        reasons: List<String>,
        guidance: List<String>,
    ) {
        val wm = windowManager ?: return
        val isCritical = level == "CRITICAL"
        val accent = if (isCritical) Color.parseColor("#C62828") else Color.parseColor("#EF6C00")

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#FFFFFF"))
            elevation = 12f
            val pad = dp(16)
            setPadding(pad, pad, pad, pad)
        }

        fun addText(text: String, sizeSp: Float, color: Int, bold: Boolean = false) {
            card.addView(TextView(this).apply {
                this.text = text
                textSize = sizeSp
                setTextColor(color)
                if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            })
        }

        // Severity band.
        card.addView(TextView(this).apply {
            text = if (isCritical) "⛔ CRITICAL RISK — DO NOT PAY" else "⚠️ HIGH RISK — PAUSE & VERIFY"
            setBackgroundColor(accent)
            setTextColor(Color.WHITE)
            textSize = 15f
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            val pad = dp(8)
            setPadding(pad, pad, pad, pad)
        })

        val amountLine = if (amount != null) " • ₹${"%,.2f".format(amount)}" else ""
        addText("Payee: ${maskVpa(vpa)}$amountLine", 14f, Color.parseColor("#212121"), bold = true)
        addText("Risk score: $score / 100 ($level)", 13f, accent, bold = true)

        if (reasons.isNotEmpty()) {
            addText("Why am I at risk?", 13f, Color.BLACK, bold = true)
            reasons.take(3).forEach { addText("• $it", 12.5f, Color.parseColor("#424242")) }
        }
        if (guidance.isNotEmpty()) {
            addText("What should I do?", 13f, Color.BLACK, bold = true)
            guidance.take(3).forEach { addText("✔ $it", 12.5f, Color.parseColor("#2E7D32")) }
        }
        addText("Receiving money NEVER needs a UPI PIN.", 12f, Color.parseColor("#616161"))

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
        }
        val goBack = Button(this).apply {
            text = "Go Back"
            setOnClickListener {
                // Return user to the payment app task so they can cancel there.
                sendBroadcast(Intent(ACTION_USER_GO_BACK))
                stopSelf()
            }
        }
        val dismiss = Button(this).apply {
            text = "Dismiss"
            setOnClickListener { stopSelf() }
        }
        row.addView(goBack)
        row.addView(dismiss)
        card.addView(row)

        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
            y = dp(48)
        }
        overlayView = card
        wm.addView(card, params)
    }

    private fun removeOverlay() {
        try {
            autoDismiss?.let { handler.removeCallbacks(it) }
        } catch (_: Exception) {
            // Nothing scheduled — safe to ignore.
        } finally {
            autoDismiss = null
        }
        try {
            overlayView?.let { windowManager?.removeView(it) }
        } catch (_: Exception) {
            // View already removed — safe to ignore.
        } finally {
            overlayView = null
        }
    }

    /**
     * Small non-blocking caution banner for MEDIUM risk: one line + tap to
     * dismiss, auto-vanishes after 8 s. Sits at the bottom so it never
     * covers the payee details the user is reading.
     */
    private fun showCompactBanner(vpa: String, score: Int, reason: String) {
        val wm = windowManager ?: return
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor("#FFF8E1"))
            elevation = 10f
            val pad = dp(12)
            setPadding(pad, pad, pad, pad)
        }
        row.addView(TextView(this).apply {
            text = "⚠️ Caution ($score/100): ${maskVpa(vpa)} — $reason"
            textSize = 13f
            setTextColor(Color.parseColor("#5D4037"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })
        row.addView(Button(this).apply {
            text = "✕"
            setOnClickListener { stopSelf() }
        })
        row.setOnClickListener { stopSelf() }

        overlayView = row
        wm.addView(row, bottomParams())
        val task = Runnable { stopSelf() }
        autoDismiss = task
        handler.postDelayed(task, COMPACT_AUTO_DISMISS_MS)
    }

    private fun bottomParams(): WindowManager.LayoutParams {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        return WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL
            y = dp(64)
        }
    }

    /** Masks the local part of a VPA, keeping first 2 chars: "re***@ybl". */
    private fun maskVpa(vpa: String): String {
        val at = vpa.indexOf('@')
        if (at <= 2) return "***"
        return vpa.take(2) + "***" + vpa.substring(at)
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    companion object {
        const val EXTRA_VPA = "extra_vpa"
        const val EXTRA_AMOUNT = "extra_amount"
        const val EXTRA_SCORE = "extra_score"
        const val EXTRA_LEVEL = "extra_level"
        const val EXTRA_REASONS = "extra_reasons"
        const val EXTRA_GUIDANCE = "extra_guidance"

        /** When true, renders the small auto-dismissing caution banner. */
        const val EXTRA_COMPACT = "extra_compact"

        /** Broadcast observed by the payment app hook / user to navigate back. */
        const val ACTION_USER_GO_BACK = "com.cybercrime.paymentguard.ACTION_USER_GO_BACK"

        private const val NOTIFICATION_ID = 1001
        private const val COMPACT_AUTO_DISMISS_MS = 8_000L
    }
}
