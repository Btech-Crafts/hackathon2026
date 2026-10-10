package com.cybercrime.paymentguard

import android.content.Context
import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * On-device offline threat interception cache.
 *
 * Design: a process-wide, lock-free in-memory lookup consulted **before**
 * any network call. All hot-path reads ([isKnownScamVpa], [isHighRiskUri])
 * are `ConcurrentHashMap` gets — strictly <5 ms, no I/O, safe to call on
 * the AccessibilityService event thread.
 *
 * Contents:
 *  - Bundled high-risk VPAs (top I4C/LEA-reported scam handles shipped with
 *    the APK so day-zero installs already intercept known mules offline).
 *  - Bundled high-risk root domains / short-link hosts for QR redirect
 *    vectors (`bit.ly`, `tinyurl.com`, …).
 *  - An optional server-snapshot overlay refreshed via [updateFromServer]
 *    (e.g. nightly WorkManager sync of `/threat-stats` deltas persisted to
 *    SharedPreferences).
 *
 * Normalisation mirrors the backend (`ThreatStore`): VPAs lower-cased +
 * trimmed, phones reduced to last 10 digits, hosts lower-cased.
 */
object OfflineThreatCache {

    private const val TAG = "OfflineThreatCache"
    private const val PREFS = "payment_guard_threat_cache"
    private const val KEY_SNAPSHOT_VERSION = "snapshot_version"
    private const val KEY_SNAPSHOT_VPAS = "snapshot_vpas"

    /** Bundled scam VPAs — keep in sync with `data/mock_suspects.csv`. */
    private val BUNDLED_SCAM_VPAS: Set<String> = setOf(
        "refund-officer@ybl",
        "customs-clearance-fee@upi",
        "kyc-support01@axl",
        "army-canteen-offer@ibl",
        "phonepecashback2024@ybl",
        "rbi-refund-dept@paytm",
    )

    /** Bundled high-risk / short-link hosts for QR redirect interception. */
    private val BUNDLED_RISKY_HOSTS: Set<String> = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
        "cutt.ly", "rebrand.ly", "shorturl.at", "ow.ly",
        "buff.ly", "tiny.cc", "rb.gy", "qrco.de",
    )

    private val scamVpas = ConcurrentHashMap<String, Boolean>()
    private val riskyHosts = ConcurrentHashMap<String, Boolean>()

    @Volatile
    private var initialized = false

    // ------------------------------------------------------------------ //

    /**
     * One-time initialisation. Idempotent and cheap after the first call.
     * Loads bundled lists, then overlays the persisted server snapshot.
     */
    @Synchronized
    fun initialize(context: Context) {
        if (initialized) return
        for (vpa in BUNDLED_SCAM_VPAS) scamVpas[normalizeVpa(vpa)] = true
        for (host in BUNDLED_RISKY_HOSTS) riskyHosts[host.lowercase()] = true
        try {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            prefs.getStringSet(KEY_SNAPSHOT_VPAS, null)?.forEach { raw ->
                val key = normalizeVpa(raw)
                if (key.isNotEmpty()) scamVpas[key] = true
            }
            Log.i(TAG, "Offline cache ready: ${scamVpas.size} VPAs, ${riskyHosts.size} hosts")
        } catch (e: Exception) {
            Log.w(TAG, "Snapshot restore failed, bundled lists still active: ${e.message}")
        }
        initialized = true
    }

    /**
     * Persists a server-provided suspect delta and merges it into memory.
     * Intended for a background WorkManager sync — never call on the
     * accessibility event thread (does disk I/O).
     */
    fun updateFromServer(context: Context, suspectVpas: Set<String>, version: String) {
        val clean = suspectVpas.map(::normalizeVpa).filter { it.isNotEmpty() }.toSet()
        for (vpa in clean) scamVpas[vpa] = true
        try {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString(KEY_SNAPSHOT_VERSION, version)
                .putStringSet(KEY_SNAPSHOT_VPAS, clean)
                .apply()
        } catch (e: Exception) {
            Log.w(TAG, "Snapshot persist failed: ${e.message}")
        }
        Log.i(TAG, "Offline cache updated to $version: ${scamVpas.size} VPAs total")
    }

    // ------------------------------------------------------------------ //
    // Hot path — must stay allocation-light and I/O-free (<5 ms).
    // ------------------------------------------------------------------ //

    /**
     * Returns true when [rawVpa] is a known scam handle.
     * Normalises (lower-case + trim) before lookup; null-safe.
     */
    fun isKnownScamVpa(rawVpa: String?): Boolean {
        if (rawVpa.isNullOrBlank()) return false
        return scamVpas.containsKey(normalizeVpa(rawVpa))
    }

    /**
     * Returns true when [rawUri] is a mandate auto-debit **or** an HTTP(S)
     * redirect to a high-risk host — both interceptable fully offline.
     */
    fun isHighRiskUri(rawUri: String?): Boolean {
        if (rawUri.isNullOrBlank()) return false
        val t = rawUri.trim()
        if (t.startsWith("upi://mandate", ignoreCase = true) ||
            t.startsWith("upi:mandate", ignoreCase = true)
        ) {
            // Offline rule mirrors the backend: any mandate without an `mc=`
            // tag is treated as a hijack suspect until the server says otherwise.
            return !Regex("(?i)[?&]mc=\\d{4}").containsMatchIn(t)
        }
        if (t.startsWith("http://", ignoreCase = true) ||
            t.startsWith("https://", ignoreCase = true)
        ) {
            val host = runCatching {
                android.net.Uri.parse(t).host?.lowercase().orEmpty()
            }.getOrDefault("")
            return host.isNotEmpty() && riskyHosts.containsKey(host)
        }
        return false
    }

    /** Current memory footprint (VPAs + hosts) — for diagnostics. */
    fun size(): Int = scamVpas.size + riskyHosts.size

    // ------------------------------------------------------------------ //

    /** Lower-case + trim — mirrors backend `normalize_vpa_value`. */
    fun normalizeVpa(vpa: String): String = vpa.trim().lowercase()
}
