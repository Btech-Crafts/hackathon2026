package com.cybercrime.paymentguard

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * User + organization trust list (allowlist).
 *
 * Why it exists: the engine can only prove *badness*, never goodness — every
 * ID it hasn't seen is UNVERIFIED. But the user *knows* some payees (their
 * organization's official VPA, family, regular vendors). Trusting an ID
 * short-circuits scoring to a verified-LOW verdict instead of warning.
 *
 * Two tiers:
 *  - [ORG_TRUSTED_VPAS]: compiled-in official IDs. **Your organization must
 *    fill this in before release** with its verified VPAs (lowercase).
 *  - User-added: persisted in SharedPreferences via [setTrusted]; survives
 *    restarts, never leaves the phone.
 *
 * Normalisation mirrors the engine (trim + lowercase). Exact-match only —
 * trusting `shop@upi` never trusts `shop-support@upi`.
 */
object TrustedStore {

    /** TODO(RELEASE): put your organization's official VPAs here, lowercase. */
    val ORG_TRUSTED_VPAS: Set<String> = setOf(
        // e.g. "payments@yourcompany",
    )

    private const val PREFS = "payment_guard_trusted"
    private const val KEY_IDS = "trusted_vpas"

    private val memory = ConcurrentHashMap<String, Boolean>()

    @Volatile
    private var loaded = false

    /** One-time load: bundled org IDs + user-saved set. Idempotent. */
    @Synchronized
    fun init(context: Context) {
        if (loaded) return
        for (vpa in ORG_TRUSTED_VPAS) {
            val key = norm(vpa)
            if (key.isNotEmpty()) memory[key] = true
        }
        try {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getStringSet(KEY_IDS, null)
                ?.forEach { raw ->
                    val key = norm(raw)
                    if (key.isNotEmpty()) memory[key] = true
                }
        } catch (_: Exception) {
            // Prefs unreadable — bundled IDs still active.
        }
        loaded = true
    }

    /** True when the user or org has explicitly vouched for this VPA. */
    fun isTrusted(rawVpa: String?): Boolean {
        if (rawVpa.isNullOrBlank()) return false
        return memory.containsKey(norm(rawVpa))
    }

    /**
     * Adds or removes a user trust entry (disk I/O — call off the hot path;
     * the in-memory map updates synchronously so checks stay instant).
     */
    fun setTrusted(context: Context, rawVpa: String, trusted: Boolean) {
        val key = norm(rawVpa)
        if (key.isEmpty()) return
        if (trusted) memory[key] = true else memory.remove(key)
        try {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val current = prefs.getStringSet(KEY_IDS, emptySet())?.toMutableSet() ?: mutableSetOf()
            if (trusted) current.add(key) else current.remove(key)
            prefs.edit().putStringSet(KEY_IDS, current).apply()
        } catch (_: Exception) {
            // Persist failed — memory entry still holds for this session.
        }
    }

    fun norm(vpa: String): String = vpa.trim().lowercase()
}
