package com.cybercrime.paymentguard

import java.net.URLDecoder
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import kotlin.math.max
import kotlin.math.min

/**
 * Fully on-device risk engine — a faithful Kotlin port of the backend
 * pipeline (`heuristics.py` + `qr_analyzer.py` + `mandate_analyzer.py` +
 * `anomaly_detector.py` + `scorer.py`).
 *
 * No network, no database, no permissions: every function is a pure
 * computation over the supplied strings, so verdicts land in microseconds
 * and work in flight mode. Rule codes, weights, thresholds and floors mirror
 * the server exactly; keep the two in sync when either changes.
 *
 * Known-suspect status is supplied by the caller (usually
 * [OfflineThreatCache.isKnownScamVpa]) so this engine stays free of Android
 * dependencies and unit-testable as plain JVM code.
 */
object RiskEngine {

    // ------------------------------------------------------------------ //
    // Verdicts
    // ------------------------------------------------------------------ //

    data class VpaVerdict(
        val score: Int,
        val level: String, // LOW | MEDIUM | HIGH | CRITICAL
        val flags: List<String>,
        val reasons: List<String>,
        val guidance: List<String>,
    )

    data class QrVerdict(
        val vpa: String,
        val payeeName: String,
        val amount: String?,
        val isReverseCollectScam: Boolean,
        val isMandateHijack: Boolean,
        val mccStatus: String,
        val score: Int,
        val severity: String, // LOW | MEDIUM | HIGH | CRITICAL
        val factors: List<String>,
        val guidance: String, // SAFE_TO_PROCEED | VERIFY_AND_PROCEED_WITH_CAUTION
        // | DO_NOT_PAY_VERIFY_FIRST | DO_NOT_SCAN_OR_PAY
        val reasons: List<String>,
    )

    // ------------------------------------------------------------------ //
    // Shared constants (mirrors backend)
    // ------------------------------------------------------------------ //

    private val VPA_RE = Regex("^[a-zA-Z0-9.\\-_]{2,256}@[a-zA-Z]{2,64}$")
    private val MCC_RE = Regex("^\\d{4}$")

    private val TRUSTED_PSP = setOf(
        "okhdfcbank", "okicici", "oksbi", "okaxisbank", "okaxis", "ybl", "ibl",
        "axl", "apl", "upi", "paytm", "phonepe", "airtel", "jio", "slice",
        "navi", "cred", "superyes", "yesbank", "idfcbank", "cmsidfc", "indus",
        "hsbc", "dbs", "freecharge", "mobikwik", "kotak", "rbl", "federal",
        "pnb", "bob", "canara", "unionbank", "okbizaxis", "sbi", "hdfc", "icici",
    )
    private val PERSONAL_PSP = setOf("ybl", "ibl", "axl", "apl", "upi", "paytm", "phonepe")
    private val P2P_HANDLES = setOf(
        "ybl", "ibl", "axl", "apl", "upi", "paytm", "phonepe",
        "okhdfcbank", "okicici", "oksbi", "okaxis", "okaxisbank",
    )
    private val IMPERSONATION = setOf(
        "refund", "custom", "customs", "support", "kyc", "rbi", "bank",
        "officer", "army", "navy", "airforce", "police", "cbi", "incometax",
        "income", "gst", "electricity", "loan", "prize", "lottery", "cashback",
        "reward", "verif", "blocked", "suspend", "helpline", "care", "service",
        "claim", "bonus", "offer",
    )
    private val BRANDS = setOf(
        "gpay", "googlepay", "googlepe", "phonepe", "phonepay", "paytm",
        "paytem", "bhim", "upi", "rbi", "sbi", "hdfc", "icici", "axis",
        "amazon", "flipkart",
    )
    private val PRESSURE = setOf(
        "urgent", "immediately", "secret", "otp", "pin", "cvv", "expir",
        "last chance", "block", "suspend", "do not tell", "dont tell", "confidential",
    )
    private val CREDIT_LURE = setOf(
        "receive refund", "cashback credit", "cashback credited", "lottery prize",
        "reward release", "claim bonus", "claim your bonus", "cashback",
        "refund credit", "prize money", "you have won", "you've won",
        "reward points credit",
    )
    private val CORPORATE = setOf(
        "electricity", "power", "utility", "utilities", "board", "nigam",
        "municipal", "gas", "water", "telecom", "airtel", "jio", "vodafone",
        "bsnl", "broadband", "bank", "insurance", "department", "dept",
        "support", "customercare", "customer care", "service centre",
        "service center", "pvt", "ltd", "limited", "store", "official",
    )
    private val SHORT_LINKS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
        "rebrand.ly", "shorturl.at", "ow.ly", "buff.ly", "tiny.cc", "rb.gy", "qrco.de",
    )
    private val KNOWN_MCC = mapOf(
        "5411" to "Grocery / supermarkets", "5812" to "Restaurants",
        "5912" to "Pharmacies", "4111" to "Transport / utilities",
        "4900" to "Utilities (electric/gas/water)",
        "6012" to "Banks / financial institutions", "6011" to "ATMs / cash",
        "7995" to "Gambling / betting (high-risk)",
        "4829" to "Money transfer / remittance", "7372" to "Computer / IT services",
        "5732" to "Electronics", "5651" to "Clothing", "5541" to "Fuel",
        "5814" to "Fast food",
    )
    private val CRITICAL_TAGS = setOf(
        "pa", "pn", "mc", "am", "cu", "tn", "tr", "mode", "recurrence",
        "validitystart", "validityend", "share", "sign",
    )
    private val ZERO_WIDTH = setOf('\u200B', '\u200C', '\u200D', '\uFEFF')

    // ------------------------------------------------------------------ //
    // Small helpers
    // ------------------------------------------------------------------ //

    private fun norm(vpa: String) = vpa.trim().lowercase()
    private fun handleOf(vpa: String?): String? =
        if (vpa != null && "@" in vpa) vpa.substringAfterLast("@").lowercase() else null
    private fun localOf(vpa: String?): String =
        if (vpa != null && "@" in vpa) vpa.substringBeforeLast("@") else (vpa ?: "")

    private fun hit(haystack: String, needles: Set<String>): String? {
        val h = haystack.lowercase()
        return needles.firstOrNull { it in h }
    }

    /** Bounded Levenshtein (early exit above 2) — mirrors the backend. */
    internal fun levLe2(a: String, b: String): Int {
        if (a == b) return 0
        if (kotlin.math.abs(a.length - b.length) > 2) return 3
        var prev = IntArray(b.length + 1) { it }
        for (i in 1..a.length) {
            val cur = IntArray(b.length + 1)
            cur[0] = i
            var rowMin = i
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                cur[j] = min(min(prev[j] + 1, cur[j - 1] + 1), prev[j - 1] + cost)
                rowMin = min(rowMin, cur[j])
            }
            if (rowMin > 2) return 3
            prev = cur
        }
        return prev[b.length]
    }

    private fun levelOf(score: Int): String = when {
        score >= 80 -> "CRITICAL"
        score >= 60 -> "HIGH"
        score >= 30 -> "MEDIUM"
        else -> "LOW"
    }

    private fun guidanceOf(severity: String, hardStop: Boolean): String = when {
        hardStop || severity == "CRITICAL" -> "DO_NOT_SCAN_OR_PAY"
        severity == "HIGH" -> "DO_NOT_PAY_VERIFY_FIRST"
        severity == "MEDIUM" -> "VERIFY_AND_PROCEED_WITH_CAUTION"
        else -> "SAFE_TO_PROCEED"
    }

    private fun parseAmount(am: String?): Double? =
        try {
            am?.replace(",", "")?.trim()?.toDouble()
        } catch (_: Exception) {
            null
        }

    // ------------------------------------------------------------------ //
    // VPA evaluation — mirrors heuristics.py + scorer.py
    // ------------------------------------------------------------------ //

    /**
     * Scores a bare payee VPA. [expectedIncoming] must be true when the user
     * was promised incoming funds (lure words detected by the caller).
     */
    fun evaluateVpa(
        rawVpa: String,
        amount: Double? = null,
        payeeName: String? = null,
        note: String? = null,
        mcc: String? = null,
        expectedIncoming: Boolean = false,
        isKnownSuspect: Boolean = false,
        isSketchMatch: Boolean = false,
        isTrusted: Boolean = false,
    ): VpaVerdict {
        // Explicit user/org trust beats every heuristic — the human vouched.
        if (isTrusted) {
            return VpaVerdict(
                0, "LOW", listOf("TRUSTED_PAYEE"),
                listOf("This payee is in your trusted list — verified by you or your organization."),
                listOf("Proceed — you marked this payee as trusted."),
            )
        }
        val vpa = norm(rawVpa)
        val flags = mutableListOf<String>()
        val reasons = mutableListOf<String>()
        val guidance = mutableListOf<String>()
        var score = 0
        fun add(code: String, w: Int, r: String, g: String) {
            flags.add(code); reasons.add(r)
            if (g !in guidance) guidance.add(g)
            score += w
        }

        val local = localOf(vpa)
        val handle = handleOf(vpa)

        // Rule 1 — syntax & handle.
        if (!VPA_RE.matches(vpa)) {
            add(
                "INVALID_VPA_SYNTAX", 25,
                "Payee ID '$vpa' has an invalid UPI format.",
                "Stop. Ask the payee for their correct UPI ID and verify it via a trusted channel before paying.",
            )
            return VpaVerdict(min(100, score), levelOf(min(100, score)), flags, reasons, guidance)
        }
        if (handle !in TRUSTED_PSP) {
            add(
                "UNTRUSTED_PSP_HANDLE", 15,
                "Handle '@$handle' is not a recognised PSP/bank handle.",
                "Be cautious with unfamiliar handles. Verify the payee's identity independently before proceeding.",
            )
        }

        // Rule 2 — impersonation / typosquat.
        if (local.isNotEmpty()) {
            val combined = listOf(local, payeeName ?: "", note ?: "").filter { it.isNotEmpty() }.joinToString(" ")
            val keyword = hit(combined, IMPERSONATION)
            val brand = hit(local, BRANDS)
            val personal = handle in PERSONAL_PSP
            if (keyword != null && personal && mcc == null) {
                add(
                    "IMPERSONATION_KEYWORD", 30,
                    "Payee ID contains authority keyword '$keyword' on personal handle '@$handle' with no merchant credentials.",
                    "Banks, RBI, customs and KYC teams never collect money over personal UPI IDs. Do not pay; verify via the official helpline.",
                )
            } else if (keyword != null && mcc == null) {
                add(
                    "IMPERSONATION_KEYWORD_UNVERIFIED", 15,
                    "Payee context contains sensitive keyword '$keyword' without merchant verification.",
                    "Independently verify any caller claiming refunds, KYC or customs fees before paying.",
                )
            }
            if (brand == null) {
                outer@ for (token in BRANDS) {
                    for (frag in local.lowercase().split(Regex("[^a-z0-9]+"))) {
                        if (frag.isEmpty() || frag == token) continue
                        if (frag.length >= 4 && levLe2(frag, token) in 1..2) {
                            add(
                                "TYPOSQUAT_HANDLE", 25,
                                "Payee handle '$frag' closely mimics trusted brand '$token' — a common impersonation trick.",
                                "Type the official UPI ID yourself from the company's verified website/app instead of using this one.",
                            )
                            break@outer
                        }
                    }
                }
            }
        }

        // Rule 3 — reverse-collect.
        val lure = hit(note ?: "", setOf("receive", "refund", "cashback", "prize", "reward", "collect", "incoming", "credit"))
        if (expectedIncoming) {
            add(
                "REVERSE_COLLECT_SCAM", 35,
                "You were promised incoming money, but this sends money OUT of your account (entering your UPI PIN will debit you).",
                "STOP — to RECEIVE money you never enter a UPI PIN. Decline this request and do not authorise it.",
            )
        } else if (lure != null) {
            add(
                "SUSPICIOUS_CREDIT_LURE", 15,
                "Payment note promises '$lure' yet this is an outgoing payment.",
                "If someone promised you money, they should be SENDING it, not asking you to pay.",
            )
        }

        // Rule 4 — MCC vs identity.
        val corpHit = corporateClaim(payeeName, vpa)
        val merchantHint = hit(payeeName ?: "", setOf("ltd", "pvt", "store", "mart", "shop", "merchant", "bazaar", "traders", "enterprise"))
        if ((merchantHint != null || corpHit != null) && mcc == null) {
            add(
                "MISSING_MCC", 12,
                "Payee claims to be a business/authority but shows no Merchant Category Code (unverified personal account).",
                "Genuine merchants show verified business details. Ask for an invoice and pay only via the official checkout link.",
            )
        }

        // Rule 5 — pressure language.
        hit(note ?: "", PRESSURE)?.let {
            add(
                "PRESSURE_LANGUAGE", 10,
                "Payment note uses pressure/secrecy language ('$it') typical of scams.",
                "Scammers create urgency so you don't verify. Pause, and call the organisation on its official number.",
            )
        }

        // Rule 6 — amount.
        if (amount != null) {
            if (amount >= 50000) {
                add("HIGH_AMOUNT", 10, "High-value payment of ₹$amount — errors and fraud are costlier at this size.", "Split-verify: confirm the payee on a second channel before authorising large amounts.")
            } else if (amount >= 10000) {
                add("ELEVATED_AMOUNT", 5, "Elevated payment of ₹$amount.", "Double-check the payee VPA character-by-character before entering your PIN.")
            }
        }

        // Rule 7 — random-looking handle (UNVERIFIED, never "safe").
        if (local.isNotEmpty() && !local.all { it.isDigit() }) {
            val alpha = local.lowercase().filter { it in 'a'..'z' }
            if (alpha.length >= 6 && alpha.none { it in "aeiou" }) {
                add(
                    "RANDOM_LOOKING_HANDLE", 30,
                    "Payee handle '${local.take(32)}' looks auto-generated (unpronounceable, UNVERIFIED, no reputation trail).",
                    "Treat this ID as UNVERIFIED, not safe. Pay only if you got this ID from a source you trust.",
                )
            } else {
                val digits = local.count { it.isDigit() }
                if (local.length >= 10 && digits.toDouble() / local.length >= 0.7) {
                    add(
                        "MACHINE_MINTED_HANDLE", 20,
                        "Payee handle '${local.take(32)}' is mostly digits — a machine-minted shape with no reputation trail.",
                        "Pay only if you independently trust the source of this ID.",
                    )
                }
            }
        }

        if (isKnownSuspect) {
            score += 80
            flags.add(0, "KNOWN_SUSPECT_VPA")
            reasons.add(0, "This payee ID is flagged in the on-device threat list of reported scam handles.")
            guidance.add(0, "Do NOT pay this ID. Report it in the app and at cybercrime.gov.in or by calling 1930 (India).")
        } else if (isSketchMatch) {
            score += 15
            flags.add("NATIONAL_SKETCH_MATCH")
            reasons.add("Possible match in the national suspect sketch — treat with extra caution.")
        }

        score = max(0, min(100, score))
        if (reasons.isEmpty()) {
            reasons.add("No known scam patterns matched and this ID is not in the threat list — but it is UNVERIFIED, not proven safe.")
        }
        if (guidance.isEmpty()) {
            guidance.add("Only proceed if you received this ID from a source you trust. When in doubt, call the payee on a separately known number first.")
        }
        if (levelOf(score) != "LOW" && "Never share your UPI PIN or OTP — receiving money never needs a PIN." !in guidance) {
            guidance.add("Never share your UPI PIN or OTP — receiving money never needs a PIN.")
        }
        return VpaVerdict(score, levelOf(score), flags.toList(), reasons.toList(), guidance.toList())
    }

    /** Corporate-claim keyword over display name + VPA local part only. */
    private fun corporateClaim(payeeName: String?, vpa: String?): String? {
        val hay = "${payeeName ?: ""} ${localOf(vpa)}".lowercase()
        return CORPORATE.sortedByDescending { it.length }.firstOrNull { it.isNotEmpty() && it in hay }
    }

    // ------------------------------------------------------------------ //
    // QR evaluation — mirrors qr_analyzer + mandate + anomaly + merchant
    // ------------------------------------------------------------------ //

    private enum class Kind { PAY, MANDATE, URL, UNKNOWN }

    private class Intent(
        val kind: Kind,
        val pa: String? = null,
        val pn: String? = null,
        val mc: String? = null,
        val am: String? = null,
        val tr: String? = null,
        val cu: String? = null,
        val tn: String? = null,
        val urlHost: String? = null,
        val isShortLink: Boolean = false,
    )

    private fun first(params: Map<String, List<String>>, key: String): String? {
        val v = params[key]?.firstOrNull()?.trim()
        return if (v.isNullOrEmpty()) null else v
    }

    private fun parseUpi(raw: String): Intent {
        val text = raw.trim()
        if (text.isEmpty()) return Intent(Kind.UNKNOWN)
        val low = text.lowercase()
        if (low.startsWith("http://") || low.startsWith("https://")) {
            val host = try {
                android.net.Uri.parse(text).host?.lowercase()
            } catch (_: Exception) {
                null
            }
            return Intent(Kind.URL, urlHost = host, isShortLink = host in SHORT_LINKS)
        }
        val m = Regex("(?i)^upi:(?://)?([a-z]+)\\?(.*)$", RegexOption.DOT_MATCHES_ALL).find(text)
            ?: return if (VPA_RE.matches(text)) Intent(Kind.PAY, pa = text) else Intent(Kind.UNKNOWN)
        val scheme = m.groupValues[1].lowercase()
        if (scheme !in setOf("pay", "mandate", "collect", "autopay")) return Intent(Kind.UNKNOWN)
        val params = mutableMapOf<String, MutableList<String>>()
        for (pair in m.groupValues[2].split("&")) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            val k = (if (eq < 0) pair else pair.substring(0, eq)).trim().lowercase()
            val v = try {
                URLDecoder.decode(if (eq < 0) "" else pair.substring(eq + 1), "UTF-8")
            } catch (_: Exception) {
                if (eq < 0) "" else pair.substring(eq + 1)
            }
            params.getOrPut(k) { mutableListOf() }.add(v)
        }
        val kind = if (scheme == "mandate" || scheme == "autopay") Kind.MANDATE else Kind.PAY
        return Intent(
            kind,
            pa = first(params, "pa"), pn = first(params, "pn"), mc = first(params, "mc"),
            am = first(params, "am"), tr = first(params, "tr"), cu = first(params, "cu"),
            tn = first(params, "tn"),
        )
    }

    /** Duplicate critical params (parser-differential attack) from raw query. */
    private fun duplicateTags(raw: String): Map<String, List<String>> {
        val m = Regex("(?i)^upi:(?://)?[a-z]+\\?(.*)$", RegexOption.DOT_MATCHES_ALL).find(raw.trim())
            ?: return emptyMap()
        val grouped = mutableMapOf<String, MutableList<String>>()
        for (pair in m.groupValues[1].split("&")) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            val k = (if (eq < 0) pair else pair.substring(0, eq)).trim().lowercase()
            if (k in CRITICAL_TAGS) {
                grouped.getOrPut(k) { mutableListOf() }.add(if (eq < 0) "" else pair.substring(eq + 1))
            }
        }
        return grouped.filter { it.value.size > 1 }
    }

    private val DATE_FMTS = listOf("ddMMyyyy", "yyyyMMdd", "yyyy-MM-dd", "dd-MM-yyyy", "dd/MM/yyyy")
        .map { DateTimeFormatter.ofPattern(it) }

    private fun npciDate(s: String?): LocalDate? {
        if (s.isNullOrBlank()) return null
        for (f in DATE_FMTS) {
            try {
                return LocalDate.parse(s.trim(), f)
            } catch (_: Exception) {
            }
        }
        return null
    }

    /**
     * Full QR verdict, fully offline. [expectedAction] is "RECEIVE" when the
     * user was promised incoming funds, else "PAY". [isKnownSuspect] and
     * [isSketchMatch] come from the on-device threat layers.
     */
    fun evaluateQr(
        rawPayload: String,
        expectedAction: String = "PAY",
        isKnownSuspect: Boolean = false,
        isSketchMatch: Boolean = false,
        isTrusted: Boolean = false,
    ): QrVerdict {
        val preTrust = parseUpi(rawPayload)
        if (isTrusted && preTrust.pa != null) {
            return QrVerdict(
                preTrust.pa, preTrust.pn ?: "", preTrust.am, false, false,
                "VERIFIED_MERCHANT", 0, "LOW", listOf("TRUSTED_PAYEE"),
                "SAFE_TO_PROCEED",
                listOf("This payee is in your trusted list — verified by you or your organization."),
            )
        }
        val intent = preTrust
        val factors = mutableListOf<String>()
        val reasons = mutableListOf<String>()
        var score = 0
        val vpa = intent.pa ?: ""
        val payeeName = intent.pn ?: ""
        val amountStr = intent.am
        val amount = parseAmount(amountStr)
        val wantReceive = expectedAction.uppercase() == "RECEIVE"

        // --- 1. URL redirect vectors --------------------------------------
        if (intent.kind == Kind.URL) {
            score += 45
            factors.add("URL_REDIRECT_VECTOR")
            reasons.add(
                "QR contains a web link (${intent.urlHost ?: "unknown host"}) instead of a native upi:// payment intent.",
            )
            if (intent.isShortLink) {
                score += 20
                factors.add("SHORT_LINK_OBFUSCATION")
                reasons.add("Shortened link hides the real destination — a common phishing vector.")
            }
            score += anomalyWeight(rawPayload, vpa.ifEmpty { null }, amount, intent.mc, intent.cu, factors, reasons)
            if (isKnownSuspect) score += 80
            score = max(0, min(100, score))
            val sev = levelOf(score)
            return QrVerdict(vpa, payeeName, amountStr, false, false, "UNVERIFIED_INDIVIDUAL", score, sev, factors.ifEmpty { listOf("NO_QR_RISK_SIGNALS") }, guidanceOf(sev, false), reasons)
        }
        if (intent.kind == Kind.UNKNOWN) {
            score += 25
            factors.add("UNPARSEABLE_QR_PAYLOAD")
            reasons.add("QR content is not a recognised UPI intent — cannot verify payee.")
            score = max(0, min(100, score))
            val sev = levelOf(score)
            return QrVerdict(vpa, payeeName, amountStr, false, false, "UNVERIFIED_INDIVIDUAL", score, sev, factors, guidanceOf(sev, false), reasons)
        }

        // --- 2. Reverse-collect -------------------------------------------
        var isRc = false
        val phrase = intent.tn?.let { tn -> CREDIT_LURE.firstOrNull { it in tn.lowercase() } }
        if (wantReceive && intent.kind == Kind.PAY) {
            isRc = true; score += 55
            factors.add("REVERSE_COLLECT_CONTEXT_MISMATCH")
            reasons.add("You were promised incoming money (RECEIVE) but this QR encodes an outgoing payment — approving it with your PIN will DEBIT you.")
        }
        if (phrase != null && intent.kind == Kind.PAY) {
            isRc = true; score += 40
            factors.add("REVERSE_COLLECT_TN_LURE")
            reasons.add("Payment note promises '$phrase' yet this QR debits your account — a hallmark cashback/refund lure.")
        }
        if (isRc && amount != null && amount > 0) {
            score += 10
            factors.add("HARDCODED_DEBIT_AMOUNT")
            reasons.add("QR pre-fills a debit of ₹$amount; the attacker controls the amount.")
        }
        if (intent.kind == Kind.MANDATE && (wantReceive || phrase != null)) {
            isRc = true; score += 40
            factors.add("MANDATE_DISGUISED_AS_CREDIT")
            reasons.add("This QR creates a recurring payment mandate, not a one-time credit — it can debit you repeatedly.")
        }

        // --- 2b. Mandate-hijack inspection ----------------------------------
        var isHijack = false
        if (intent.kind == Kind.MANDATE) {
            val rec = Regex("(?i)[?&](recurrence|mode)=([^&]*)").find(rawPayload)?.groupValues?.get(2)?.trim() ?: ""
            val hasRec = rec.isNotEmpty() || rawPayload.lowercase().contains("mode=autopay")
            val start = npciDate(Regex("(?i)[?&]validitystart=([^&]*)").find(rawPayload)?.groupValues?.get(1))
            val end = npciDate(Regex("(?i)[?&]validityend=([^&]*)").find(rawPayload)?.groupValues?.get(1))
            val days = if (start != null && end != null) ChronoUnit.DAYS.between(start, end).toInt() else null
            val recurring = hasRec || (days != null && days > 30)
            if (recurring) {
                score += 20
                factors.add("RECURRING_AUTODEBIT_MANDATE")
                reasons.add("This QR creates a *recurring* auto-debit mandate${if (rec.isNotEmpty()) " ($rec)" else ""}${if (days != null) " valid for $days days" else ""} — it can pull money repeatedly, not once.")
                val mcOk = intent.mc != null && MCC_RE.matches(intent.mc.trim())
                if (!mcOk) {
                    isHijack = true; score += 60
                    factors.add("RECURRING_MANDATE_HIJACK")
                    reasons.add("Recurring auto-debit to a payee with no registered corporate MCC — authorising this hands the attacker repeat debits.")
                } else {
                    factors.add("MCC_MANDATE_REGISTERED")
                    reasons.add("Recurring mandate to MCC ${intent.mc!!.trim()} — verify the biller in your UPI app's AutoPay section before authorising.")
                }
            }
        }

        // --- 3. Merchant / MCC audit -----------------------------------------
        var mccStatus = "UNVERIFIED_INDIVIDUAL"
        if (intent.cu != null && intent.cu.trim().uppercase() != "INR") {
            score += 30
            factors.add("NON_INR_CURRENCY")
            reasons.add("Currency '${intent.cu}' is not INR — NPCI UPI mandates INR; tampered or foreign QR.")
            mccStatus = "NON_INR_CURRENCY"
        } else {
            val mc = intent.mc?.trim()?.ifEmpty { null }
            if (mc != null && !MCC_RE.matches(mc)) {
                score += 20
                factors.add("INVALID_MCC_FORMAT")
                reasons.add("Merchant code '$mc' is not a 4-digit numeric MCC — possibly tampered.")
                mccStatus = "INVALID_MCC_FORMAT"
            } else {
                val corp = corporateClaim(intent.pn, intent.pa)
                val h = handleOf(intent.pa)
                val loc = localOf(intent.pa)
                val p2p = h in P2P_HANDLES
                val phoneLike = loc.filter { it.isDigit() }.length >= 10
                if (corp != null && mc == null) {
                    score += 35
                    factors.add("P2M_SPOOF_SUSPECT")
                    reasons.add("Payee claims '$corp' status but shows no Merchant Category Code — genuine utilities/merchants use verified P2M accounts.")
                    mccStatus = "P2M_SPOOF_SUSPECT"
                } else if (corp != null && mc != null && p2p && phoneLike) {
                    score += 35
                    factors.add("P2M_SPOOF_SUSPECT")
                    reasons.add("Payee claims '$corp' status but the VPA looks like a personal phone number on consumer handle '@$h'.")
                    mccStatus = "P2M_SPOOF_SUSPECT"
                } else if (mc != null) {
                    factors.add("MCC_PRESENT")
                    reasons.add("QR carries MCC $mc (${KNOWN_MCC[mc] ?: "Registered merchant category"}).")
                    mccStatus = "VERIFIED_MERCHANT"
                }
            }
        }

        // --- 3b. Tamper + value-anomaly guard ----------------------------------
        score += anomalyWeight(rawPayload, intent.pa, amount, intent.mc, intent.cu, factors, reasons)

        // --- 4. Threat layers ---------------------------------------------------
        if (isKnownSuspect) {
            score += 80
            factors.add(0, "KNOWN_SUSPECT_VPA")
            reasons.add(0, "Payee VPA is flagged in the on-device threat list of reported scam handles.")
        } else if (isSketchMatch) {
            score += 15
            factors.add("NATIONAL_SKETCH_MATCH")
            reasons.add("Possible match in the national suspect sketch — treat with extra caution.")
        }
        // VPA heuristics for the extracted payee (impersonation/typosquat/etc.).
        if (intent.pa != null) {
            val hv = evaluateVpa(intent.pa, amount, intent.pn, intent.tn, intent.mc?.takeIf { it.trim().all { c -> c.isDigit() } }, wantReceive, false)
            val owned = setOf("REVERSE_COLLECT_SCAM", "SUSPICIOUS_CREDIT_LURE", "MISSING_MCC", "IMPERSONATION_KEYWORD", "IMPERSONATION_KEYWORD_UNVERIFIED")
            hv.flags.filter { it !in owned }.forEach { factors.add("VPA_$it") }
            hv.reasons.forEach { reasons.add(it) }
            score += vpaExtraWeight(hv.flags)
        }

        if (isRc && wantReceive && intent.kind == Kind.PAY) score = max(score, 95)
        if (isHijack) {
            score = max(score, 95)
            if (mccStatus == "UNVERIFIED_INDIVIDUAL") mccStatus = "P2M_SPOOF_SUSPECT"
        }
        score = max(0, min(100, score))
        val sev = levelOf(score)
        if (factors.isEmpty()) factors.add("NO_QR_RISK_SIGNALS")
        if (reasons.isEmpty()) {
            reasons.add("QR intent parses cleanly and the payee is not flagged — but the payee is UNVERIFIED. Proceed only if you trust the source.")
        }
        return QrVerdict(vpa, payeeName, amountStr, isRc, isHijack, mccStatus, score, sev, factors.toList(), guidanceOf(sev, isRc || isHijack), reasons.toList())
    }

    /** Weight table for VPA-heuristic flags reused inside QR verdicts. */
    private fun vpaExtraWeight(flags: List<String>): Int {
        var total = 0
        for (code in flags) {
            total += when (code) {
                "INVALID_VPA_SYNTAX" -> 25
                "UNTRUSTED_PSP_HANDLE" -> 15
                "TYPOSQUAT_HANDLE" -> 25
                "PRESSURE_LANGUAGE" -> 10
                "HIGH_AMOUNT" -> 10
                "ELEVATED_AMOUNT" -> 5
                "RANDOM_LOOKING_HANDLE" -> 30
                "MACHINE_MINTED_HANDLE" -> 20
                else -> 0
            }
        }
        return total
    }

    /** Shared tamper + value-anomaly audit. Returns additive weight. */
    private fun anomalyWeight(
        raw: String,
        vpa: String?,
        amount: Double?,
        mcc: String?,
        currency: String?,
        factors: MutableList<String>,
        reasons: MutableList<String>,
    ): Int {
        var w = 0
        for ((tag, values) in duplicateTags(raw).toSortedMap()) {
            w += 35
            factors.add("DUPLICATE_PARAM_${tag.uppercase()}")
            val preview = values.take(3).joinToString(" / ") { it.take(32).ifEmpty { "(empty)" } }
            reasons.add("QR repeats critical parameter '$tag' ($preview) — preview and payment may use different values.")
        }
        if (vpa != null) {
            if (vpa.any { it in ZERO_WIDTH }) {
                w += 30
                factors.add("ZERO_WIDTH_VPA_TRICK")
                reasons.add("Payee ID contains invisible zero-width characters — a blocklist-evasion trick. Do not pay.")
            } else if (vpa.any { it.code > 127 }) {
                w += 20
                factors.add("VPA_NON_ASCII_OBFUSCATION")
                reasons.add("Payee ID contains non-ASCII characters — NPCI VPAs are strict ASCII; likely a lookalike spoof.")
            }
            val visible = vpa.filter { it !in ZERO_WIDTH }
            if ("@" in visible && !VPA_RE.matches(visible)) {
                w += 20
                factors.add("VPA_MALFORMED_OBFUSCATION")
                reasons.add("Payee ID '${visible.take(64)}' violates the NPCI VPA format — possibly tampered handle.")
            }
        }
        if (currency != null) {
            val c = currency.trim()
            if ('₹' in c || '$' in c || '€' in c || '£' in c || '¥' in c || c.length > 3 || !Regex("^[A-Za-z]{3}$").matches(c)) {
                w += 30
                factors.add("CURRENCY_TAMPER")
                reasons.add("Currency tag '${c.take(16)}' is not a valid ISO code — tampered QR trying to mask the debit currency.")
            }
        }
        if (amount != null && amount >= 25000 && mcc.isNullOrBlank()) {
            val h = handleOf(vpa)
            if (h in P2P_HANDLES) {
                w += 25
                factors.add("HIGH_VALUE_UNVERIFIED_P2P")
                reasons.add("High-value transfer of ₹$amount to an unverified personal account (@$h) with no merchant credentials — confirm on a second channel before authorising.")
            }
        }
        return w
    }
}
