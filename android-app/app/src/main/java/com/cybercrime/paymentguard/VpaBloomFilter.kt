package com.cybercrime.paymentguard

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/**
 * Pure-Kotlin reader for the `threat_bloom.bin` artifact produced by
 * `scripts/build_bloom_filter.py` (stdlib-only, zero dependencies).
 *
 * The artifact encodes the *entire* national-scale suspect set (~30 lakh
 * capacity) in ~3.4 MB. Lookup is a few SHA-256 hashes + bit tests —
 * well under 1 ms, no I/O after load, safe on any thread.
 *
 * Hashing contract — MUST stay identical to the Python builder:
 * ```
 * key      = "vpa:<lower-cased vpa>" (or "phone:<last-10-digits>"), UTF-8
 * digest1  = SHA256("UPIBF:v1:" + key)
 * digest2  = SHA256(key + ":UPIBF:v1")
 * h1       = u64be(digest1[0..8]);  h2 = u64be(digest2[0..8]) forced odd
 * pos[i]   = (h1 + i*h2) mod m  (evaluated with unsigned modular arithmetic
 *            so 64-bit overflow can never skew positions vs. the builder)
 * ```
 * Cross-check vectors (m = 28,755,176, k = 7):
 * - `vpa:refund-officer@ybl` → [16995304, 4933439, 21626750, …]
 * - `vpa:friend.123@okhdfcbank` → [11359886, 4482743, 26360776, …]
 *
 * Semantics: `false` = definitely clean (no false negatives, allow
 * instantly); `true` = possibly present (~1% false positives at full
 * capacity — confirm via Room exact table or the backend).
 */
class VpaBloomFilter private constructor(
    private val mBits: Long,
    private val k: Int,
    private val bits: ByteArray,
) {

    /** Probabilistic membership probe for a raw payee VPA. Null-safe. */
    fun mightContainVpa(rawVpa: String?): Boolean {
        if (rawVpa.isNullOrBlank()) return false
        return mightContain("vpa:" + rawVpa.trim().lowercase())
    }

    /** Probabilistic membership probe for a raw phone number. Null-safe. */
    fun mightContainPhone(rawPhone: String?): Boolean {
        if (rawPhone.isNullOrBlank()) return false
        val digits = rawPhone.filter { it.isDigit() }
        val last10 = if (digits.length > 10) digits.takeLast(10) else digits
        if (last10.isEmpty()) return false
        return mightContain("phone:$last10")
    }

    private fun mightContain(key: String): Boolean {
        val positions = positionsFor(key, mBits, k)
        for (pos in positions) {
            val byteIdx = (pos / 8).toInt()
            if (byteIdx >= bits.size) return false
            val mask = 1 shl (pos % 8).toInt()
            if ((bits[byteIdx].toInt() and 0xFF) and mask == 0) return false
        }
        return true
    }

    companion object {
        private const val MAGIC = "UPIBF1\u0000\u0000"
        private const val HEADER_SIZE = 8 + 8 + 4 + 8 + 8 + 8 // 44 bytes

        /**
         * Parses a serialized artifact (header + bit array).
         * @throws IllegalArgumentException on bad magic / truncation.
         */
        fun load(blob: ByteArray): VpaBloomFilter {
            require(blob.size >= HEADER_SIZE) { "Bloom blob truncated" }
            val buf = ByteBuffer.wrap(blob, 0, HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            val magicBytes = ByteArray(8)
            buf.get(magicBytes)
            require(String(magicBytes, Charsets.UTF_8) == MAGIC) { "Not a UPIBF filter" }
            val mBits = buf.long
            val k = buf.int
            // capacity(8) + count(8) + fp(8) skipped — informational only.
            require(mBits > 0 && k in 1..64) { "Corrupt Bloom header" }
            val needBytes = ((mBits + 7) / 8).toInt()
            require(blob.size >= HEADER_SIZE + needBytes) { "Bloom bit array truncated" }
            val bits = blob.copyOfRange(HEADER_SIZE, HEADER_SIZE + needBytes)
            return VpaBloomFilter(mBits, k, bits)
        }

        /** Bit positions for [key] — unsigned modular arithmetic throughout. */
        internal fun positionsFor(key: String, mBits: Long, k: Int): LongArray {
            val raw = key.toByteArray(Charsets.UTF_8)
            val md = MessageDigest.getInstance("SHA-256")
            val h1 = u64be(md.digest("UPIBF:v1:".toByteArray(Charsets.UTF_8) + raw))
            val h2 = u64be(md.digest(raw + ":UPIBF:v1:".toByteArray(Charsets.UTF_8))) or 1L
            val h1m = java.lang.Long.remainderUnsigned(h1, mBits)
            val h2m = java.lang.Long.remainderUnsigned(h2, mBits)
            return LongArray(k) { i -> (h1m + (i.toLong() * h2m) % mBits) % mBits }
        }

        private fun u64be(bytes: ByteArray): Long =
            ByteBuffer.wrap(bytes, 0, 8).order(ByteOrder.BIG_ENDIAN).long
    }
}
