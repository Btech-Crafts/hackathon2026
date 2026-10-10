"""Value-anomaly & parameter-tampering guard for NPCI deep links.

Audits extracted parameters against NPCI deep-link security constraints:

1. **Duplicate query parameters** — e.g. ``pa=victim@ybl&pa=mule@paytm``.
   Lenient parsers take the *first* value while strict ones take the *last*,
   so attackers smuggle a mule VPA past preview screens. Any security-critical
   tag (``pa``/``pn``/``mc``/``am``/``cu``/``tn``/``tr``/``recurrence``/
   ``validityend``...) appearing twice is a tamper signal.
2. **VPA obfuscation** — zero-width spaces (``U+200B``/``U+200C``/``U+200D``/
   ``U+FEFF``), full-width lookalikes (``＠``), or non-standard symbols in the
   handle that survive copy-paste but break exact-match blocklists.
3. **High-value unverified P2P** — amount >= ₹25,000 to a VPA on a
   non-merchant (consumer P2P) PSP handle with no MCC.

Stdlib-only (no ``qr_analyzer`` import) to avoid import cycles; the QR
pipeline calls :func:`audit_qr_anomalies` directly.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import parse_qsl

#: Tags whose duplication indicates a parser-differential attack.
CRITICAL_TAGS: frozenset[str] = frozenset(
    {
        "pa",
        "pn",
        "mc",
        "am",
        "cu",
        "tn",
        "tr",
        "mode",
        "recurrence",
        "validitystart",
        "validityend",
        "share",
        "sign",
    }
)

#: Invisible characters abused to dodge VPA blocklists / display spoofing.
ZERO_WIDTH_CHARS: tuple[str, ...] = ("\u200b", "\u200c", "\u200d", "\ufeff")

#: Full-width / confusable codepoints that mimic ASCII in QR previews.
FULLWIDTH_AT: str = "\uff20"  # full-width '@'

VPA_STRICT_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$")

#: Consumer P2P PSP suffixes — high-value transfers here without an MCC are
#: unverified person-to-person debits, the riskiest shape for large amounts.
NON_MERCHANT_PSP_HANDLES: frozenset[str] = frozenset(
    {
        "ybl",
        "ibl",
        "axl",
        "apl",
        "upi",
        "paytm",
        "phonepe",
        "okhdfcbank",
        "okicici",
        "oksbi",
        "okaxis",
        "okaxisbank",
    }
)

HIGH_VALUE_P2P_THRESHOLD = 25_000.0

DUPLICATE_PARAM_WEIGHT = 35
ZERO_WIDTH_WEIGHT = 30
VPA_OBFUSCATION_WEIGHT = 20
CURRENCY_TAMPER_WEIGHT = 30
HIGH_VALUE_P2P_WEIGHT = 25


def find_duplicate_params(raw_payload: str) -> dict[str, list[str]]:
    """Return ``{tag: [values...]}`` for critical tags appearing 2+ times.

    Uses :func:`parse_qsl` (order-preserving, no collapsing) against the raw
    query string so duplicates are visible — unlike :func:`parse_qs`.
    """
    text = (raw_payload or "").strip()
    m = re.match(r"(?i)^upi:(?://)?[a-z]+\?(.*)$", text, re.DOTALL)
    if not m:
        return {}
    try:
        pairs = parse_qsl(m.group(1), keep_blank_values=True)
    except Exception:
        return {}
    grouped: dict[str, list[str]] = {}
    for key, value in pairs:
        k = key.strip().lower()
        if k in CRITICAL_TAGS:
            grouped.setdefault(k, []).append(value)
    return {k: v for k, v in grouped.items() if len(v) > 1}


def detect_vpa_tricks(vpa: Optional[str]) -> tuple[int, list[str], list[str]]:
    """Inspect a VPA for invisible-character / lookalike obfuscation.

    Returns:
        Tuple ``(weight, flags, reasons)``.
    """
    if not vpa:
        return 0, [], []
    flags: list[str] = []
    reasons: list[str] = []
    weight = 0

    if any(ch in vpa for ch in ZERO_WIDTH_CHARS):
        flags.append("ZERO_WIDTH_VPA_TRICK")
        reasons.append(
            "Payee ID contains invisible zero-width characters — a blocklist-evasion "
            "trick that makes a flagged VPA look clean. Do not pay."
        )
        weight += ZERO_WIDTH_WEIGHT

    if FULLWIDTH_AT in vpa or re.search(r"[^\x00-\x7F]", vpa):
        # Non-ASCII present: could be a legitimate name elsewhere, but inside a
        # VPA (which is strict ASCII per NPCI) it is always suspicious.
        if "ZERO_WIDTH_VPA_TRICK" not in flags:
            flags.append("VPA_NON_ASCII_OBFUSCATION")
            reasons.append(
                "Payee ID contains non-ASCII / full-width characters — NPCI VPAs are "
                "strict ASCII; this is likely a lookalike spoof."
            )
            weight += VPA_OBFUSCATION_WEIGHT
        else:
            weight += 5  # defence in depth when both signals co-occur.

    # Visible-but-illegal shape (spaces, symbols, bad handle) that still
    # *looks* like a VPA to a hurried user.
    visible = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", vpa)
    if "@" in visible and not VPA_STRICT_RE.match(visible):
        flags.append("VPA_MALFORMED_OBFUSCATION")
        reasons.append(
            f"Payee ID '{visible[:64]}' violates the NPCI VPA format — possible "
            "tampered handle."
        )
        weight += VPA_OBFUSCATION_WEIGHT

    return weight, flags, reasons


def detect_currency_tamper(cu: Optional[str]) -> tuple[int, list[str], list[str]]:
    """Flag non-standard currency encodings (symbols, overlong values)."""
    if cu is None:
        return 0, [], []  # absent `cu` defaults to INR per NPCI — not tamper.
    text = cu.strip()
    if re.search(r"[₹$€£¥]", text) or len(text) > 3 or not re.match(r"^[A-Za-z]{3}$", text):
        return (
            CURRENCY_TAMPER_WEIGHT,
            ["CURRENCY_TAMPER"],
            [
                f"Currency tag '{text[:16]}' is not a valid ISO code — tampered QR "
                "trying to mask the debit currency."
            ],
        )
    return 0, [], []


def check_high_value_p2p(
    vpa: Optional[str],
    amount: Optional[float],
    mcc: Optional[str],
) -> tuple[int, list[str], list[str]]:
    """Flag >= ₹25,000 transfers to MCC-less consumer-handle VPAs."""
    if amount is None or amount < HIGH_VALUE_P2P_THRESHOLD:
        return 0, [], []
    if mcc and mcc.strip():
        return 0, [], []  # MCC-carrying billers are out of scope here.
    handle = vpa.rsplit("@", 1)[1].lower() if vpa and "@" in vpa else ""
    if handle in NON_MERCHANT_PSP_HANDLES:
        return (
            HIGH_VALUE_P2P_WEIGHT,
            ["HIGH_VALUE_UNVERIFIED_P2P"],
            [
                f"High-value transfer of ₹{amount:,.2f} to an unverified personal "
                f"account (@{handle}) with no merchant credentials — confirm on a "
                "second channel before authorising."
            ],
        )
    return 0, [], []


def parse_amount_safe(am: Optional[str]) -> Optional[float]:
    """Parse an ``am`` tag to float; None when absent/invalid."""
    if am is None:
        return None
    try:
        return float(am.replace(",", "").strip())
    except ValueError:
        return None


def audit_qr_anomalies(
    raw_payload: str,
    vpa: Optional[str] = None,
    amount: Optional[float] = None,
    mcc: Optional[str] = None,
    currency: Optional[str] = None,
) -> tuple[int, list[str], list[str]]:
    """Run the full tamper + value-anomaly audit.

    Args:
        raw_payload: Full decoded QR string (needed for duplicate detection).
        vpa: Extracted ``pa`` tag (or None).
        amount: Parsed ``am`` value (or None).
        mcc: Extracted ``mc`` tag (or None).
        currency: Extracted ``cu`` tag (or None).

    Returns:
        Tuple ``(total_weight, flags, reasons)`` (additive pre-clamp weight).
    """
    total = 0
    flags: list[str] = []
    reasons: list[str] = []

    dupes = find_duplicate_params(raw_payload)
    if dupes:
        total += DUPLICATE_PARAM_WEIGHT
        for tag, values in sorted(dupes.items()):
            flags.append(f"DUPLICATE_PARAM_{tag.upper()}")
            preview = " / ".join(v[:32] or "(empty)" for v in values[:3])
            reasons.append(
                f"QR repeats critical parameter '{tag}' ({preview}) — a "
                "parser-differential attack: preview and payment may use different values."
            )

    w, f, r = detect_vpa_tricks(vpa)
    total += w
    flags += f
    reasons += r

    w, f, r = detect_currency_tamper(currency)
    total += w
    flags += f
    reasons += r

    w, f, r = check_high_value_p2p(vpa, amount, mcc)
    total += w
    flags += f
    reasons += r

    return total, flags, reasons
