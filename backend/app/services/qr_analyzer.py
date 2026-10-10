"""QR / NPCI deep-link analyzer for the UPI Scam Detection Engine.

Covers three responsibilities:

1. **NPCI URI parsing** — safe extraction of ``upi://pay`` and
   ``upi://mandate`` parameters (``pa``/``pn``/``mc``/``am``/``tr``/``cu``/``tn``)
   plus detection of QR redirect vectors (HTTP/HTTPS URLs, short-links).
2. **Reverse-collect detection** — :class:`ReverseCollectDetector` flags
   debit-as-credit fraud where victims expecting incoming funds are handed an
   outgoing ``upi://pay`` intent.
3. **Merchant validation** — :class:`MerchantValidator` audits MCC presence,
   format, currency, and P2P-vs-P2M identity mismatches per NPCI deep-linking
   conventions.

All public entry points are fully typed (PEP 484) and side-effect free so
they are trivially unit-testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Optional
from urllib.parse import parse_qs, urlparse

from app.services.anomaly_detector import audit_qr_anomalies
from app.services.mandate_analyzer import MANDATE_HIJACK_FLOOR, evaluate_mandate

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UPI_SCHEMES: frozenset[str] = frozenset({"pay", "mandate", "collect", "autopay"})

MCC_RE: re.Pattern[str] = re.compile(r"^\d{4}$")

#: Short-link / redirector domains frequently abused to hide the real payee.
SHORT_LINK_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at",
        "ow.ly",
        "buff.ly",
        "tiny.cc",
        "rb.gy",
        "qrco.de",
    }
)

#: Deceptive ``tn`` (transaction-note) phrases promising incoming funds.
#: Matched case-insensitively as substrings — covers the spec phrases plus
#: common morphological variants ("cashback credited", "claim your bonus"...).
DECEPTIVE_CREDIT_PHRASES: tuple[str, ...] = (
    "receive refund",
    "cashback credit",
    "cashback credited",
    "lottery prize",
    "reward release",
    "claim bonus",
    "claim your bonus",
    "cashback",
    "refund credit",
    "prize money",
    "you have won",
    "you've won",
    "reward points credit",
)

#: Payee-name tokens that assert a corporate / utility / authority identity.
CORPORATE_CLAIM_KEYWORDS: frozenset[str] = frozenset(
    {
        "electricity",
        "power",
        "utility",
        "utilities",
        "board",
        "nigam",
        "municipal",
        "gas",
        "water",
        "telecom",
        "airtel",
        "jio",
        "vodafone",
        "bsnl",
        "broadband",
        "bank",
        "insurance",
        "department",
        "dept",
        "support",
        "customercare",
        "customer care",
        "service centre",
        "service center",
        "pvt",
        "ltd",
        "limited",
        "store",
        "official",
    }
)

#: Handles overwhelmingly used for consumer P2P transfers. A corporate-claim
#: name on one of these handles with no MCC is the classic P2M-spoof shape.
P2P_CONSUMER_HANDLES: frozenset[str] = frozenset(
    {"ybl", "ibl", "axl", "apl", "upi", "paytm", "phonepe", "okhdfcbank", "okicici", "oksbi"}
)

#: A small reference map of well-known MCCs (not exhaustive — used for
#: category labelling; any 4-digit code passes *format* validation).
KNOWN_MCC_CATEGORIES: dict[str, str] = {
    "5411": "Grocery / supermarkets",
    "5812": "Restaurants",
    "5912": "Pharmacies",
    "4111": "Transport / utilities",
    "4900": "Utilities (electric/gas/water)",
    "6012": "Banks / financial institutions",
    "6011": "ATMs / cash",
    "7995": "Gambling / betting (high-risk)",
    "4829": "Money transfer / remittance",
    "7372": "Computer / IT services",
    "5732": "Electronics",
    "5651": "Clothing",
    "5541": "Fuel",
    "5814": "Fast food",
}

MccStatus = Literal[
    "VERIFIED_MERCHANT",
    "UNVERIFIED_INDIVIDUAL",
    "MISSING_MCC_FOR_BUSINESS",
    "INVALID_MCC_FORMAT",
    "NON_INR_CURRENCY",
    "P2M_SPOOF_SUSPECT",
]

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
GuidanceAction = Literal[
    "SAFE_TO_PROCEED",
    "VERIFY_AND_PROCEED_WITH_CAUTION",
    "DO_NOT_PAY_VERIFY_FIRST",
    "DO_NOT_SCAN_OR_PAY",
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NpciIntent:
    """Parsed representation of a QR payload.

    Attributes:
        raw: Original decoded QR string (truncated for logs by callers).
        kind: ``pay`` / ``mandate`` for UPI intents, ``url`` for HTTP(S)
            redirect vectors, ``unknown`` for anything else.
        pa: Payee VPA (``pa`` tag) if present.
        pn: Payee name (``pn`` tag) if present.
        mc: Merchant Category Code (``mc`` tag) if present.
        am: Amount string (``am`` tag) if present.
        tr: Transaction reference (``tr`` tag) if present.
        cu: Currency (``cu`` tag) if present.
        tn: Transaction note (``tn`` tag) if present.
        url_host: Lower-cased host for ``url`` payloads.
        is_short_link: True when the host is a known short-link domain.
    """

    raw: str
    kind: Literal["pay", "mandate", "url", "unknown"]
    pa: Optional[str] = None
    pn: Optional[str] = None
    mc: Optional[str] = None
    am: Optional[str] = None
    tr: Optional[str] = None
    cu: Optional[str] = None
    tn: Optional[str] = None
    url_host: Optional[str] = None
    is_short_link: bool = False
    extra_params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class QrRiskVerdict:
    """Combined QR risk verdict (matches the API response contract)."""

    vpa: str
    payee_name: str
    amount: Optional[str]
    is_reverse_collect_scam: bool
    mcc_status: str
    risk_score: int
    severity: Severity
    risk_factors: list[str]
    guidance: GuidanceAction
    reasons: list[str]
    is_mandate_hijack: bool = False


# ---------------------------------------------------------------------------
# NPCI parser
# ---------------------------------------------------------------------------


def _first(params: dict[str, list[str]], key: str) -> Optional[str]:
    vals = params.get(key)
    if not vals:
        return None
    v = vals[0].strip()
    return v or None


def parse_upi_payload(raw: str) -> NpciIntent:
    """Safely parse a decoded QR string into an :class:`NpciIntent`.

    Handles ``upi://pay?...``, ``upi://mandate?...`` (and case variants),
    HTTP/HTTPS redirect vectors, and arbitrary garbage (``unknown``).

    Args:
        raw: Decoded QR text, stripped of surrounding whitespace.

    Returns:
        Parsed intent; never raises on malformed input.
    """
    text = (raw or "").strip()
    if not text:
        return NpciIntent(raw=raw, kind="unknown")

    lowered = text.lower()

    # --- HTTP(S) redirect vector -------------------------------------------
    if lowered.startswith("http://") or lowered.startswith("https://"):
        try:
            host = (urlparse(text).hostname or "").lower()
        except Exception:
            host = ""
        return NpciIntent(
            raw=text,
            kind="url",
            url_host=host or None,
            is_short_link=host in SHORT_LINK_DOMAINS,
        )

    # --- UPI deep link ------------------------------------------------------
    # Accept "upi://pay", "UPI://PAY", "upi:pay?..." variants.
    m = re.match(r"(?i)^upi:(?://)?([a-z]+)\?(.*)$", text, re.DOTALL)
    if not m:
        # Bare VPA printed next to a QR (common on shop stickers).
        if re.match(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$", text):
            return NpciIntent(raw=text, kind="pay", pa=text)
        return NpciIntent(raw=text, kind="unknown")

    scheme = m.group(1).lower()
    query = m.group(2)
    if scheme not in UPI_SCHEMES:
        return NpciIntent(raw=text, kind="unknown")

    try:
        params = parse_qs(query, keep_blank_values=True)
    except Exception:
        params = {}

    kind: Literal["pay", "mandate", "url", "unknown"] = (
        "mandate" if scheme in ("mandate", "autopay") else "pay"
    )
    known = {"pa", "pn", "mc", "am", "tr", "cu", "tn", "mode", "purpose", "sign"}
    extra = {k: (v[0] if v else "") for k, v in params.items() if k not in known}

    return NpciIntent(
        raw=text,
        kind=kind,
        pa=_first(params, "pa"),
        pn=_first(params, "pn"),
        mc=_first(params, "mc"),
        am=_first(params, "am"),
        tr=_first(params, "tr"),
        cu=_first(params, "cu"),
        tn=_first(params, "tn"),
        extra_params=extra,
    )


def parse_amount(am: Optional[str]) -> Optional[float]:
    """Parse the ``am`` tag to float; None when absent/invalid."""
    if am is None:
        return None
    try:
        return float(am.replace(",", "").strip())
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Reverse-collect detector
# ---------------------------------------------------------------------------


class ReverseCollectDetector:
    """Rule-based debit-as-credit (reverse-collect) scam detector.

    The classic scheme: the victim is told they will *receive* money
    (refund / cashback / prize / buyer payment) but the QR encodes an
    *outgoing* ``upi://pay`` debit — approving it with a UPI PIN sends
    money to the attacker. Receiving money never requires a PIN.
    """

    #: Score floor applied on hard context mismatch (RECEIVE vs pay-intent).
    CONTEXT_MISMATCH_FLOOR = 95
    TN_LURE_WEIGHT = 40
    CONTEXT_MISMATCH_WEIGHT = 55
    HARDCODED_AMOUNT_WEIGHT = 10

    def __init__(self, deceptive_phrases: tuple[str, ...] = DECEPTIVE_CREDIT_PHRASES) -> None:
        """Args:
        deceptive_phrases: Substring list matched against ``tn`` (lower-cased).
        """
        self._phrases = tuple(p.lower() for p in deceptive_phrases)

    def find_deceptive_phrase(self, note: Optional[str]) -> Optional[str]:
        """Return the first deceptive credit-claim phrase in ``note``."""
        if not note:
            return None
        lowered = note.lower()
        for phrase in self._phrases:
            if phrase in lowered:
                return phrase
        return None

    def evaluate(
        self,
        intent: NpciIntent,
        expected_action: Optional[Literal["RECEIVE", "PAY"]] = None,
    ) -> tuple[bool, int, list[str], list[str]]:
        """Evaluate an intent for reverse-collect signals.

        Args:
            intent: Parsed QR payload.
            expected_action: Client context — what the user *believes* will
                happen. ``RECEIVE`` means the user was promised incoming funds.

        Returns:
            Tuple ``(is_scam, weight, flags, reasons)`` where ``weight`` is
            the additive 0-100 contribution (before clamping) and ``flags``
            are machine-readable codes.
        """
        flags: list[str] = []
        reasons: list[str] = []
        weight = 0
        is_scam = False

        if intent.kind not in ("pay", "mandate"):
            return False, 0, [], []  # URL/unknown handled by other engines.

        phrase = self.find_deceptive_phrase(intent.tn)

        # Rule 1 — hard context mismatch: promised credit, handed a debit.
        if expected_action == "RECEIVE" and intent.kind == "pay":
            is_scam = True
            weight += self.CONTEXT_MISMATCH_WEIGHT
            flags.append("REVERSE_COLLECT_CONTEXT_MISMATCH")
            reasons.append(
                "You were promised incoming money (RECEIVE) but this QR encodes an "
                "outgoing payment (upi://pay) — approving it with your PIN will DEBIT you."
            )

        # Rule 2 — deceptive tn lure coexisting with an active debit URI.
        if phrase is not None and intent.kind == "pay":
            is_scam = True
            weight += self.TN_LURE_WEIGHT
            flags.append("REVERSE_COLLECT_TN_LURE")
            reasons.append(
                f"Payment note promises '{phrase}' yet this QR debits your account — "
                "a hallmark cashback/refund lure."
            )

        # Rule 3 — hardcoded/bounded amount raises outbound exposure.
        amount = parse_amount(intent.am)
        if is_scam and amount is not None and amount > 0:
            weight += self.HARDCODED_AMOUNT_WEIGHT
            flags.append("HARDCODED_DEBIT_AMOUNT")
            reasons.append(
                f"QR pre-fills a debit of ₹{amount:,.2f}; the attacker controls the amount."
            )

        # Rule 4 — recurring mandate presented as one-time credit.
        if intent.kind == "mandate" and (expected_action == "RECEIVE" or phrase is not None):
            is_scam = True
            weight += self.TN_LURE_WEIGHT
            flags.append("MANDATE_DISGUISED_AS_CREDIT")
            reasons.append(
                "This QR creates a recurring payment mandate (upi://mandate), not a "
                "one-time credit — it can debit you repeatedly."
            )

        return is_scam, weight, flags, reasons


# ---------------------------------------------------------------------------
# Merchant / MCC validator
# ---------------------------------------------------------------------------


class MerchantValidator:
    """NPCI compliance + P2P-vs-P2M identity audit engine."""

    def __init__(
        self,
        corporate_keywords: frozenset[str] = CORPORATE_CLAIM_KEYWORDS,
        p2p_handles: frozenset[str] = P2P_CONSUMER_HANDLES,
    ) -> None:
        """Args:
        corporate_keywords: ``pn`` substrings asserting business identity.
        p2p_handles: PSP handles treated as consumer (non-merchant) handles.
        """
        self._corp = corporate_keywords
        self._p2p = p2p_handles

    @staticmethod
    def _handle_of(vpa: Optional[str]) -> Optional[str]:
        if not vpa or "@" not in vpa:
            return None
        return vpa.rsplit("@", 1)[1].lower()

    def claims_business(self, payee_name: Optional[str], vpa: Optional[str]) -> Optional[str]:
        """Return the corporate-claim keyword hit, if any.

        Only the display name and the VPA *local* part are searched — the
        PSP handle itself (e.g. ``@okhdfcbank``) is excluded so substrings
        like ``bank`` inside handle names don't false-positive. Longest
        keywords match first so ``electricity`` wins over ``support``.
        """
        local = vpa.rsplit("@", 1)[0] if vpa and "@" in vpa else (vpa or "")
        hay = f"{payee_name or ''} {local}".lower()
        for kw in sorted(self._corp, key=len, reverse=True):
            if kw and kw in hay:
                return kw
        return None

    @staticmethod
    def _local_looks_like_personal_phone(local: str) -> bool:
        """True when the VPA local part is phone-number-like (10+ digits).

        Genuine merchants use business handles; a corporate *name* paired
        with a bare phone number local (e.g. ``98765XXXXX@okhdfcbank``) is
        the textbook P2M-spoof shape — even if an MCC tag was injected.
        """
        digits = re.sub(r"\D", "", local or "")
        return len(digits) >= 10

    def audit(self, intent: NpciIntent) -> tuple[str, int, list[str], list[str]]:
        """Audit MCC / currency / identity consistency.

        Returns:
            Tuple ``(mcc_status, weight, flags, reasons)``.
        """
        flags: list[str] = []
        reasons: list[str] = []
        weight = 0

        # Non-UPI redirect vectors carry no MCC semantics — handled elsewhere.
        if intent.kind in ("url", "unknown"):
            return "UNVERIFIED_INDIVIDUAL", 0, [], []

        # --- Currency -------------------------------------------------------
        if intent.cu is not None and intent.cu.strip().upper() != "INR":
            flags.append("NON_INR_CURRENCY")
            reasons.append(
                f"Currency '{intent.cu}' is not INR — NPCI UPI mandates INR; "
                "tampered or foreign QR."
            )
            return "NON_INR_CURRENCY", 30, flags, reasons

        # --- MCC format ------------------------------------------------------
        mc = (intent.mc or "").strip() or None
        if mc is not None and not MCC_RE.match(mc):
            flags.append("INVALID_MCC_FORMAT")
            reasons.append(
                f"Merchant code '{mc}' is not a 4-digit numeric MCC — possibly tampered."
            )
            return "INVALID_MCC_FORMAT", 20, flags, reasons

        corporate_hit = self.claims_business(intent.pn, intent.pa)
        handle = self._handle_of(intent.pa)
        local = (intent.pa.rsplit("@", 1)[0] if intent.pa and "@" in intent.pa else "")
        is_p2p_handle = handle in self._p2p if handle else False

        # --- P2M spoof: corporate claims with no MCC ---------------------------
        # A corporate-claim name on a consumer handle *without* an MCC is the
        # classic spoof shape (e.g. "Electricity Dept" on @okhdfcbank, no mc).
        # When a valid MCC *is* present we only keep the spoof flag if the
        # local part is phone-number-like (personal account masquerading).
        if corporate_hit and mc is None:
            flags.append("P2M_SPOOF_SUSPECT")
            reasons.append(
                f"Payee claims '{corporate_hit}' status but shows no Merchant Category "
                "Code — genuine utilities/merchants use verified P2M accounts."
            )
            weight += 35
            return "P2M_SPOOF_SUSPECT", weight, flags, reasons

        if (
            corporate_hit
            and mc is not None
            and is_p2p_handle
            and self._local_looks_like_personal_phone(local)
        ):
            flags.append("P2M_SPOOF_SUSPECT")
            reasons.append(
                f"Payee claims '{corporate_hit}' status but the VPA local part looks like "
                f"a personal phone number on consumer handle '@{handle}'."
            )
            weight += 35
            return "P2M_SPOOF_SUSPECT", weight, flags, reasons

        if corporate_hit and mc is None:
            flags.append("MISSING_MCC_FOR_BUSINESS")
            reasons.append(
                "Payee presents as a business/utility but the QR carries no MCC."
            )
            return "MISSING_MCC_FOR_BUSINESS", 20, flags, reasons

        if mc is not None:
            category = KNOWN_MCC_CATEGORIES.get(mc, "Registered merchant category")
            flags.append("MCC_PRESENT")
            reasons.append(f"QR carries MCC {mc} ({category}).")
            return "VERIFIED_MERCHANT", 0, flags, reasons

        # Plain P2P QR (friend, shop sticker without MCC) — not suspicious alone.
        return "UNVERIFIED_INDIVIDUAL", 0, [], []


# ---------------------------------------------------------------------------
# Combined evaluation
# ---------------------------------------------------------------------------


def _severity_for(score: int) -> Severity:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _guidance_for(severity: Severity, is_reverse_collect: bool) -> GuidanceAction:
    if is_reverse_collect or severity == "CRITICAL":
        return "DO_NOT_SCAN_OR_PAY"
    if severity == "HIGH":
        return "DO_NOT_PAY_VERIFY_FIRST"
    if severity == "MEDIUM":
        return "VERIFY_AND_PROCEED_WITH_CAUTION"
    return "SAFE_TO_PROCEED"


def evaluate_qr_payload(
    raw_payload: str,
    expected_action: Optional[Literal["RECEIVE", "PAY"]] = None,
    known_suspect: bool = False,
    suspect_source: Optional[str] = None,
    extra_heuristics_weight: int = 0,
    extra_flags: Optional[list[str]] = None,
    extra_reasons: Optional[list[str]] = None,
) -> QrRiskVerdict:
    """End-to-end QR risk evaluation producing the API response contract.

    Combines URL-redirect analysis, :class:`ReverseCollectDetector`,
    :class:`MerchantValidator`, and optional upstream signals (threat-intel
    hits, VPA heuristic weights from :mod:`app.services.heuristics`).

    Args:
        raw_payload: Decoded QR string (``upi://...`` / URL / bare VPA).
        expected_action: Client context flag (``RECEIVE`` vs ``PAY``).
        known_suspect: True when the extracted VPA hit the threat store.
        suspect_source: Provenance label for the threat hit.
        extra_heuristics_weight: Additive weight from the VPA heuristic engine.
        extra_flags: Extra machine-readable flags from upstream engines.
        extra_reasons: Extra human-readable reasons from upstream engines.

    Returns:
        :class:`QrRiskVerdict` with a 0-100 score and severity/guidance.
    """
    intent = parse_upi_payload(raw_payload)
    risk_factors: list[str] = []
    reasons: list[str] = []
    score = 0

    vpa = intent.pa or ""
    payee_name = intent.pn or ""
    amount = intent.am

    # --- 1. Redirect-vector analysis ---------------------------------------
    if intent.kind == "url":
        score += 45
        risk_factors.append("URL_REDIRECT_VECTOR")
        reasons.append(
            f"QR contains a web link ({intent.url_host or 'unknown host'}) instead of a "
            "native upi:// payment intent — payment-gateway impersonation risk."
        )
        if intent.is_short_link:
            score += 20
            risk_factors.append("SHORT_LINK_OBFUSCATION")
            reasons.append(
                "Shortened link hides the real destination — a common phishing vector. "
                "Expand it before trusting."
            )
        # Tamper audit still applies to link payloads carrying query strings.
        a_weight, a_flags, a_reasons = audit_qr_anomalies(
            raw_payload, vpa or None, parse_amount(amount), intent.mc, intent.cu
        )
        score += a_weight
        risk_factors += a_flags
        reasons += a_reasons
        verdict_score = min(100, score + (80 if known_suspect else 0) + extra_heuristics_weight)
        severity = _severity_for(verdict_score)
        return QrRiskVerdict(
            vpa=vpa,
            payee_name=payee_name,
            amount=amount,
            is_reverse_collect_scam=False,
            mcc_status="UNVERIFIED_INDIVIDUAL",
            risk_score=verdict_score,
            severity=severity,
            risk_factors=risk_factors + (extra_flags or []),
            guidance=_guidance_for(severity, False),
            reasons=reasons + (extra_reasons or []),
        )

    if intent.kind == "unknown":
        score += 25
        risk_factors.append("UNPARSEABLE_QR_PAYLOAD")
        reasons.append("QR content is not a recognised UPI intent — cannot verify payee.")
        verdict_score = min(100, score + extra_heuristics_weight)
        return QrRiskVerdict(
            vpa=vpa,
            payee_name=payee_name,
            amount=amount,
            is_reverse_collect_scam=False,
            mcc_status="UNVERIFIED_INDIVIDUAL",
            risk_score=verdict_score,
            severity=_severity_for(verdict_score),
            risk_factors=risk_factors + (extra_flags or []),
            guidance=_guidance_for(_severity_for(verdict_score), False),
            reasons=reasons + (extra_reasons or []),
        )

    # --- 2. Reverse-collect detection ---------------------------------------
    rc = ReverseCollectDetector()
    is_rc, rc_weight, rc_flags, rc_reasons = rc.evaluate(intent, expected_action)
    score += rc_weight
    risk_factors += rc_flags
    reasons += rc_reasons

    # --- 2b. AutoPay mandate-hijack inspection ---------------------------------
    is_hijack, m_weight, m_flags, m_reasons, _m_intent = evaluate_mandate(raw_payload)
    score += m_weight
    risk_factors += m_flags
    reasons += m_reasons

    # --- 3. Merchant / MCC audit ---------------------------------------------
    mv = MerchantValidator()
    mcc_status, mcc_weight, mcc_flags, mcc_reasons = mv.audit(intent)
    score += mcc_weight
    risk_factors += mcc_flags
    reasons += mcc_reasons

    # --- 3b. Value-anomaly & parameter-tampering guard --------------------------
    a_weight, a_flags, a_reasons = audit_qr_anomalies(
        raw_payload,
        intent.pa,
        parse_amount(intent.am),
        intent.mc,
        intent.cu,
    )
    score += a_weight
    risk_factors += a_flags
    reasons += a_reasons

    # --- 4. Upstream signals (threat intel + VPA heuristics) ------------------
    if known_suspect:
        score += 80
        risk_factors.insert(0, "KNOWN_SUSPECT_VPA")
        src = f" (source: {suspect_source})" if suspect_source else ""
        reasons.insert(
            0, f"Payee VPA is flagged in the cybercrime threat repository{src}."
        )
    if extra_heuristics_weight:
        score += extra_heuristics_weight
    if extra_flags:
        risk_factors += extra_flags
    if extra_reasons:
        reasons += extra_reasons

    # Hard floor: promised-credit-but-handed-debit is always critical.
    if is_rc and expected_action == "RECEIVE" and intent.kind == "pay":
        score = max(score, ReverseCollectDetector.CONTEXT_MISMATCH_FLOOR)

    # Hard floor: recurring auto-debit to an MCC-less payee is always critical.
    if is_hijack:
        score = max(score, MANDATE_HIJACK_FLOOR)
        mcc_status = "P2M_SPOOF_SUSPECT" if mcc_status == "UNVERIFIED_INDIVIDUAL" else mcc_status

    final_score = max(0, min(100, int(score)))
    severity = _severity_for(final_score)

    if not risk_factors:
        risk_factors = ["NO_QR_RISK_SIGNALS"]
    if not reasons:
        reasons = [
            "QR intent parses cleanly and the payee is not flagged — but the "
            "payee is UNVERIFIED. Proceed only if you trust the source."
        ]

    return QrRiskVerdict(
        vpa=vpa,
        payee_name=payee_name,
        amount=amount,
        is_reverse_collect_scam=is_rc,
        mcc_status=mcc_status,
        risk_score=final_score,
        severity=severity,
        risk_factors=risk_factors,
        guidance=_guidance_for(severity, is_rc or is_hijack),
        reasons=reasons,
        is_mandate_hijack=is_hijack,
    )


# ---------------------------------------------------------------------------
# Image decoding (pyzbar / OpenCV, optional dependencies)
# ---------------------------------------------------------------------------


def decode_qr_image_bytes(image_bytes: bytes) -> list[str]:
    """Decode QR strings from raw image bytes.

    Tries ``pyzbar`` first (best for skewed captures), then OpenCV's
    ``QRCodeDetector`` (multi + single). Returns an empty list when no
    dependency is installed or no code is found — never raises for bad input.

    Args:
        image_bytes: Raw uploaded file bytes (PNG/JPEG/WebP...).

    Returns:
        List of decoded UTF-8 strings (usually length 0 or 1).
    """
    if not image_bytes:
        return []

    # --- Attempt 1: pyzbar ----------------------------------------------------
    try:
        from pyzbar.pyzbar import decode as zbar_decode  # type: ignore[import-not-found]

        try:
            from PIL import Image  # type: ignore[import-not-found]
        except ImportError:
            Image = None  # type: ignore[assignment]

        if Image is not None:
            import io

            pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            results: list[str] = []
            for obj in zbar_decode(pil_img):
                try:
                    results.append(obj.data.decode("utf-8", errors="replace"))
                except Exception:
                    continue
            if results:
                return results
    except Exception:
        pass  # pyzbar missing native zbar lib — fall through to OpenCV.

    # --- Attempt 2: OpenCV ------------------------------------------------------
    try:
        import cv2  # type: ignore[import-not-found]
        import numpy as np  # type: ignore[import-not-found]

        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return []
        detector = cv2.QRCodeDetector()
        try:
            ok, decoded_list, _, _ = detector.detectAndDecodeMulti(img)
            if ok and decoded_list:
                return [s for s in decoded_list if s]
        except Exception:
            pass
        try:
            data, _, _ = detector.detectAndDecode(img)
            return [data] if data else []
        except Exception:
            return []
    except Exception:
        return []

    return []
