"""Rule-based heuristic analyzer for UPI payment flows.

Covers:
  1. VPA syntax & PSP domain validation.
  2. Impersonation / typosquatting keyword detection.
  3. Transaction-context analysis (reverse-collect / debit-as-credit).
  4. Merchant Category Code (MCC) presence / mismatch checks.
  5. Social-engineering pressure language in transaction notes.

Each rule returns a :class:`HeuristicFinding` with an additive risk weight.
Weights are combined and clamped to 0-100 by ``app.services.scorer``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VPA_RE: re.Pattern[str] = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$")

#: Widely-used PSP / bank handles observed in legitimate Indian UPI traffic.
#: Anything outside this set is treated as an untrusted / private handle,
#: NOT as an automatic block — it only adds a small structural weight.
TRUSTED_PSP_HANDLES: frozenset[str] = frozenset(
    {
        "okhdfcbank",
        "okicici",
        "oksbi",
        "okaxisbank",
        "okaxis",
        "ybl",
        "ibl",
        "axl",
        "apl",
        "upi",
        "paytm",
        "phonepe",
        "airtel",
        "jio",
        "slice",
        "navi",
        "cred",
        "superyes",
        "yesbank",
        "idfcbank",
        "cmsidfc",
        "indus",
        "hsbc",
        "dbs",
        "freecharge",
        "mobikwik",
        "kotak",
        "rbl",
        "federal",
        "pnb",
        "bob",
        "canara",
        "unionbank",
        "okbizaxis",
        "sbi",
        "hdfc",
        "icici",
    }
)

#: Personal-use PSP handles most frequently abused in impersonation scams.
#: Authority keywords (refund/support/kyc/...) on these handles score high.
PERSONAL_PSP_HANDLES: frozenset[str] = frozenset(
    {"ybl", "ibl", "axl", "apl", "upi", "paytm", "phonepe"}
)

#: Keywords with high precision for refund / authority / KYC scams.
IMPERSONATION_KEYWORDS: frozenset[str] = frozenset(
    {
        "refund",
        "custom",
        "customs",
        "support",
        "kyc",
        "rbi",
        "bank",
        "officer",
        "army",
        "navy",
        "airforce",
        "police",
        "cbi",
        "incometax",
        "income",
        "gst",
        "electricity",
        "loan",
        "prize",
        "lottery",
        "cashback",
        "reward",
        "verif",
        "blocked",
        "suspend",
        "helpline",
        "care",
        "service",
        "claim",
        "bonus",
        "offer",
    }
)

#: Brand tokens used to catch typosquat / lookalike payee handles.
BRAND_TOKENS: frozenset[str] = frozenset(
    {
        "gpay",
        "googlepay",
        "googlepe",
        "phonepe",
        "phonepay",
        "paytm",
        "paytem",
        "bhim",
        "upi",
        "rbi",
        "sbi",
        "hdfc",
        "icici",
        "axis",
        "amazon",
        "flipkart",
    }
)

#: Urgency / secrecy language typical of social-engineering pressure.
PRESSURE_KEYWORDS: frozenset[str] = frozenset(
    {
        "urgent",
        "immediately",
        "secret",
        "otp",
        "pin",
        "cvv",
        "expir",
        "last chance",
        "block",
        "suspend",
        "do not tell",
        "dont tell",
        "confidential",
    }
)

MERCHANT_NAME_HINTS: frozenset[str] = frozenset(
    {"ltd", "pvt", "store", "mart", "shop", "merchant", "bazaar", "traders", "enterprise"}
)

INCOMING_PROMISE_HINTS: frozenset[str] = frozenset(
    {
        "receive",
        "refund",
        "cashback",
        "prize",
        "reward",
        "collect",
        "incoming",
        "you will get",
        "you'll get",
        "credit",
    }
)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HeuristicFinding:
    """Single rule-engine hit.

    Attributes:
        code: Machine-readable flag, e.g. ``IMPERSONATION_KEYWORD``.
        weight: Additive risk contribution (0-100 scale before clamping).
        reason: Explainable 'Why am I at risk?' sentence.
        guidance: Actionable 'What should I do?' sentence.
    """

    code: str
    weight: int
    reason: str
    guidance: str
    details: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_vpa(vpa: str) -> str:
    """Return the canonical lower-cased, stripped VPA."""
    return vpa.strip().lower()


def split_vpa(vpa_normalized: str) -> tuple[str, str]:
    """Split ``local@handle``; returns ``("", "")`` when malformed."""
    if "@" not in vpa_normalized:
        return "", ""
    local, handle = vpa_normalized.rsplit("@", 1)
    return local, handle


def _contains_any(haystack: str, needles: frozenset[str]) -> Optional[str]:
    hay = haystack.lower()
    for needle in needles:
        if needle in hay:
            return needle
    return None


def _levenshtein_le2(a: str, b: str) -> int:
    """Bounded Levenshtein distance (early exit above 2). Used for typosquat."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
            row_min = min(row_min, cur[-1])
        if row_min > 2:
            return 3
        prev = cur
    return prev[-1]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def check_vpa_syntax(vpa_normalized: str) -> list[HeuristicFinding]:
    """Rule 1 — VPA syntax & PSP domain validation."""
    findings: list[HeuristicFinding] = []
    if not VPA_RE.match(vpa_normalized):
        findings.append(
            HeuristicFinding(
                code="INVALID_VPA_SYNTAX",
                weight=25,
                reason=f"Payee ID '{vpa_normalized}' has an invalid UPI format.",
                guidance="Stop. Ask the payee for their correct UPI ID and verify it via a trusted channel before paying.",
                details={"vpa": vpa_normalized},
            )
        )
        return findings  # Cannot reliably run handle checks on malformed VPAs.
    _, handle = split_vpa(vpa_normalized)
    if handle not in TRUSTED_PSP_HANDLES:
        findings.append(
            HeuristicFinding(
                code="UNTRUSTED_PSP_HANDLE",
                weight=15,
                reason=f"Handle '@{handle}' is not a recognised PSP/bank handle.",
                guidance="Be cautious with unfamiliar handles. Verify the payee's identity independently before proceeding.",
                details={"handle": handle},
            )
        )
    return findings


def check_impersonation(
    vpa_normalized: str,
    payee_name: Optional[str] = None,
    note: Optional[str] = None,
    mcc: Optional[str] = None,
) -> list[HeuristicFinding]:
    """Rule 2 — impersonation / typosquatting on unverified personal handles."""
    findings: list[HeuristicFinding] = []
    local, handle = split_vpa(vpa_normalized)
    if not local:
        return findings

    combined_text = " ".join(p for p in (local, payee_name or "", note or "") if p)
    keyword = _contains_any(combined_text, IMPERSONATION_KEYWORDS)
    brand = _contains_any(local, BRAND_TOKENS)

    is_personal_handle = handle in PERSONAL_PSP_HANDLES

    # 2a. Authority keyword on a personal handle without MCC = classic scam shape.
    if keyword and is_personal_handle and not mcc:
        findings.append(
            HeuristicFinding(
                code="IMPERSONATION_KEYWORD",
                weight=30,
                reason=(
                    f"Payee ID contains authority keyword '{keyword}' "
                    f"on personal handle '@{handle}' with no merchant credentials."
                ),
                guidance=(
                    "Banks, RBI, customs and KYC teams never collect money over "
                    "personal UPI IDs. Do not pay; verify via the official helpline."
                ),
                details={"keyword": keyword, "handle": handle},
            )
        )
    elif keyword and not mcc:
        # Weaker signal on non-personal handles still worth surfacing.
        findings.append(
            HeuristicFinding(
                code="IMPERSONATION_KEYWORD_UNVERIFIED",
                weight=15,
                reason=f"Payee context contains sensitive keyword '{keyword}' without merchant verification.",
                guidance="Independently verify any caller claiming refunds, KYC or customs fees before paying.",
                details={"keyword": keyword},
            )
        )

    # 2b. Typosquat: local part is within edit-distance 1-2 of a brand token
    #     but is not exactly the brand (e.g. 'paytmm', 'phonepay', 'rbii').
    if brand is None:
        for token in BRAND_TOKENS:
            # Compare compacted alphanumeric local fragments against brand.
            for fragment in re.split(r"[^a-z0-9]+", local.lower()):
                if not fragment or fragment == token:
                    continue
                if len(fragment) >= 4 and _levenshtein_le2(fragment, token) in (1, 2):
                    findings.append(
                        HeuristicFinding(
                            code="TYPOSQUAT_HANDLE",
                            weight=25,
                            reason=(
                                f"Payee handle '{fragment}' closely mimics trusted brand "
                                f"'{token}' — a common impersonation trick."
                            ),
                            guidance="Type the official UPI ID yourself from the company's verified website/app instead of using this one.",
                            details={"fragment": fragment, "mimics": token},
                        )
                    )
                    break
            else:
                continue
            break

    return findings


def check_transaction_context(
    transaction_type: str,
    user_expects_incoming: bool,
    note: Optional[str] = None,
) -> list[HeuristicFinding]:
    """Rule 3 — reverse-collect / debit-as-credit scam pattern.

    The classic scam: victim is promised incoming funds (refund, prize, buyer
    payment) but the UPI screen actually initiates an *outgoing* debit (PAY)
    which requires entering a PIN. Receiving money NEVER requires a PIN.
    """
    findings: list[HeuristicFinding] = []
    note_hit = _contains_any(note or "", INCOMING_PROMISE_HINTS)

    if transaction_type == "PAY" and user_expects_incoming:
        findings.append(
            HeuristicFinding(
                code="REVERSE_COLLECT_SCAM",
                weight=35,
                reason=(
                    "You were promised incoming money, but this screen sends money OUT "
                    "of your account (entering your UPI PIN will debit you)."
                ),
                guidance=(
                    "STOP — to RECEIVE money you never enter a UPI PIN. "
                    "Decline this request and do not authorise it."
                ),
                details={"pattern": "promised-credit-but-outgoing-debit"},
            )
        )
    elif transaction_type == "PAY" and note_hit:
        findings.append(
            HeuristicFinding(
                code="SUSPICIOUS_CREDIT_LURE",
                weight=15,
                reason=f"Payment note promises '{note_hit}' yet this is an outgoing payment.",
                guidance="If someone promised you money, they should be SENDING it, not asking you to pay. Confirm with them on a verified number.",
                details={"keyword": note_hit},
            )
        )
    return findings


def check_mcc(
    vpa_normalized: str,
    payee_name: Optional[str] = None,
    mcc: Optional[str] = None,
) -> list[HeuristicFinding]:
    """Rule 4 — missing / mismatched Merchant Category Code."""
    findings: list[HeuristicFinding] = []
    _, handle = split_vpa(vpa_normalized)
    name_hit = _contains_any(payee_name or "", MERCHANT_NAME_HINTS)
    keyword_hit = _contains_any(vpa_normalized + " " + (payee_name or ""), IMPERSONATION_KEYWORDS)

    if (name_hit or keyword_hit) and not mcc:
        findings.append(
            HeuristicFinding(
                code="MISSING_MCC",
                weight=12,
                reason="Payee claims to be a business/authority but shows no Merchant Category Code (unverified personal account).",
                guidance="Genuine merchants show verified business details. Ask for an invoice and pay only via the official checkout link.",
                details={"handle": handle},
            )
        )
    return findings


def check_pressure_language(note: Optional[str]) -> list[HeuristicFinding]:
    """Rule 5 — urgency / secrecy pressure in the transaction note."""
    findings: list[HeuristicFinding] = []
    if not note:
        return findings
    hit = _contains_any(note, PRESSURE_KEYWORDS)
    if hit:
        findings.append(
            HeuristicFinding(
                code="PRESSURE_LANGUAGE",
                weight=10,
                reason=f"Payment note uses pressure/secrecy language ('{hit}') typical of scams.",
                guidance="Scammers create urgency so you don't verify. Pause, and call the organisation on its official number.",
                details={"keyword": hit},
            )
        )
    return findings


def check_amount(amount: Optional[float]) -> list[HeuristicFinding]:
    """Rule 6 — amount anomaly (high-value first-time debits are riskier)."""
    findings: list[HeuristicFinding] = []
    if amount is None:
        return findings
    if amount >= 50000:
        findings.append(
            HeuristicFinding(
                code="HIGH_AMOUNT",
                weight=10,
                reason=f"High-value payment of ₹{amount:,.2f} — errors and fraud are costlier at this size.",
                guidance="Split-verify: confirm the payee on a second channel (call/official app) before authorising large amounts.",
                details={"amount": str(amount)},
            )
        )
    elif amount >= 10000:
        findings.append(
            HeuristicFinding(
                code="ELEVATED_AMOUNT",
                weight=5,
                reason=f"Elevated payment of ₹{amount:,.2f}.",
                guidance="Double-check the payee VPA character-by-character before entering your PIN.",
                details={"amount": str(amount)},
            )
        )
    return findings


def check_unverifiable_handle(vpa_normalized: str) -> list[HeuristicFinding]:
    """Rule 7 — random-looking / reputation-less handle.

    Scammers rotate auto-generated IDs (``jsfkjshfk124@oksbi``) that carry no
    reputation: no threat-list hit is *expected*, so "not flagged" must never
    be presented as "safe". Heuristic: a letter-run of 6+ with zero vowels
    (a/e/i/o/u) is unpronounceable gibberish no human picks; a 10+ char
    handle that is >=70% digits (but not a phone number) is machine-minted.
    Pure-digit locals (phone-number VPAs) are a legitimate pattern — skipped.
    """
    findings: list[HeuristicFinding] = []
    local, _ = split_vpa(vpa_normalized)
    if not local:
        return findings
    if local.isdigit():
        return findings  # phone-number VPA — normal personal pattern.
    alpha = re.sub(r"[^a-z]", "", local.lower())
    if len(alpha) >= 6 and not re.search(r"[aeiou]", alpha):
        findings.append(
            HeuristicFinding(
                code="RANDOM_LOOKING_HANDLE",
                weight=30,
                reason=(
                    f"Payee handle '{local[:32]}' looks auto-generated (unpronounceable, "
                    "UNVERIFIED, no reputation trail) — scammers rotate random IDs "
                    "precisely so no database has seen them yet."
                ),
                guidance=(
                    "Treat this ID as UNVERIFIED, not safe. Pay only if you got this "
                    "ID from a person/source you independently trust."
                ),
                details={"local": local[:64]},
            )
        )
        return findings
    digits = sum(c.isdigit() for c in local)
    if len(local) >= 10 and digits / len(local) >= 0.7:
        findings.append(
            HeuristicFinding(
                code="MACHINE_MINTED_HANDLE",
                weight=20,
                reason=(
                    f"Payee handle '{local[:32]}' is mostly digits — a machine-minted "
                    "shape with no reputation trail."
                ),
                guidance="Pay only if you independently trust the source of this ID.",
                details={"local": local[:64]},
            )
        )
    return findings


def analyze_payment(
    vpa: str,
    amount: Optional[float] = None,
    payee_name: Optional[str] = None,
    note: Optional[str] = None,
    mcc: Optional[str] = None,
    transaction_type: str = "PAY",
    user_expects_incoming: bool = False,
) -> tuple[str, list[HeuristicFinding]]:
    """Run the full rule chain.

    Returns:
        Tuple of ``(vpa_normalized, findings)``.
    """
    vpa_normalized = normalize_vpa(vpa)
    findings: list[HeuristicFinding] = []
    findings += check_vpa_syntax(vpa_normalized)
    findings += check_impersonation(vpa_normalized, payee_name, note, mcc)
    findings += check_transaction_context(transaction_type, user_expects_incoming, note)
    findings += check_mcc(vpa_normalized, payee_name, mcc)
    findings += check_pressure_language(note)
    findings += check_amount(amount)
    findings += check_unverifiable_handle(vpa_normalized)
    return vpa_normalized, findings
