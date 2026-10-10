"""UPI AutoPay mandate-hijack inspector for the Scam Detection Engine.

Scam shape: the victim scans what looks like a one-time payment QR, but the
payload is ``upi://mandate?...`` — authorising it grants the attacker a
*recurring* auto-debit (potentially for months). NPCI mandates carry:

  * ``validitystart`` / ``validityend`` — authorisation window.
  * ``recurrence`` — ``daily`` / ``weekly`` / ``monthly`` / ``aspresented``...
  * ``am`` — per-execution cap / max recurring amount (``am`` may also carry
    ``amt``/``maxamount`` aliases on some PSP builds).
  * ``share`` — account-detail share consent flag.
  * ``rev`` / ``mode`` — mandate revision / autopay mode markers.

Rule:
    If the URI initiates a recurring auto-debit (``recurrence`` present or
    ``validityend - validitystart`` > 30 days) **and** the payee lacks a
    registered corporate MCC, emit ``RECURRING_MANDATE_HIJACK`` with a
    score floor of 95 (CRITICAL).

This module is stdlib-only with no imports from :mod:`qr_analyzer` so the
QR pipeline can depend on it without import cycles.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional
from urllib.parse import parse_qs

#: Score floor for a confirmed mandate hijack (always CRITICAL).
MANDATE_HIJACK_FLOOR = 95
MANDATE_HIJACK_WEIGHT = 60

#: Validity windows longer than this are treated as long-lived auto-debits
#: even when no explicit ``recurrence`` tag is present.
LONG_MANDATE_DAYS = 30

MCC_RE: re.Pattern[str] = re.compile(r"^\d{4}$")

_DATE_FORMATS: tuple[str, ...] = ("%d%m%Y", "%Y%m%d", "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y")


@dataclass(frozen=True)
class MandateIntent:
    """Parsed ``upi://mandate`` payload.

    Attributes:
        raw: Original URI string.
        is_mandate: False when the URI is not a mandate intent at all.
        pa: Payee VPA (``pa`` tag).
        pn: Payee display name.
        mc: Merchant Category Code (may be absent on spoofed mandates).
        am: Max recurring amount string.
        cu: Currency tag.
        tn: Transaction note.
        tr: Transaction reference.
        validity_start: Parsed start date (None when absent/unparseable).
        validity_end: Parsed end date (None when absent/unparseable).
        validity_days: Window length in days (None when not computable).
        recurrence: Raw ``recurrence`` tag lower-cased, if present.
        share: Raw ``share`` consent tag, if present.
        has_recurrence: True when any recurrence/autopay marker is present.
    """

    raw: str
    is_mandate: bool = False
    pa: Optional[str] = None
    pn: Optional[str] = None
    mc: Optional[str] = None
    am: Optional[str] = None
    cu: Optional[str] = None
    tn: Optional[str] = None
    tr: Optional[str] = None
    validity_start: Optional[datetime] = None
    validity_end: Optional[datetime] = None
    validity_days: Optional[int] = None
    recurrence: Optional[str] = None
    share: Optional[str] = None
    has_recurrence: bool = False


def _first(params: dict[str, list[str]], *keys: str) -> Optional[str]:
    for key in keys:
        vals = params.get(key)
        if vals:
            v = vals[0].strip()
            if v:
                return v
    return None


def _parse_npcidate(value: Optional[str]) -> Optional[datetime]:
    """Parse NPCI validity dates (``DDMMYYYY`` canonical, ISO also accepted)."""
    if not value:
        return None
    text = value.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_mandate_uri(raw: str) -> MandateIntent:
    """Parse a ``upi://mandate?...`` deep link.

    Args:
        raw: Decoded QR string.

    Returns:
        :class:`MandateIntent` with ``is_mandate=False`` when the input is
        not a mandate URI (never raises on malformed input).
    """
    text = (raw or "").strip()
    m = re.match(r"(?i)^upi:(?://)?([a-z]+)\?(.*)$", text, re.DOTALL)
    if not m or m.group(1).lower() not in ("mandate", "autopay"):
        return MandateIntent(raw=raw, is_mandate=False)
    try:
        params = parse_qs(m.group(2), keep_blank_values=True)
    except Exception:
        params = {}

    start = _parse_npcidate(_first(params, "validitystart", "validityStart"))
    end = _parse_npcidate(_first(params, "validityend", "validityEnd"))
    days: Optional[int] = None
    if start is not None and end is not None:
        days = (end - start).days

    recurrence = _first(params, "recurrence")
    mode = _first(params, "mode")
    has_recurrence = bool(
        (recurrence and recurrence.strip())
        or (mode and mode.strip().lower() in ("autopay", "mandate", "recurring"))
    )

    return MandateIntent(
        raw=text,
        is_mandate=True,
        pa=_first(params, "pa"),
        pn=_first(params, "pn"),
        mc=_first(params, "mc"),
        am=_first(params, "am", "amt", "maxamount", "maxAmount"),
        cu=_first(params, "cu"),
        tn=_first(params, "tn"),
        tr=_first(params, "tr"),
        validity_start=start,
        validity_end=end,
        validity_days=days,
        recurrence=recurrence.lower() if recurrence else None,
        share=_first(params, "share"),
        has_recurrence=has_recurrence,
    )


def _has_registered_mcc(mc: Optional[str]) -> bool:
    return bool(mc and MCC_RE.match(mc.strip()))


def evaluate_mandate(
    raw_payload: str,
) -> tuple[bool, int, list[str], list[str], MandateIntent]:
    """Evaluate a raw QR string for mandate-hijack signals.

    Args:
        raw_payload: Decoded QR text.

    Returns:
        Tuple ``(is_hijack, weight, flags, reasons, intent)``. ``is_hijack``
        is True only for recurring auto-debits aimed at MCC-less payees;
        one-time ``upi://pay`` URIs always return ``(False, 0, [], [], ...)``.
    """
    intent = parse_mandate_uri(raw_payload)
    if not intent.is_mandate:
        return False, 0, [], [], intent

    flags: list[str] = []
    reasons: list[str] = []
    weight = 0

    long_window = intent.validity_days is not None and intent.validity_days > LONG_MANDATE_DAYS
    recurring = intent.has_recurrence or long_window

    if not recurring:
        # Short, one-shot mandate to a named payee — informational only.
        return False, 0, [], [], intent

    flags.append("RECURRING_AUTODEBIT_MANDATE")
    reasons.append(
        "This QR creates a *recurring* auto-debit mandate"
        + (f" ({intent.recurrence})" if intent.recurrence else "")
        + (
            f" valid for {intent.validity_days} days"
            if intent.validity_days is not None
            else ""
        )
        + " — it can pull money repeatedly, not once."
    )
    weight += 20

    if not _has_registered_mcc(intent.mc):
        flags.append("RECURRING_MANDATE_HIJACK")
        reasons.append(
            "Recurring auto-debit to a payee with no registered corporate MCC — "
            "genuine AutoPay merchants (OTT, utilities, lenders) always carry one. "
            "Authorising this hands the attacker repeat debits."
        )
        weight += MANDATE_HIJACK_WEIGHT
        return True, weight, flags, reasons, intent

    # Recurring but MCC-carrying — still worth surfacing, not a hijack.
    flags.append("MCC_MANDATE_REGISTERED")
    reasons.append(
        f"Recurring mandate to MCC {intent.mc.strip()} — verify the biller in your "
        "UPI app's AutoPay section before authorising."
    )
    return False, weight, flags, reasons, intent


MandateRisk = Literal["HIJACK", "RECURRING_REGISTERED", "ONE_SHOT", "NOT_MANDATE"]


def classify_mandate(raw_payload: str) -> MandateRisk:
    """Coarse mandate classification for routing / metrics."""
    is_hijack, _, flags, _, intent = evaluate_mandate(raw_payload)
    if not intent.is_mandate:
        return "NOT_MANDATE"
    if is_hijack:
        return "HIJACK"
    if "RECURRING_AUTODEBIT_MANDATE" in flags:
        return "RECURRING_REGISTERED"
    return "ONE_SHOT"
