"""Unified 0-100 risk scorer for the UPI Scam Detection Engine.

Combines heuristic findings, threat-intel hits, and structural anomalies
into a single normalised integer score plus explainable output.
"""

from __future__ import annotations

from typing import Sequence

from app.schemas import RecommendedAction, RiskLevel
from app.services.heuristics import HeuristicFinding

#: Threat-intel hit dominates the score — a known I4C/LEA suspect is
#: near-automatically HIGH/CRITICAL even without other signals.
KNOWN_SUSPECT_WEIGHT = 80


def _level_for(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 60:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _action_for(level: RiskLevel) -> RecommendedAction:
    return {
        RiskLevel.LOW: RecommendedAction.ALLOW,
        RiskLevel.MEDIUM: RecommendedAction.WARN,
        RiskLevel.HIGH: RecommendedAction.WARN_BLOCK,
        RiskLevel.CRITICAL: RecommendedAction.BLOCK,
    }[level]


def score_evaluation(
    findings: Sequence[HeuristicFinding],
    is_known_suspect: bool,
    suspect_source: str | None = None,
) -> tuple[int, RiskLevel, RecommendedAction, list[str], list[str], list[str]]:
    """Combine signals into ``(score, level, action, flags, reasons, guidance)``.

    Args:
        findings: Heuristic rule hits for this transaction.
        is_known_suspect: True when the VPA matched the threat-intel store.
        suspect_source: Provenance label (e.g. ``i4c-feed`` / ``redis``).

    Returns:
        Tuple of score (0-100), risk level, recommended action,
        machine-readable flags, human-readable reasons, and guidance steps.
    """
    total = sum(f.weight for f in findings)
    flags: list[str] = [f.code for f in findings]
    reasons: list[str] = [f.reason for f in findings]
    guidance: list[str] = []
    seen_guidance: set[str] = set()
    for f in findings:
        if f.guidance not in seen_guidance:
            guidance.append(f.guidance)
            seen_guidance.add(f.guidance)

    if is_known_suspect:
        total += KNOWN_SUSPECT_WEIGHT
        flags = ["KNOWN_SUSPECT_VPA"] + flags
        src = f" (source: {suspect_source})" if suspect_source else ""
        reasons.insert(
            0,
            f"This payee ID is flagged in the cybercrime threat repository{src}. "
            "It has been linked to previously reported fraud.",
        )
        block_msg = (
            "Do NOT pay this ID. Report it in the app and at cybercrime.gov.in "
            "or by calling 1930 (India)."
        )
        if block_msg not in seen_guidance:
            guidance.insert(0, block_msg)

    score = max(0, min(100, int(total)))
    level = _level_for(score)
    action = _action_for(level)

    if not reasons:
        reasons = [
            "No known scam patterns matched and this ID is not in the threat "
            "repository — but it is UNVERIFIED, not proven safe."
        ]
    if not guidance:
        guidance = [
            "Only proceed if you received this ID from a source you trust. "
            "When in doubt, call the payee on a separately known number first."
        ]

    # Universal safety footer for anything above LOW.
    if level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
        footer = "Never share your UPI PIN or OTP — receiving money never needs a PIN."
        if footer not in guidance:
            guidance.append(footer)

    return score, level, action, flags, reasons, guidance
