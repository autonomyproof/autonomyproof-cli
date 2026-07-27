"""Readiness scoring (PRD §13)."""

from __future__ import annotations

from collections.abc import Iterable

from autonomyproof.models import Finding

INITIAL_SCORE = 100
MIN_SCORE = 0

SCORE_DISCLAIMER = (
    "The AutonomyProof readiness score is based on the currently supported technical "
    "checks and is not a certification or guarantee of security."
)


def compute_score(findings: Iterable[Finding]) -> int:
    """Return the readiness score in the inclusive range [0, 100]."""
    score = INITIAL_SCORE
    for finding in findings:
        score -= finding.severity.score_deduction
    return max(MIN_SCORE, score)


def risk_level(score: int) -> str:
    """Map a score to a risk band (PRD §13)."""
    if score >= 80:
        return "Low"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "High"
    return "Critical"
