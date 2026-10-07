"""Transparent risk scoring for recon findings."""

from __future__ import annotations


SEVERITY_WEIGHTS = {"LOW": 15, "MEDIUM": 30, "HIGH": 50}


def calculate_risk_score(findings: list[dict]) -> tuple[int, str, list[str]]:
    """Return risk score, level, and reasoning based on findings."""
    score = 0
    reasons: list[str] = []
    for finding in findings:
        severity = str(finding.get("severity", "LOW")).upper()
        score += SEVERITY_WEIGHTS.get(severity, 15)
        reasons.append(f"{severity}: {finding.get('title', 'Security observation')}")

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    return min(score, 100), level, reasons
