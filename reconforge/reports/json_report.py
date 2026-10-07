"""JSON report generation."""

from __future__ import annotations


def generate_json_report(payload: dict) -> dict:
    """Create a JSON-safe report structure."""
    return {
        "target": payload.get("target"),
        "timestamp": payload.get("timestamp"),
        "risk_level": payload.get("risk_level"),
        "risk_score": payload.get("risk_score"),
        "dns": payload.get("dns", {}),
        "ports": payload.get("ports", []),
        "subdomains": payload.get("subdomains", []),
        "technologies": payload.get("technologies", []),
        "findings": payload.get("findings", []),
    }
