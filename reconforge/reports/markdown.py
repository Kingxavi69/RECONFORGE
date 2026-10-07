"""Markdown report generation."""

from __future__ import annotations


def generate_markdown_report(payload: dict) -> str:
    """Render a minimal markdown report."""
    lines = [
        "# ReconForge Report",
        "",
        f"- Target: {payload.get('target', 'unknown')}",
        f"- Risk Level: {payload.get('risk_level', 'LOW')}",
        f"- Risk Score: {payload.get('risk_score', 0)}",
        "",
        "## DNS",
        "",
        str(payload.get("dns", {})),
        "",
        "## Ports",
        "",
        str(payload.get("ports", [])),
    ]
    return "\n".join(lines)
