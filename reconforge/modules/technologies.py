"""Passive technology detection helpers."""

from __future__ import annotations


def detect_technologies(headers: dict | None = None, html: str = "") -> list[str]:
    """Look for likely web technologies from headers and HTML patterns."""
    findings: set[str] = set()
    header_map = (headers or {}).get("headers", {}) if isinstance(headers, dict) else {}
    blobs = [
        str(headers or ""),
        str(html),
        " ".join(header_map.keys()),
        " ".join(header_map.values()),
    ]
    lower = " ".join(blobs).lower()

    if "nginx" in lower:
        findings.add("Likely technology: nginx")
    if "apache" in lower:
        findings.add("Likely technology: Apache")
    if "php" in lower:
        findings.add("Likely technology: PHP")
    if "wordpress" in lower:
        findings.add("Likely technology: WordPress")
    if "react" in lower:
        findings.add("Likely technology: React")
    if "node" in lower or "express" in lower:
        findings.add("Likely technology: Node.js")
    if not findings:
        findings.add("Likely technology: static site or unknown stack")
    return sorted(findings)
