"""Convert raw reconnaissance data into organized security observations."""

from __future__ import annotations


def analyze_scan(scan: dict) -> list[dict]:
    """Create basic reconnaissance findings from the collected data."""
    findings: list[dict] = []
    ports = scan.get("ports") or []
    web = scan.get("web") or {}
    headers = web.get("security_headers", {}) if isinstance(web, dict) else {}

    for port in ports:
        if int(port.get("port", 0)) in {22, 3389, 5900} and port.get("state") == "open":
            findings.append(
                {
                    "title": "Publicly exposed administrative service detected",
                    "severity": "HIGH",
                    "description": f"Port {port.get('port')} is open and may be a management or remote access endpoint.",
                    "evidence": [f"Port {port.get('port')} open"],
                }
            )

    if not headers.get("content-security-policy"):
        findings.append(
            {
                "title": "Missing Content-Security-Policy header",
                "severity": "MEDIUM",
                "description": "The site is missing a Content-Security-Policy header, which weakens browser-side protections.",
                "evidence": ["Content-Security-Policy header missing"],
            }
        )
    if not headers.get("strict-transport-security") and web.get("url", "").startswith("https://"):
        findings.append(
            {
                "title": "Missing HSTS header",
                "severity": "MEDIUM",
                "description": "The HTTPS endpoint is not enforcing Strict-Transport-Security.",
                "evidence": ["Strict-Transport-Security header missing"],
            }
        )
    if not headers.get("x-frame-options"):
        findings.append(
            {
                "title": "Missing X-Frame-Options header",
                "severity": "LOW",
                "description": "The application is not explicitly telling browsers how to frame the page.",
                "evidence": ["X-Frame-Options header missing"],
            }
        )
    if scan.get("technologies"):
        findings.append(
            {
                "title": "Server technology disclosed",
                "severity": "LOW",
                "description": "Technology information was detected from headers or HTML patterns.",
                "evidence": scan.get("technologies", []),
            }
        )

    return findings
