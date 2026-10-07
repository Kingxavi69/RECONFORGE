"""Orchestrates scanning workflows and persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from reconforge.config import ReconConfig
from reconforge.database import Database
from reconforge.intelligence.analyzer import analyze_scan
from reconforge.intelligence.risk import calculate_risk_score
from reconforge.modules.dns import resolve_dns_records
from reconforge.modules.ports import scan_ports
from reconforge.modules.subdomains import discover_subdomains
from reconforge.modules.technologies import detect_technologies
from reconforge.modules.tls import inspect_tls
from reconforge.modules.web import check_file, fetch_web
from reconforge.utils.validators import validate_target


def run_scan(target: str, full: bool = False, config: ReconConfig | None = None, db_path: str = "reconforge.db") -> dict:
    """Run a single reconnaissance scan against an explicit target."""
    validation = validate_target(target)
    if not validation["valid"]:
        return {"ok": False, "message": validation["error"], "scan_id": None}

    config = config or ReconConfig.load()
    db = Database(db_path or config.database_path)
    db.create_tables()

    target_url = validation["normalized"]
    parsed = urlparse(target_url)
    host = validation["host"]

    dns = resolve_dns_records(host)
    ports = []
    port_result = scan_ports(host, nmap_path=config.nmap_path, timeout=config.timeout)
    if port_result.get("ok"):
        ports = port_result.get("ports", [])

    web = {}
    if parsed.scheme in {"http", "https"}:
        web = fetch_web(target_url, timeout=config.timeout, user_agent=config.user_agent)
    elif target_url.startswith("https://"):
        web = fetch_web(target_url, timeout=config.timeout, user_agent=config.user_agent)

    tls_info = {}
    if parsed.scheme == "https":
        tls_info = inspect_tls(target_url, timeout=config.timeout)

    subdomains = discover_subdomains(host, wordlist=config.wordlist_path)
    technologies = detect_technologies(web, "")

    scan_data = {
        "target": host,
        "ports": ports,
        "dns": dns,
        "web": web,
        "tls": tls_info,
        "subdomains": subdomains,
        "technologies": technologies,
    }
    findings = analyze_scan(scan_data)
    score, level, reasons = calculate_risk_score(findings)
    summary = "; ".join(reasons) if reasons else "No significant issues observed."

    scan_id = db.insert_scan(host, summary, score, level)
    db.insert_dns_records(scan_id, dns)
    db.insert_ports(scan_id, ports)
    if web:
        db.insert_web_result(scan_id, web)
    db.insert_subdomains(scan_id, subdomains)
    db.insert_technologies(scan_id, technologies)
    db.insert_findings(scan_id, findings)

    return {
        "ok": True,
        "scan_id": scan_id,
        "target": host,
        "risk_score": score,
        "risk_level": level,
        "dns": dns,
        "ports": ports,
        "web": web,
        "subdomains": subdomains,
        "technologies": technologies,
        "findings": findings,
        "message": "Scan complete.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
