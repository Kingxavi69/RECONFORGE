"""Compare historical recon results."""

from __future__ import annotations


def compare_scans(left: dict, right: dict) -> dict:
    """Compare two scan dictionaries and summarize differences."""
    left_ports = {(p.get("port"), p.get("service")) for p in left.get("ports", [])}
    right_ports = {(p.get("port"), p.get("service")) for p in right.get("ports", [])}

    new = sorted(right_ports - left_ports)
    removed = sorted(left_ports - right_ports)
    changed = []

    if left.get("dns") != right.get("dns"):
        changed.append("DNS records changed")
    if left.get("subdomains") != right.get("subdomains"):
        changed.append("Subdomain inventory changed")
    if left.get("technologies") != right.get("technologies"):
        changed.append("Technology profile changed")
    if left.get("findings") != right.get("findings"):
        changed.append("Security findings changed")

    return {
        "new": [f"Port {port}" for port, _ in new],
        "removed": [f"Port {port}" for port, _ in removed],
        "changed": changed,
    }
