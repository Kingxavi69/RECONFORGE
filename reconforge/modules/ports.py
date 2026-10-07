"""Port scanning using nmap with safe subprocess execution."""

from __future__ import annotations

import re
import shutil
import subprocess


def scan_ports(target: str, nmap_path: str = "nmap", timeout: int = 20) -> dict:
    """Execute a basic TCP service scan against a supplied target."""
    path = shutil.which(nmap_path) or shutil.which("nmap")
    if not path:
        return {
            "ok": False,
            "message": "[!] Nmap is not installed. Install it with: sudo apt install nmap",
            "ports": [],
        }

    try:
        completed = subprocess.run(
            [path, "-Pn", "-sV", "-T3", "-p", "1-1024", target],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "message": f"Port scan failed: {exc}", "ports": []}

    output = completed.stdout + completed.stderr
    ports: list[dict] = []
    lines = output.splitlines()
    for line in lines:
        match = re.match(r"^(\d{1,5})\s+(open|closed|filtered)\s+(\S+)\s*(.*)$", line.strip())
        if match:
            port, state, service, version = match.groups()
            ports.append(
                {
                    "port": int(port),
                    "state": state,
                    "service": service,
                    "version": version.strip() or "unknown",
                }
            )

    if not ports:
        return {"ok": True, "message": "No open ports detected during the scan.", "ports": []}

    return {"ok": True, "message": "Port scan complete.", "ports": ports}
