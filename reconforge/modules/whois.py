"""WHOIS lookup helper with graceful degradation."""

from __future__ import annotations

import shutil
import subprocess


def get_whois(target: str) -> dict:
    """Query WHOIS if the command is available."""
    exe = shutil.which("whois")
    if not exe:
        return {"ok": False, "message": "WHOIS utility is unavailable on this system."}

    try:
        completed = subprocess.run([exe, target], capture_output=True, text=True, timeout=10, check=False)
        output = completed.stdout.strip() or completed.stderr.strip() or "WHOIS output unavailable."
        return {"ok": True, "message": output}
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - defensive
        return {"ok": False, "message": f"WHOIS lookup failed: {exc}"}
