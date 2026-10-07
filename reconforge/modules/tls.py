"""TLS certificate inspection."""

from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse


def inspect_tls(url: str, timeout: int = 10) -> dict:
    """Inspect HTTPS certificate metadata if the target supports TLS."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"ok": False, "message": "TLS inspection is only available for HTTPS targets."}

    host = parsed.hostname
    port = parsed.port or 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
                if not cert:
                    return {"ok": False, "message": "No certificate information was returned."}
                return {
                    "ok": True,
                    "subject": cert.get("subject", []),
                    "issuer": cert.get("issuer", []),
                    "not_after": cert.get("notAfter"),
                    "not_before": cert.get("notBefore"),
                    "version": wrapped.version(),
                    "valid": True,
                }
    except (socket.gaierror, ssl.SSLError, OSError) as exc:
        return {"ok": False, "message": f"TLS inspection failed: {exc}"}
