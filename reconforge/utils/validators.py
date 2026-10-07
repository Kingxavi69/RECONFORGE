"""Validation helpers for targets and user input."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def _is_valid_hostname(host: str) -> bool:
    if not host or host.lower() == "localhost":
        return bool(host)
    if len(host) > 253:
        return False
    if host.startswith(".") or host.endswith(".") or ".." in host:
        return False
    labels = host.split(".")
    if not labels:
        return False
    for label in labels:
        if not label:
            return False
        if len(label) > 63:
            return False
        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def validate_target(value: str) -> dict:
    """Validate domain, URL, IPv4, or IPv6 targets and normalize them."""
    if not value or not str(value).strip():
        return {"valid": False, "normalized": "", "error": "No target supplied."}

    target = str(value).strip()

    if re.search(r"\s", target):
        return {"valid": False, "normalized": "", "error": "Target contains whitespace."}

    if "://" in target:
        try:
            parsed = urlparse(target)
        except ValueError as exc:
            return {"valid": False, "normalized": "", "error": str(exc)}
        if not parsed.scheme or not parsed.netloc:
            return {"valid": False, "normalized": "", "error": "Malformed URL supplied."}
        host = parsed.hostname
        if not host:
            return {"valid": False, "normalized": "", "error": "URL is missing a host."}
        try:
            ipaddress.ip_address(host)
            target_type = "ip"
        except ValueError:
            if not _is_valid_hostname(host):
                return {"valid": False, "normalized": "", "error": "URL host is invalid."}
            target_type = "domain"
        normalized = target if target.startswith(("http://", "https://")) else f"https://{host}"
        return {"valid": True, "normalized": normalized, "host": host, "scheme": parsed.scheme, "status": target_type, "error": None}

    try:
        ipaddress.ip_address(target)
        return {"valid": True, "normalized": f"https://{target}", "host": target, "scheme": "https", "status": "ip", "error": None}
    except ValueError:
        pass

    if _is_valid_hostname(target):
        return {"valid": True, "normalized": f"https://{target}", "host": target, "scheme": "https", "status": "domain", "error": None}

    if target.startswith("http://") or target.startswith("https://"):
        return {"valid": False, "normalized": "", "error": "Malformed URL supplied."}

    return {"valid": False, "normalized": "", "error": "Target must be a domain, URL, IPv4, or IPv6 address."}
