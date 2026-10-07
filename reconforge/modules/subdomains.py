"""Passive subdomain discovery."""

from __future__ import annotations

import ipaddress
import os

import dns.resolver


def discover_subdomains(domain: str, wordlist: str | None = None) -> list[dict]:
    """Try a conservative pass for likely subdomains using DNS resolution."""
    try:
        ipaddress.ip_address(domain)
        return []
    except ValueError:
        pass

    candidates = ["www", "api", "mail", "admin", "login", "portal", "dev", "test", "staging", "vpn"]
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist, "r", encoding="utf-8") as handle:
                extra = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
            candidates.extend(extra[:50])
        except OSError:
            pass

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    results: list[dict] = []

    seen: set[str] = set()
    for candidate in candidates:
        name = f"{candidate}.{domain}".lower()
        if name in seen:
            continue
        seen.add(name)
        try:
            answer = resolver.resolve(name, "A")
            for record in answer:
                results.append({"name": name, "resolved_ip": str(record)})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            continue
    return results
