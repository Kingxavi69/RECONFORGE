"""DNS reconnaissance helpers."""

from __future__ import annotations

import ipaddress
from typing import Any

import dns.exception
import dns.name
import dns.query
import dns.resolver
import dns.rdatatype


def normalize_dns_records(records: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Normalize raw DNS records into a type -> value list mapping."""
    normalized: dict[str, list[str]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        record_type = str(record.get("type", "")).upper()
        value = record.get("value")
        if not record_type or value is None:
            continue
        normalized.setdefault(record_type, [])
        normalized[record_type].append(str(value))
    return normalized


def resolve_dns_records(target: str) -> dict[str, list[str]]:
    """Resolve common DNS records for a target using dnspython."""
    try:
        ipaddress.ip_address(target)
        return {}
    except ValueError:
        pass

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    records: list[dict[str, Any]] = []
    for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = resolver.resolve(target, record_type)
            for answer in answers:
                records.append({"type": record_type, "value": str(answer)})
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            continue
    return normalize_dns_records(records)
