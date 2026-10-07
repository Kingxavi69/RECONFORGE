"""Dataclasses for common recon objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetInfo:
    """Structured normalization of a target."""

    raw: str
    normalized: str
    host: str
    scheme: str
    port: int | None
    target_type: str
    valid: bool = True
    error: str | None = None


@dataclass
class Finding:
    """Security observation."""

    title: str
    severity: str = "LOW"
    description: str = ""
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
        }
