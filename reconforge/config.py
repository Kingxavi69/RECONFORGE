"""Configuration and environment helpers for ReconForge."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_CONFIG = {
    "timeout": 10,
    "user_agent": "ReconForge/0.1 (+authorized security testing)",
    "nmap_path": "nmap",
    "database_path": "reconforge.db",
    "report_dir": "reports",
    "wordlist_path": "wordlists/common.txt",
}


@dataclass
class ReconConfig:
    """Configuration settings loaded from disk or defaults."""

    timeout: int = 10
    user_agent: str = DEFAULT_CONFIG["user_agent"]
    nmap_path: str = DEFAULT_CONFIG["nmap_path"]
    database_path: str = DEFAULT_CONFIG["database_path"]
    report_dir: str = DEFAULT_CONFIG["report_dir"]
    wordlist_path: str = DEFAULT_CONFIG["wordlist_path"]

    @classmethod
    def load(cls, path: str | None = None) -> "ReconConfig":
        config_path = Path(path) if path else Path.home() / ".reconforge" / "config.json"
        if config_path.exists():
            try:
                data = json.loads(config_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = {}
            for key, value in DEFAULT_CONFIG.items():
                if key in data:
                    setattr(cls, key, data[key])
        config = cls()
        for key, value in DEFAULT_CONFIG.items():
            env_key = f"RECONFORGE_{key.upper()}"
            if env_key in os.environ:
                value = os.environ[env_key]
                if key in {"timeout"}:
                    value = int(value)
                setattr(config, key, value)
        return config

    def as_dict(self) -> dict[str, Any]:
        return {
            "timeout": self.timeout,
            "user_agent": self.user_agent,
            "nmap_path": self.nmap_path,
            "database_path": self.database_path,
            "report_dir": self.report_dir,
            "wordlist_path": self.wordlist_path,
        }
