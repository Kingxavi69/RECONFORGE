"""SQLite-backed persistence for scan history and evidence."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class Database:
    """Simple SQLite adapter for ReconForge."""

    def __init__(self, db_path: str = "reconforge.db") -> None:
        self.db_path = db_path
        self._ensure_parent_directory()

    def _ensure_parent_directory(self) -> None:
        path = Path(self.db_path)
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def create_tables(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    summary TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    host TEXT,
                    normalized TEXT,
                    target_type TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    record_type TEXT,
                    value TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    port INTEGER,
                    state TEXT,
                    service TEXT,
                    version TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS web_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    url TEXT,
                    status_code INTEGER,
                    server TEXT,
                    content_type TEXT,
                    redirect_chain TEXT,
                    headers TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    name TEXT,
                    resolved_ip TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS technologies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    name TEXT,
                    confidence TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    title TEXT,
                    severity TEXT,
                    description TEXT,
                    evidence TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )

    def insert_scan(self, target: str, summary: str = "", risk_score: int | None = None, risk_level: str | None = None) -> int:
        with self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (target, summary, risk_score, risk_level, created_at) VALUES (?, ?, ?, ?, ?)",
                (target, summary, risk_score, risk_level, datetime.now(timezone.utc).isoformat()),
            )
            return int(cursor.lastrowid)

    def insert_dns_records(self, scan_id: int, records: dict) -> None:
        with self.connect() as conn:
            for record_type, values in records.items():
                for value in values:
                    conn.execute("INSERT INTO dns_records (scan_id, record_type, value) VALUES (?, ?, ?)", (scan_id, record_type, str(value)))

    def insert_ports(self, scan_id: int, ports: list[dict]) -> None:
        with self.connect() as conn:
            for port in ports:
                conn.execute(
                    "INSERT INTO ports (scan_id, port, state, service, version) VALUES (?, ?, ?, ?, ?)",
                    (scan_id, port.get("port"), port.get("state"), port.get("service"), port.get("version")),
                )

    def insert_web_result(self, scan_id: int, web: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO web_results (scan_id, url, status_code, server, content_type, redirect_chain, headers) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    web.get("url"),
                    web.get("status_code"),
                    web.get("server"),
                    web.get("content_type"),
                    json.dumps(web.get("redirect_chain", [])),
                    json.dumps(web.get("headers", {})),
                ),
            )

    def insert_subdomains(self, scan_id: int, entries: list[dict]) -> None:
        with self.connect() as conn:
            for entry in entries:
                conn.execute("INSERT INTO subdomains (scan_id, name, resolved_ip) VALUES (?, ?, ?)", (scan_id, entry.get("name"), entry.get("resolved_ip")))

    def insert_technologies(self, scan_id: int, technologies: list[str]) -> None:
        with self.connect() as conn:
            for item in technologies:
                conn.execute("INSERT INTO technologies (scan_id, name, confidence) VALUES (?, ?, ?)", (scan_id, item, "likely"))

    def insert_findings(self, scan_id: int, findings: list[dict]) -> None:
        with self.connect() as conn:
            for item in findings:
                conn.execute(
                    "INSERT INTO findings (scan_id, title, severity, description, evidence) VALUES (?, ?, ?, ?, ?)",
                    (scan_id, item.get("title"), item.get("severity"), item.get("description"), json.dumps(item.get("evidence", []))),
                )

    def get_scan(self, scan_id: int) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return {}
            return dict(row)

    def list_scans(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
            return [dict(row) for row in rows]

    def get_dns_records(self, scan_id: int) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM dns_records WHERE scan_id = ? ORDER BY record_type, value", (scan_id,)).fetchall()
            return [dict(row) for row in rows]

    def get_ports(self, scan_id: int) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM ports WHERE scan_id = ? ORDER BY port", (scan_id,)).fetchall()
            return [dict(row) for row in rows]

    def get_web_result(self, scan_id: int) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM web_results WHERE scan_id = ? ORDER BY id DESC LIMIT 1", (scan_id,)).fetchone()
            return dict(row) if row else {}

    def get_findings(self, scan_id: int) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
            return [dict(row) for row in rows]

    def get_technologies(self, scan_id: int) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM technologies WHERE scan_id = ? ORDER BY name", (scan_id,)).fetchall()
            return [dict(row) for row in rows]

    def fetch_history(self) -> list[dict]:
        return self.list_scans()
