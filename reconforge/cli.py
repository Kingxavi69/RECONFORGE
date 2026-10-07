"""Command-line interface for ReconForge."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console

from reconforge import __version__
from reconforge.config import ReconConfig
from reconforge.database import Database
from reconforge.intelligence.diff import compare_scans
from reconforge.reports.html import save_html_report
from reconforge.reports.json_report import generate_json_report
from reconforge.reports.markdown import generate_markdown_report
from reconforge.scanner import run_scan
from reconforge.utils.validators import validate_target

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconforge",
        description="ReconForge: authorized reconnaissance and attack-surface intelligence.",
        epilog=(
            "Legal notice: only scan systems you own or are explicitly authorized to assess. "
            "Do not perform credential theft, malware, persistence, brute-force, or destructive attacks."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a reconnaissance scan against an explicit target.")
    scan_parser.add_argument("target", help="Domain, IPv4, IPv6, or URL to assess.")
    scan_parser.add_argument("--full", action="store_true", help="Run full reconnaissance, including more checks.")

    dns_parser = subparsers.add_parser("dns", help="Run DNS reconnaissance for a target.")
    dns_parser.add_argument("target")

    ports_parser = subparsers.add_parser("ports", help="Run TCP port scanning for a target.")
    ports_parser.add_argument("target")

    web_parser = subparsers.add_parser("web", help="Inspect HTTP or HTTPS metadata.")
    web_parser.add_argument("target")

    sub_parser = subparsers.add_parser("subdomains", help="Perform passive subdomain discovery.")
    sub_parser.add_argument("target")
    sub_parser.add_argument("--wordlist", help="Optional wordlist path for passive checks.")

    report_parser = subparsers.add_parser("report", help="Generate a scan report.")
    report_parser.add_argument("scan_id", type=int)
    report_parser.add_argument("--format", choices=["html", "json", "markdown"], default="html")

    history_parser = subparsers.add_parser("history", help="Show scan history.")

    compare_parser = subparsers.add_parser("compare", help="Compare two existing scan results.")
    compare_parser.add_argument("scan_id_1", type=int)
    compare_parser.add_argument("scan_id_2", type=int)

    return parser


def cmd_scan(target: str, full: bool = False) -> int:
    validation = validate_target(target)
    if not validation["valid"]:
        console.print(f"[red]{validation['error']}[/red]")
        return 1

    console.print("[green][+] Target validated[/green]")
    console.print("[green][+] Scan authorized target only[/green]")
    result = run_scan(target, full=full)
    if not result.get("ok"):
        console.print(f"[yellow]{result.get('message')}[/yellow]")
        return 1

    console.print(f"[cyan]Scan ID: {result['scan_id']}[/cyan]")
    console.print(f"[cyan]Risk Score: {result.get('risk_level', 'LOW')}[/cyan]")
    return 0


def cmd_dns(target: str) -> int:
    validation = validate_target(target)
    if not validation["valid"]:
        console.print(f"[red]{validation['error']}[/red]")
        return 1
    from reconforge.modules.dns import resolve_dns_records
    records = resolve_dns_records(validation["host"])
    console.print(records)
    return 0


def cmd_ports(target: str) -> int:
    validation = validate_target(target)
    if not validation["valid"]:
        console.print(f"[red]{validation['error']}[/red]")
        return 1
    from reconforge.modules.ports import scan_ports
    result = scan_ports(validation["host"])
    if not result["ok"]:
        console.print(f"[yellow]{result['message']}[/yellow]")
        return 1
    console.print(result["ports"])
    return 0


def cmd_web(target: str) -> int:
    validation = validate_target(target)
    if not validation["valid"]:
        console.print(f"[red]{validation['error']}[/red]")
        return 1
    from reconforge.modules.web import fetch_web
    result = fetch_web(validation["normalized"])
    console.print(result)
    return 0


def cmd_subdomains(target: str, wordlist: str | None = None) -> int:
    validation = validate_target(target)
    if not validation["valid"]:
        console.print(f"[red]{validation['error']}[/red]")
        return 1
    from reconforge.modules.subdomains import discover_subdomains
    results = discover_subdomains(validation["host"], wordlist)
    console.print(results)
    return 0


def cmd_report(scan_id: int, fmt: str) -> int:
    db = Database("reconforge.db")
    scan = db.get_scan(scan_id)
    if not scan:
        console.print("[red]Scan not found.[/red]")
        return 1
    payload = {
        "target": scan.get("target"),
        "timestamp": scan.get("created_at"),
        "risk_level": scan.get("risk_level", "LOW"),
        "risk_score": scan.get("risk_score", 0),
        "dns": {"A": ["example.com"]},
        "ports": [],
        "subdomains": [],
        "technologies": [],
        "findings": [],
    }
    if fmt == "json":
        output = json.dumps(generate_json_report(payload), indent=2)
    elif fmt == "markdown":
        output = generate_markdown_report(payload)
    else:
        output = save_html_report(payload, f"reports/scan_{scan_id}.html")
    console.print(output)
    return 0


def cmd_history() -> int:
    db = Database("reconforge.db")
    rows = db.fetch_history()
    if not rows:
        console.print("[yellow]No scan history yet.[/yellow]")
        return 0
    for row in rows:
        console.print(f"[cyan]{row['id']}[/cyan] - {row['target']} - {row['risk_level']} - {row['created_at']}")
    return 0


def cmd_compare(scan_id_1: int, scan_id_2: int) -> int:
    db = Database("reconforge.db")
    left = {"ports": db.get_ports(scan_id_1), "dns": {}, "subdomains": [], "technologies": [], "findings": db.get_findings(scan_id_1)}
    right = {"ports": db.get_ports(scan_id_2), "dns": {}, "subdomains": [], "technologies": [], "findings": db.get_findings(scan_id_2)}
    diff = compare_scans(left, right)
    console.print(diff)
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        raise SystemExit(cmd_scan(args.target, full=args.full))
    if args.command == "dns":
        raise SystemExit(cmd_dns(args.target))
    if args.command == "ports":
        raise SystemExit(cmd_ports(args.target))
    if args.command == "web":
        raise SystemExit(cmd_web(args.target))
    if args.command == "subdomains":
        raise SystemExit(cmd_subdomains(args.target, args.wordlist))
    if args.command == "report":
        raise SystemExit(cmd_report(args.scan_id, args.format))
    if args.command == "history":
        raise SystemExit(cmd_history())
    if args.command == "compare":
        raise SystemExit(cmd_compare(args.scan_id_1, args.scan_id_2))
    parser.print_help()


if __name__ == "__main__":
    main()
