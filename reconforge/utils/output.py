"""Rich output helpers."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def show_banner() -> None:
    console.print(Panel.fit("[bold cyan]RECONFORGE v0.1.0[/bold cyan]\n[green]Authorized reconnaissance and attack-surface intelligence[/green]", border_style="cyan"))


def print_table(title: str, rows: list[dict], columns: list[str]) -> None:
    table = Table(title=title, show_header=True, header_style="bold magenta")
    for column in columns:
        table.add_column(column, style="cyan")
    for row in rows:
        table.add_row(*[str(row.get(column, "")) for column in columns])
    console.print(table)
