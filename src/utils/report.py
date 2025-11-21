import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗  ██████╗  ██████╗██╗  ██╗███████╗██████╗            ║
║   ██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗           ║
║   ██║  ██║██║   ██║██║     █████╔╝ █████╗  ██████╔╝           ║
║   ██║  ██║██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗           ║
║   ██████╔╝╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║           ║
║   ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝           ║
║                                                               ║
║        Container Misconfiguration Scanner v1.0                ║
║              Created by havoc                                 ║
╚═══════════════════════════════════════════════════════════════╝
"""


def print_banner() -> None:
    console = Console()
    console.print(BANNER, style="bold cyan")


def print_findings(findings: list[dict], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(findings, indent=2))
        return
    
    if not findings:
        console = Console()
        console.print("[green]No misconfigurations found![/green]")
        return
    
    table = Table(title="Misconfiguration Report")
    table.add_column("Severity", style="bold")
    table.add_column("Check")
    table.add_column("Details")
    
    for finding in findings:
        severity = finding["severity"]
        color = "red" if severity == "HIGH" else "yellow" if severity == "MEDIUM" else "blue"
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            finding["check"],
            finding["details"]
        )
    
    console = Console()
    console.print(table)
