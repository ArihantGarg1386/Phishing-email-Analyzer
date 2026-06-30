"""
Renders a ParsedEmail + FinalVerdict as a structured terminal report
using `rich`. Kept separate from the analysis logic so the same data
could later be rendered as JSON/HTML without touching detection code.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .parser import ParsedEmail
from .verdict import FinalVerdict

VERDICT_COLORS = {
    "Clean": "green",
    "Suspicious": "yellow",
    "Likely Phishing": "dark_orange",
    "Confirmed Malicious": "bold red",
}

SEVERITY_COLOR_THRESHOLDS = [(70, "red"), (35, "yellow"), (0, "cyan")]


def _severity_color(sev: int) -> str:
    for threshold, color in SEVERITY_COLOR_THRESHOLDS:
        if sev >= threshold:
            return color
    return "cyan"


def render_report(email_obj: ParsedEmail, verdict: FinalVerdict, console: Console | None = None) -> None:
    console = console or Console()

    console.rule("[bold]Email Forensics Report[/bold]")
    console.print(f"[dim]Source file:[/dim] {email_obj.source_path}\n")

    # --- Header summary table ---
    header_table = Table(title="Header Analysis", show_lines=False, expand=True)
    header_table.add_column("Field", style="bold")
    header_table.add_column("Value")
    header_table.add_row("From", email_obj.from_addr or "—")
    header_table.add_row("Reply-To", email_obj.reply_to or "—")
    header_table.add_row("Return-Path", email_obj.return_path or "—")
    header_table.add_row("Subject", email_obj.subject or "—")
    header_table.add_row("SPF", email_obj.spf_result or "not present")
    header_table.add_row("DKIM", email_obj.dkim_result or "not present")
    header_table.add_row("DMARC", email_obj.dmarc_result or "not present")
    header_table.add_row("Received hops", str(len(email_obj.received_chain)))
    header_table.add_row("Attachments", str(len(email_obj.attachments)) or "0")
    console.print(header_table)
    console.print()

    # --- Heuristic flags table ---
    if verdict.flags:
        flags_table = Table(title="Heuristic Flags", expand=True)
        flags_table.add_column("Severity", justify="right", width=10)
        flags_table.add_column("Rule")
        flags_table.add_column("Description")
        for f in sorted(verdict.flags, key=lambda x: -x.severity):
            color = _severity_color(f.severity)
            flags_table.add_row(f"[{color}]{f.severity}[/{color}]", f.rule, f.description)
        console.print(flags_table)
    else:
        console.print(Panel("No heuristic flags triggered.", border_style="green"))
    console.print()

    # --- External verification table ---
    if verdict.url_verdicts:
        url_table = Table(title="External URL Verification", expand=True)
        url_table.add_column("URL", overflow="fold")
        url_table.add_column("Source")
        url_table.add_column("Result")
        url_table.add_column("Detail")
        for v in verdict.url_verdicts:
            result_text = "[bold red]MALICIOUS[/bold red]" if v.malicious else "[green]clean[/green]"
            url_table.add_row(v.url, v.source, result_text, v.detail)
        console.print(url_table)
    else:
        console.print(Panel(
            "No external verification performed (no URLs found, or no API keys configured).",
            border_style="dim",
        ))
    console.print()

    # --- Final verdict panel ---
    color = VERDICT_COLORS.get(verdict.label, "white")
    verdict_text = Text()
    verdict_text.append(f"VERDICT: {verdict.label}\n", style=f"bold {color}")
    verdict_text.append(f"Final Score: {verdict.final_score}/100\n")
    verdict_text.append(f"Internal Heuristic Score: {verdict.internal_score}/100\n")
    verdict_text.append(f"Externally Confirmed Malicious: {verdict.external_confirmed_malicious}\n\n")
    verdict_text.append(verdict.agreement_note, style="italic")

    console.print(Panel(verdict_text, title="Final Verdict", border_style=color, expand=True))
