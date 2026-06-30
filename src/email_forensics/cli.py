from __future__ import annotations

import sys
import json
import argparse
from dataclasses import asdict

from dotenv import load_dotenv
from rich.console import Console

from .parser import parse_email_file
from .heuristics import run_all_heuristics, compute_internal_score
from .verification import verify_urls
from .verdict import build_verdict
from .report import render_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-forensics",
        description="Scans a raw email (.eml/.txt) for phishing indicators and verifies "
                    "findings against external threat intelligence APIs.",
    )
    parser.add_argument("--file", "-f", required=True, help="Path to the .eml or .txt email file")
    parser.add_argument("--no-api", action="store_true", help="Skip external API verification (heuristics only)")
    parser.add_argument("--json", metavar="PATH", help="Also write the full result as JSON to this path")
    return parser


def run(argv: list[str] | None = None) -> int:
    load_dotenv()
    console = Console()
    args = build_arg_parser().parse_args(argv)

    try:
        email_obj = parse_email_file(args.file)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] file not found: {args.file}")
        return 1
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Error parsing email:[/bold red] {exc}")
        return 1

    with console.status("[bold cyan]Running heuristic analysis...[/bold cyan]"):
        flags = run_all_heuristics(email_obj)
        internal_score = compute_internal_score(flags)

    url_verdicts = []
    if not args.no_api:
        unique_urls = list(dict.fromkeys(u.raw for u in email_obj.urls))
        if unique_urls:
            with console.status(f"[bold cyan]Verifying {len(unique_urls)} URL(s) against external APIs...[/bold cyan]"):
                url_verdicts = verify_urls(unique_urls)

    verdict = build_verdict(flags, internal_score, url_verdicts)
    render_report(email_obj, verdict, console)

    if args.json:
        output = {
            "source_file": email_obj.source_path,
            "from": email_obj.from_addr,
            "subject": email_obj.subject,
            "internal_score": verdict.internal_score,
            "final_score": verdict.final_score,
            "label": verdict.label,
            "external_confirmed_malicious": verdict.external_confirmed_malicious,
            "agreement_note": verdict.agreement_note,
            "flags": [asdict(f) for f in flags],
            "url_verdicts": [asdict(v) for v in url_verdicts],
        }
        with open(args.json, "w") as fh:
            json.dump(output, fh, indent=2)
        console.print(f"\n[dim]Full results written to {args.json}[/dim]")

    return 0


if __name__ == "__main__":
    sys.exit(run())
