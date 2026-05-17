#!/usr/bin/env python3
"""
LockPick -- Terminal Security Toolkit
Commands: password, hash, scan
"""

import argparse
import json
import os
import sys
import time

# Force UTF-8 output on Windows so Unicode chars render correctly
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

VERSION = "1.1.0"

console = Console(highlight=False)

BANNER = """[bold cyan]
  ██╗      ██████╗  ██████╗██╗  ██╗██████╗ ██╗ ██████╗██╗  ██╗
  ██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔══██╗██║██╔════╝██║ ██╔╝
  ██║     ██║   ██║██║     █████╔╝ ██████╔╝██║██║     █████╔╝
  ██║     ██║   ██║██║     ██╔═██╗ ██╔═══╝ ██║██║     ██╔═██╗
  ███████╗╚██████╔╝╚██████╗██║  ██╗██║     ██║╚██████╗██║  ██╗
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝[/bold cyan]
[dim]      Find what shouldn't be there. Before someone else does.  v{version}[/dim]
""".format(version=VERSION)

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}

STRENGTH_COLORS = {
    "STRONG":   "bold green",
    "GOOD":     "green",
    "FAIR":     "yellow",
    "WEAK":     "red",
    "CRITICAL": "bold red",
}

OK   = "[green] OK [/green]"
FAIL = "[red]FAIL[/red]"


def _strength_bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    empty  = width - filled
    if score >= 80:
        color = "green"
    elif score >= 60:
        color = "yellow"
    elif score >= 40:
        color = "dark_orange"
    else:
        color = "red"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"


# ------------------------------------------------------------------ password

def cmd_password_check(args: argparse.Namespace) -> None:
    from modules.password_strength import analyze_password
    from modules.hibp import check_password_pwned

    password = args.password
    result   = analyze_password(password)
    strength = result["strength"]
    color    = STRENGTH_COLORS.get(strength, "white")
    bar      = _strength_bar(result["score"])

    console.print()
    console.print(Panel(
        f"  {bar}  [{color}]{strength}[/{color}]  {result['score']}/100\n\n"
        f"  [bold]Entropy:[/bold] {result['entropy']} bits   "
        f"[bold]Length:[/bold] {result['length']} chars",
        title="[bold]Password Analysis[/bold]",
        border_style="cyan",
        padding=(1, 2),
    ))

    details = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    details.add_column("Check", style="dim")
    details.add_column("Result")
    details.add_row("Lowercase letters", OK if result["has_lower"] else FAIL)
    details.add_row("Uppercase letters", OK if result["has_upper"] else FAIL)
    details.add_row("Digits",            OK if result["has_digit"] else FAIL)
    details.add_row("Symbols",           OK if result["has_symbol"] else FAIL)
    console.print(details)

    if result["issues"]:
        console.print("[bold yellow]Issues:[/bold yellow]")
        for issue in result["issues"]:
            console.print(f"  [yellow]*[/yellow] {issue}")

    if result["suggestions"]:
        console.print("[bold cyan]Suggestions:[/bold cyan]")
        for s in result["suggestions"]:
            console.print(f"  [cyan]->[/cyan] {s}")

    if not args.no_hibp:
        console.print()
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            progress.add_task("Checking Have I Been Pwned...", total=None)
            hibp = check_password_pwned(password)

        if not hibp["checked"]:
            console.print(f"[yellow]HIBP check failed:[/yellow] {hibp.get('error', 'Unknown error')}")
        elif hibp["pwned"]:
            console.print(Panel(
                f"[bold red]PWNED![/bold red] Found in [bold]{hibp['count']:,}[/bold] data breaches.\n"
                "[red]Do NOT use this password.[/red]",
                border_style="red",
            ))
        else:
            console.print(Panel(
                "[bold green]Not found in any known data breaches.[/bold green]\n"
                "[dim](HaveIBeenPwned k-Anonymity -- your full password was never sent)[/dim]",
                border_style="green",
            ))
    console.print()


def cmd_password_generate(args: argparse.Namespace) -> None:
    from modules.password_strength import generate_password, analyze_password

    pwd    = generate_password(
        length=args.length,
        use_symbols=not args.no_symbols,
        use_digits=not args.no_digits,
        exclude_ambiguous=args.no_ambiguous,
    )
    result = analyze_password(pwd)
    color  = STRENGTH_COLORS.get(result["strength"], "white")
    bar    = _strength_bar(result["score"])

    console.print()
    console.print(Panel(
        f"[bold green]{pwd}[/bold green]\n\n"
        f"  {bar}  [{color}]{result['strength']}[/{color}]  {result['score']}/100\n"
        f"  Entropy: {result['entropy']} bits",
        title="[bold]Generated Password[/bold]",
        border_style="green",
        padding=(1, 2),
    ))
    console.print()


# ------------------------------------------------------------------ hash

def cmd_hash_text(args: argparse.Namespace) -> None:
    from modules.hasher import hash_text, hash_all_algorithms

    console.print()
    if args.all:
        hashes = hash_all_algorithms(args.text)
        table  = Table(title="All Hashes", box=box.ROUNDED, border_style="cyan")
        table.add_column("Algorithm", style="cyan", no_wrap=True)
        table.add_column("Hash", style="green")
        for algo, h in hashes.items():
            table.add_row(algo, h)
        console.print(table)
    else:
        h = hash_text(args.text, args.algorithm)
        console.print(Panel(
            f"[bold]Algorithm:[/bold] {args.algorithm}\n"
            f"[bold]Hash:[/bold]      [green]{h}[/green]",
            title="Hash Result",
            border_style="cyan",
        ))
    console.print()


def cmd_hash_file(args: argparse.Namespace) -> None:
    from modules.hasher import hash_file

    if not os.path.isfile(args.file):
        console.print(f"[red]File not found:[/red] {args.file}")
        sys.exit(1)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task(f"Hashing {os.path.basename(args.file)}...", total=None)
        result = hash_file(args.file, args.algorithm)

    console.print()
    console.print(Panel(
        f"[bold]File:[/bold]      {result['file']}\n"
        f"[bold]Algorithm:[/bold] {result['algorithm']}\n"
        f"[bold]Size:[/bold]      {result['size_bytes']:,} bytes\n"
        f"[bold]Hash:[/bold]      [green]{result['hash']}[/green]",
        title="File Hash",
        border_style="cyan",
    ))
    console.print()


def cmd_hash_verify(args: argparse.Namespace) -> None:
    from modules.hasher import verify_hash

    match = verify_hash(args.text, args.expected, args.algorithm)
    console.print()
    if match:
        console.print(Panel("[bold green][OK] Hash MATCHES[/bold green]", border_style="green"))
    else:
        console.print(Panel("[bold red][FAIL] Hash MISMATCH[/bold red]", border_style="red"))
    console.print()


def cmd_hmac(args: argparse.Namespace) -> None:
    from modules.hasher import generate_hmac

    result = generate_hmac(args.text, args.key, args.algorithm)
    console.print()
    console.print(Panel(
        f"[bold]HMAC ({args.algorithm}):[/bold] [green]{result}[/green]",
        title="HMAC Result",
        border_style="cyan",
    ))
    console.print()


# ------------------------------------------------------------------ scan

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _print_scan_results(findings: list, stats: dict, path: str) -> None:
    elapsed = stats.get("elapsed", 0)
    scanned = stats.get("files_scanned", 0)
    skipped = stats.get("files_skipped", 0)

    # Stats bar
    console.print(
        f"\n  [dim]Scanned [bold]{scanned}[/bold] files  |  "
        f"Skipped [bold]{skipped}[/bold]  |  "
        f"Time [bold]{elapsed:.2f}s[/bold][/dim]"
    )

    if not findings:
        console.print(Panel(
            "[bold green][OK] No secrets or credentials detected.[/bold green]",
            title=f"[bold]Scan Results — {path}[/bold]",
            border_style="green",
        ))
        return

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            c = SEVERITY_COLORS[sev]
            summary_parts.append(f"[{c}]{counts[sev]} {sev}[/{c}]")

    console.print()
    console.print(Panel(
        "  ".join(summary_parts),
        title=f"[bold red][!] {len(findings)} Finding(s) — {path}[/bold red]",
        border_style="red",
    ))

    table = Table(box=box.ROUNDED, border_style="dim", show_lines=True)
    table.add_column("Severity",       style="bold", width=10)
    table.add_column("Rule",           width=24)
    table.add_column("File",           width=34)
    table.add_column("Line",           width=5, justify="right")
    table.add_column("Match (masked)", width=28)

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.rule,
            f.file,
            str(f.line),
            f"[dim]{f.match}[/dim]",
        )

    console.print(table)
    console.print()


def cmd_scan(args: argparse.Namespace) -> None:
    from modules.secret_scanner import scan_directory, scan_git_history

    path = os.path.abspath(args.path)
    if not os.path.isdir(path):
        console.print(f"[red]Directory not found:[/red] {path}")
        sys.exit(1)

    findings = []
    stats    = {"files_scanned": 0, "files_skipped": 0, "elapsed": 0.0}

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task("Scanning files for secrets...", total=None)
        t0 = time.time()
        dir_findings, dir_stats = scan_directory(path)
        stats["elapsed"]       += time.time() - t0
        stats["files_scanned"] += dir_stats["files_scanned"]
        stats["files_skipped"] += dir_stats["files_skipped"]
        findings.extend(dir_findings)

    if not args.no_history:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as progress:
            progress.add_task(f"Scanning git history (last {args.commits} commits)...", total=None)
            t0 = time.time()
            findings.extend(scan_git_history(path, max_commits=args.commits))
            stats["elapsed"] += time.time() - t0

    _print_scan_results(findings, stats, os.path.basename(path))

    if args.json:
        data = [
            {"file": f.file, "line": f.line, "rule": f.rule,
             "severity": f.severity, "match": f.match}
            for f in findings
        ]
        with open(args.json, "w") as fp:
            json.dump({"stats": stats, "findings": data}, fp, indent=2)
        console.print(f"[dim]JSON report saved -> {args.json}[/dim]\n")


# ------------------------------------------------------------------ CLI setup

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lockpick",
        description="LockPick -- Terminal Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    parser.add_argument("--version",   action="version",   version=f"LockPick v{VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # -- password --
    pw     = sub.add_parser("password", aliases=["pw"], help="Password tools")
    pw_sub = pw.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")

    pw_check = pw_sub.add_parser("check", help="Analyze password strength and check HIBP")
    pw_check.add_argument("password", help="Password to analyze")
    pw_check.add_argument("--no-hibp", action="store_true", help="Skip HaveIBeenPwned check")
    pw_check.set_defaults(func=cmd_password_check)

    pw_gen = pw_sub.add_parser("generate", aliases=["gen"], help="Generate a strong password")
    pw_gen.add_argument("-l", "--length", type=int, default=16, metavar="N")
    pw_gen.add_argument("--no-symbols",   action="store_true")
    pw_gen.add_argument("--no-digits",    action="store_true")
    pw_gen.add_argument("--no-ambiguous", action="store_true")
    pw_gen.set_defaults(func=cmd_password_generate)

    # -- hash --
    ha     = sub.add_parser("hash", help="Hashing tools")
    ha_sub = ha.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")

    ha_text = ha_sub.add_parser("text", help="Hash a string")
    ha_text.add_argument("text")
    ha_text.add_argument("-a", "--algorithm", default="sha256")
    ha_text.add_argument("--all", action="store_true")
    ha_text.set_defaults(func=cmd_hash_text)

    ha_file = ha_sub.add_parser("file", help="Hash a file")
    ha_file.add_argument("file")
    ha_file.add_argument("-a", "--algorithm", default="sha256")
    ha_file.set_defaults(func=cmd_hash_file)

    ha_verify = ha_sub.add_parser("verify", help="Verify a text hash")
    ha_verify.add_argument("text")
    ha_verify.add_argument("expected")
    ha_verify.add_argument("-a", "--algorithm", default="sha256")
    ha_verify.set_defaults(func=cmd_hash_verify)

    ha_hmac = ha_sub.add_parser("hmac", help="Generate an HMAC")
    ha_hmac.add_argument("text")
    ha_hmac.add_argument("key")
    ha_hmac.add_argument("-a", "--algorithm", default="sha256")
    ha_hmac.set_defaults(func=cmd_hmac)

    # -- scan --
    sc = sub.add_parser("scan", help="Scan a directory or repo for secrets")
    sc.add_argument("path", nargs="?", default=".", help="Directory to scan (default: .)")
    sc.add_argument("--no-history", action="store_true",  help="Skip git history scan")
    sc.add_argument("--commits",    type=int, default=200, metavar="N")
    sc.add_argument("--json",       metavar="FILE",        help="Save findings as JSON")
    sc.set_defaults(func=cmd_scan)

    return parser


# ------------------------------------------------------------------ interactive

def _ask(prompt: str, default: str = "") -> str:
    try:
        val = input(f"  {prompt}: ").strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt


def _menu(title: str, options: list[tuple[str, str]]) -> str:
    console.print(f"\n[bold cyan]  {title}[/bold cyan]")
    console.rule(style="dim")
    for key, label in options:
        console.print(f"  [bold cyan][{key}][/bold cyan] {label}")
    console.rule(style="dim")
    try:
        return input("  Choose: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt


def interactive_mode() -> None:
    while True:
        choice = _menu("MAIN MENU", [
            ("1", "Scan directory for secrets"),
            ("2", "Password check"),
            ("3", "Password generate"),
            ("4", "Hash text"),
            ("5", "Hash file"),
            ("6", "Hash verify"),
            ("7", "Generate HMAC"),
            ("0", "Exit"),
        ])

        if choice == "0":
            console.print("\n[dim]  Goodbye.[/dim]\n")
            break

        elif choice == "1":
            path       = _ask("Directory path (Enter for current dir)", ".")
            no_history = _ask("Skip git history scan? [y/N]", "n").lower() == "y"
            commits    = 200
            if not no_history:
                c       = _ask("Max commits to scan (Enter for 200)", "200")
                commits = int(c) if c.isdigit() else 200
            save_json  = _ask("Save JSON report? Enter filename or leave blank", "")

            class A: pass
            a = A(); a.path = path; a.no_history = no_history
            a.commits = commits; a.json = save_json if save_json else None
            cmd_scan(a)

        elif choice == "2":
            pw = _ask("Password to check")
            if not pw:
                console.print("[yellow]  No password entered.[/yellow]")
                continue
            no_hibp = _ask("Skip HIBP check? [y/N]", "n").lower() == "y"
            class A: pass
            a = A(); a.password = pw; a.no_hibp = no_hibp
            cmd_password_check(a)

        elif choice == "3":
            length  = _ask("Length (Enter for 16)", "16")
            length  = int(length) if length.isdigit() else 16
            no_sym  = _ask("Exclude symbols? [y/N]", "n").lower() == "y"
            no_dig  = _ask("Exclude digits? [y/N]", "n").lower() == "y"
            no_amb  = _ask("Exclude ambiguous chars (0O1lI)? [y/N]", "n").lower() == "y"
            class A: pass
            a = A(); a.length = length; a.no_symbols = no_sym
            a.no_digits = no_dig; a.no_ambiguous = no_amb
            cmd_password_generate(a)

        elif choice == "4":
            text     = _ask("Text to hash")
            if not text: continue
            algo     = _ask("Algorithm (Enter for sha256)", "sha256")
            show_all = _ask("Show all algorithms? [y/N]", "n").lower() == "y"
            class A: pass
            a = A(); a.text = text; a.algorithm = algo; a.all = show_all
            cmd_hash_text(a)

        elif choice == "5":
            path = _ask("File path")
            if not path: continue
            algo = _ask("Algorithm (Enter for sha256)", "sha256")
            class A: pass
            a = A(); a.file = path; a.algorithm = algo
            cmd_hash_file(a)

        elif choice == "6":
            text     = _ask("Original text")
            expected = _ask("Expected hash")
            if not text or not expected: continue
            algo     = _ask("Algorithm (Enter for sha256)", "sha256")
            class A: pass
            a = A(); a.text = text; a.expected = expected; a.algorithm = algo
            cmd_hash_verify(a)

        elif choice == "7":
            text = _ask("Text to sign")
            key  = _ask("Secret key")
            if not text or not key: continue
            algo = _ask("Algorithm (Enter for sha256)", "sha256")
            class A: pass
            a = A(); a.text = text; a.key = key; a.algorithm = algo
            cmd_hmac(a)

        else:
            console.print("[yellow]  Invalid choice.[/yellow]")


# ------------------------------------------------------------------ entry point

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        console.print(BANNER)

    if not args.command:
        try:
            interactive_mode()
        except KeyboardInterrupt:
            console.print("\n[dim]  Interrupted.[/dim]\n")
        return

    if not hasattr(args, "func"):
        console.print(f"[yellow]Run:[/yellow] python main.py {args.command} --help")
        return

    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(0)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
