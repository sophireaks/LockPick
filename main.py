#!/usr/bin/env python3
"""
LockPick -- Terminal Security Toolkit
Commands: password, hash, scan, crack, wordlist, encode
"""

import argparse
import json
import os
import sys
import time

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

VERSION = "1.2.0"

console = Console(highlight=False)

BANNER = """[bold cyan]
  ██╗      ██████╗  ██████╗██╗  ██╗██████╗ ██╗ ██████╗██╗  ██╗
  ██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔══██╗██║██╔════╝██║ ██╔╝
  ██║     ██║   ██║██║     █████╔╝ ██████╔╝██║██║     █████╔╝
  ██║     ██║   ██║██║     ██╔═██╗ ██╔═══╝ ██║██║     ██╔═██╗
  ███████╗╚██████╔╝╚██████╗██║  ██╗██║     ██║╚██████╗██║  ██╗
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝╚═╝  ╚═╝[/bold cyan]
[dim]      Find what shouldn't be there. Before someone else does.  v{v}[/dim]
""".format(v=VERSION)

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
    "INFO":     "dim",
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
    color  = "green" if score >= 80 else "yellow" if score >= 60 else "dark_orange" if score >= 40 else "red"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"


# ═══════════════════════════════════════════════════════ PASSWORD

def cmd_password_check(args) -> None:
    from modules.password_strength import analyze_password
    from modules.hibp import check_password_pwned

    result   = analyze_password(args.password)
    strength = result["strength"]
    color    = STRENGTH_COLORS.get(strength, "white")
    bar      = _strength_bar(result["score"])

    console.print()
    console.print(Panel(
        f"  {bar}  [{color}]{strength}[/{color}]  {result['score']}/100\n\n"
        f"  [bold]Entropy:[/bold] {result['entropy']} bits   "
        f"[bold]Length:[/bold] {result['length']} chars",
        title="[bold]Password Analysis[/bold]",
        border_style="cyan", padding=(1, 2),
    ))

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column("Check", style="dim")
    t.add_column("Result")
    t.add_row("Lowercase", OK if result["has_lower"] else FAIL)
    t.add_row("Uppercase", OK if result["has_upper"] else FAIL)
    t.add_row("Digits",    OK if result["has_digit"] else FAIL)
    t.add_row("Symbols",   OK if result["has_symbol"] else FAIL)
    console.print(t)

    for issue in result.get("issues", []):
        console.print(f"  [yellow]*[/yellow] {issue}")
    for s in result.get("suggestions", []):
        console.print(f"  [cyan]->[/cyan] {s}")

    if not args.no_hibp:
        console.print()
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as p:
            p.add_task("Checking HaveIBeenPwned...", total=None)
            hibp = check_password_pwned(args.password)
        if not hibp["checked"]:
            console.print(f"[yellow]HIBP failed:[/yellow] {hibp.get('error')}")
        elif hibp["pwned"]:
            console.print(Panel(
                f"[bold red]PWNED![/bold red] Found in [bold]{hibp['count']:,}[/bold] breaches.\n"
                "[red]Do NOT use this password.[/red]", border_style="red",
            ))
        else:
            console.print(Panel(
                "[bold green]Not found in any known breaches.[/bold green]\n"
                "[dim](k-Anonymity -- your password was never sent)[/dim]", border_style="green",
            ))
    console.print()


def cmd_password_generate(args) -> None:
    from modules.password_strength import generate_password, analyze_password
    pwd    = generate_password(length=args.length, use_symbols=not args.no_symbols,
                               use_digits=not args.no_digits, exclude_ambiguous=args.no_ambiguous)
    result = analyze_password(pwd)
    color  = STRENGTH_COLORS.get(result["strength"], "white")
    console.print()
    console.print(Panel(
        f"[bold green]{pwd}[/bold green]\n\n"
        f"  {_strength_bar(result['score'])}  [{color}]{result['strength']}[/{color}]  "
        f"{result['score']}/100   Entropy: {result['entropy']} bits",
        title="[bold]Generated Password[/bold]", border_style="green", padding=(1, 2),
    ))
    console.print()


# ═══════════════════════════════════════════════════════ HASH

def cmd_hash_text(args) -> None:
    from modules.hasher import hash_text, hash_all_algorithms
    console.print()
    if args.all:
        hashes = hash_all_algorithms(args.text)
        t = Table(title="All Hashes", box=box.ROUNDED, border_style="cyan")
        t.add_column("Algorithm", style="cyan", no_wrap=True)
        t.add_column("Hash", style="green")
        for algo, h in hashes.items():
            t.add_row(algo, h)
        console.print(t)
    else:
        h = hash_text(args.text, args.algorithm)
        console.print(Panel(f"[bold]Algorithm:[/bold] {args.algorithm}\n[bold]Hash:[/bold]      [green]{h}[/green]",
                            title="Hash Result", border_style="cyan"))
    console.print()


def cmd_hash_file(args) -> None:
    from modules.hasher import hash_file
    if not os.path.isfile(args.file):
        console.print(f"[red]File not found:[/red] {args.file}"); sys.exit(1)
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as p:
        p.add_task(f"Hashing {os.path.basename(args.file)}...", total=None)
        result = hash_file(args.file, args.algorithm)
    console.print()
    console.print(Panel(
        f"[bold]File:[/bold]      {result['file']}\n[bold]Algorithm:[/bold] {result['algorithm']}\n"
        f"[bold]Size:[/bold]      {result['size_bytes']:,} bytes\n[bold]Hash:[/bold]      [green]{result['hash']}[/green]",
        title="File Hash", border_style="cyan",
    ))
    console.print()


def cmd_hash_verify(args) -> None:
    from modules.hasher import verify_hash
    match = verify_hash(args.text, args.expected, args.algorithm)
    console.print()
    if match:
        console.print(Panel("[bold green][OK] Hash MATCHES[/bold green]", border_style="green"))
    else:
        console.print(Panel("[bold red][FAIL] Hash MISMATCH[/bold red]", border_style="red"))
    console.print()


def cmd_hmac(args) -> None:
    from modules.hasher import generate_hmac
    result = generate_hmac(args.text, args.key, args.algorithm)
    console.print()
    console.print(Panel(f"[bold]HMAC ({args.algorithm}):[/bold] [green]{result}[/green]",
                        title="HMAC Result", border_style="cyan"))
    console.print()


# ═══════════════════════════════════════════════════════ CRACK

def cmd_crack_hash(args) -> None:
    from modules.cracker import crack_hash
    console.print(f"\n  [cyan]Target:[/cyan]   {args.hash}")
    console.print(f"  [cyan]Wordlist:[/cyan] {args.wordlist}")
    console.print(f"  [cyan]Algorithm:[/cyan] {args.algorithm}\n")

    attempts_ref = [0]
    def progress_cb(n):
        attempts_ref[0] = n

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as p:
        p.add_task(f"Cracking hash...", total=None)
        t0     = time.time()
        result = crack_hash(args.hash, args.wordlist, args.algorithm, progress_cb)
        elapsed = time.time() - t0

    console.print(f"  [dim]Tried {result['attempts']:,} passwords in {elapsed:.2f}s[/dim]\n")
    if result["found"]:
        console.print(Panel(
            f"[bold green]CRACKED![/bold green]\n\n"
            f"  [bold]Password:[/bold] [bold green]{result['password']}[/bold green]",
            title="[bold green]Hash Cracked[/bold green]", border_style="green",
        ))
    else:
        console.print(Panel("[bold red]Not found in wordlist.[/bold red]", border_style="red"))
    console.print()


def cmd_crack_zip(args) -> None:
    from modules.cracker import crack_zip
    console.print(f"\n  [cyan]Target:[/cyan]   {args.zip}")
    console.print(f"  [cyan]Wordlist:[/cyan] {args.wordlist}\n")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as p:
        p.add_task("Cracking ZIP...", total=None)
        t0      = time.time()
        result  = crack_zip(args.zip, args.wordlist)
        elapsed = time.time() - t0

    console.print(f"  [dim]Tried {result['attempts']:,} passwords in {elapsed:.2f}s[/dim]\n")
    if result["found"]:
        console.print(Panel(
            f"[bold green]CRACKED![/bold green]\n\n"
            f"  [bold]Password:[/bold] [bold green]{result['password']}[/bold green]",
            title="[bold green]ZIP Cracked[/bold green]", border_style="green",
        ))
    else:
        console.print(Panel("[bold red]Not found in wordlist.[/bold red]", border_style="red"))
    console.print()


def cmd_crack_jwt(args) -> None:
    from modules.cracker import crack_jwt, decode_jwt

    info = decode_jwt(args.token)
    console.print()

    t = Table(title="JWT Decoded", box=box.ROUNDED, border_style="cyan")
    t.add_column("Field", style="cyan", no_wrap=True)
    t.add_column("Value")
    for k, v in info["header"].items():
        t.add_row(f"header.{k}", str(v))
    for k, v in info["payload"].items():
        t.add_row(f"payload.{k}", str(v))
    alg = info["algorithm"]
    t.add_row("algorithm", f"[yellow]{alg}[/yellow]" if alg == "none" else alg)
    console.print(t)

    if alg.upper() == "NONE":
        console.print(Panel(
            "[bold red][!] Algorithm is 'none' — token is unsigned and trivially forgeable![/bold red]",
            border_style="red",
        ))
        console.print()
        return

    if not args.wordlist:
        console.print()
        return

    console.print(f"\n  [cyan]Wordlist:[/cyan] {args.wordlist}\n")
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as p:
        p.add_task("Cracking JWT secret...", total=None)
        t0      = time.time()
        result  = crack_jwt(args.token, args.wordlist)
        elapsed = time.time() - t0

    console.print(f"  [dim]Tried {result['attempts']:,} secrets in {elapsed:.2f}s[/dim]\n")
    if result["found"]:
        console.print(Panel(
            f"[bold green]CRACKED![/bold green]\n\n"
            f"  [bold]Secret:[/bold] [bold green]{result['secret']}[/bold green]",
            title="[bold green]JWT Secret Found[/bold green]", border_style="green",
        ))
    else:
        console.print(Panel("[bold red]Secret not found in wordlist.[/bold red]", border_style="red"))
    console.print()


# ═══════════════════════════════════════════════════════ WORDLIST

def cmd_wordlist_targeted(args) -> None:
    from modules.wordlist import generate_targeted, save_wordlist
    keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]
    if not keywords:
        console.print("[red]No keywords provided.[/red]"); return

    console.print(f"\n  [cyan]Keywords:[/cyan]  {', '.join(keywords)}")

    gen   = generate_targeted(keywords, include_leet=not args.no_leet,
                              include_suffixes=not args.no_suffixes,
                              capitalize=not args.no_capitalize)
    count = save_wordlist(gen, args.output)
    console.print(Panel(
        f"[bold green]{count:,}[/bold green] passwords saved to [bold]{args.output}[/bold]",
        title="Wordlist Generated", border_style="green",
    ))
    console.print()


def cmd_wordlist_bruteforce(args) -> None:
    from modules.wordlist import generate_bruteforce, save_wordlist, estimate_bruteforce_count

    total = estimate_bruteforce_count(args.charset, args.min_len, args.max_len)
    console.print(f"\n  [cyan]Charset:[/cyan]  {args.charset}")
    console.print(f"  [cyan]Length:[/cyan]   {args.min_len}–{args.max_len}")
    console.print(f"  [cyan]Estimate:[/cyan] {total:,} words\n")

    if total > 10_000_000 and not args.force:
        console.print("[yellow][!] Over 10M words. Add --force to proceed.[/yellow]\n")
        return

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as p:
        p.add_task("Generating wordlist...", total=None)
        count = save_wordlist(generate_bruteforce(args.charset, args.min_len, args.max_len), args.output)

    console.print(Panel(
        f"[bold green]{count:,}[/bold green] passwords saved to [bold]{args.output}[/bold]",
        title="Bruteforce Wordlist Generated", border_style="green",
    ))
    console.print()


# ═══════════════════════════════════════════════════════ ENCODE

def cmd_encode(args) -> None:
    from modules.encoder import encode, decode, auto_detect, METHODS

    console.print()
    if args.auto:
        results = auto_detect(args.text)
        if not results:
            console.print(Panel("[yellow]Could not detect encoding.[/yellow]", border_style="yellow"))
        else:
            t = Table(title="Auto-Detect Results", box=box.ROUNDED, border_style="cyan")
            t.add_column("Method", style="cyan", no_wrap=True)
            t.add_column("Decoded", style="green")
            for r in results:
                t.add_row(r["method"], r["result"])
            console.print(t)
        console.print()
        return

    if not args.method:
        console.print(f"[yellow]Available methods:[/yellow] {', '.join(METHODS)}")
        console.print("Use [cyan]--auto[/cyan] to auto-detect encoding.\n")
        return

    try:
        if args.decode:
            result = decode(args.text, args.method)
            label  = "Decoded"
        else:
            result = encode(args.text, args.method)
            label  = "Encoded"
        console.print(Panel(
            f"[bold]Method:[/bold] {args.method}   [bold]Mode:[/bold] {label}\n\n"
            f"[green]{result}[/green]",
            title=f"{label} Result", border_style="cyan",
        ))
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
    console.print()


# ═══════════════════════════════════════════════════════ SCAN

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _print_scan_results(findings: list, stats: dict, path: str) -> None:
    elapsed = stats.get("elapsed", 0)
    console.print(
        f"\n  [dim]Scanned [bold]{stats.get('files_scanned', 0)}[/bold] files  |  "
        f"Skipped [bold]{stats.get('files_skipped', 0)}[/bold]  |  "
        f"Time [bold]{elapsed:.2f}s[/bold][/dim]"
    )
    if not findings:
        console.print(Panel("[bold green][OK] No secrets or credentials detected.[/bold green]",
                            title=f"[bold]Scan Results — {path}[/bold]", border_style="green"))
        return

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary = "  ".join(
        f"[{SEVERITY_COLORS[s]}]{counts[s]} {s}[/{SEVERITY_COLORS[s]}]"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if s in counts
    )
    console.print()
    console.print(Panel(summary, title=f"[bold red][!] {len(findings)} Finding(s) — {path}[/bold red]",
                        border_style="red"))

    t = Table(box=box.ROUNDED, border_style="dim", show_lines=True)
    t.add_column("Severity",       style="bold", width=10)
    t.add_column("Rule",           width=24)
    t.add_column("File",           width=34)
    t.add_column("Line",           width=5, justify="right")
    t.add_column("Match (masked)", width=28)
    for f in findings:
        c = SEVERITY_COLORS.get(f.severity, "white")
        t.add_row(f"[{c}]{f.severity}[/{c}]", f.rule, f.file, str(f.line), f"[dim]{f.match}[/dim]")
    console.print(t)
    console.print()


def cmd_scan(args) -> None:
    from modules.secret_scanner import scan_directory, scan_git_history
    path = os.path.abspath(args.path)
    if not os.path.isdir(path):
        console.print(f"[red]Directory not found:[/red] {path}"); sys.exit(1)

    findings = []
    stats    = {"files_scanned": 0, "files_skipped": 0, "elapsed": 0.0}

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as p:
        p.add_task("Scanning files for secrets...", total=None)
        t0 = time.time()
        dir_findings, dir_stats = scan_directory(path)
        stats["elapsed"]       += time.time() - t0
        stats["files_scanned"] += dir_stats["files_scanned"]
        stats["files_skipped"] += dir_stats["files_skipped"]
        findings.extend(dir_findings)

    if not args.no_history:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console, transient=True) as p:
            p.add_task(f"Scanning git history (last {args.commits} commits)...", total=None)
            t0 = time.time()
            findings.extend(scan_git_history(path, max_commits=args.commits))
            stats["elapsed"] += time.time() - t0

    _print_scan_results(findings, stats, os.path.basename(path))

    if args.json:
        data = [{"file": f.file, "line": f.line, "rule": f.rule,
                 "severity": f.severity, "match": f.match} for f in findings]
        with open(args.json, "w") as fp:
            json.dump({"stats": stats, "findings": data}, fp, indent=2)
        console.print(f"[dim]JSON report saved -> {args.json}[/dim]\n")


# ═══════════════════════════════════════════════════════ PARSER

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lockpick", description="LockPick -- Terminal Security Toolkit",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version",   action="version", version=f"LockPick v{VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # password
    pw     = sub.add_parser("password", aliases=["pw"], help="Password tools")
    pw_sub = pw.add_subparsers(dest="subcommand")
    pwc = pw_sub.add_parser("check",    help="Analyze password + HIBP check")
    pwc.add_argument("password"); pwc.add_argument("--no-hibp", action="store_true")
    pwc.set_defaults(func=cmd_password_check)
    pwg = pw_sub.add_parser("generate", aliases=["gen"], help="Generate strong password")
    pwg.add_argument("-l", "--length", type=int, default=16)
    pwg.add_argument("--no-symbols",   action="store_true")
    pwg.add_argument("--no-digits",    action="store_true")
    pwg.add_argument("--no-ambiguous", action="store_true")
    pwg.set_defaults(func=cmd_password_generate)

    # hash
    ha     = sub.add_parser("hash", help="Hashing tools")
    ha_sub = ha.add_subparsers(dest="subcommand")
    hat = ha_sub.add_parser("text",   help="Hash a string")
    hat.add_argument("text"); hat.add_argument("-a", "--algorithm", default="sha256")
    hat.add_argument("--all", action="store_true"); hat.set_defaults(func=cmd_hash_text)
    haf = ha_sub.add_parser("file",   help="Hash a file")
    haf.add_argument("file"); haf.add_argument("-a", "--algorithm", default="sha256")
    haf.set_defaults(func=cmd_hash_file)
    hav = ha_sub.add_parser("verify", help="Verify a hash")
    hav.add_argument("text"); hav.add_argument("expected")
    hav.add_argument("-a", "--algorithm", default="sha256"); hav.set_defaults(func=cmd_hash_verify)
    ham = ha_sub.add_parser("hmac",   help="Generate HMAC")
    ham.add_argument("text"); ham.add_argument("key")
    ham.add_argument("-a", "--algorithm", default="sha256"); ham.set_defaults(func=cmd_hmac)

    # scan
    sc = sub.add_parser("scan", help="Scan directory/repo for secrets")
    sc.add_argument("path", nargs="?", default=".")
    sc.add_argument("--no-history", action="store_true")
    sc.add_argument("--commits", type=int, default=200)
    sc.add_argument("--json", metavar="FILE")
    sc.set_defaults(func=cmd_scan)

    # crack
    cr     = sub.add_parser("crack", help="Cracking tools")
    cr_sub = cr.add_subparsers(dest="subcommand")

    crh = cr_sub.add_parser("hash", help="Crack a hash against a wordlist")
    crh.add_argument("hash",                            help="Hash to crack")
    crh.add_argument("wordlist",                        help="Path to wordlist file")
    crh.add_argument("-a", "--algorithm", default="sha256")
    crh.set_defaults(func=cmd_crack_hash)

    crz = cr_sub.add_parser("zip", help="Crack a password-protected ZIP")
    crz.add_argument("zip",      help="Path to ZIP file")
    crz.add_argument("wordlist", help="Path to wordlist file")
    crz.set_defaults(func=cmd_crack_zip)

    crj = cr_sub.add_parser("jwt", help="Decode and optionally crack a JWT token")
    crj.add_argument("token",              help="JWT token string")
    crj.add_argument("wordlist", nargs="?", help="Wordlist to crack HS* secret (optional)")
    crj.set_defaults(func=cmd_crack_jwt)

    # wordlist
    wl     = sub.add_parser("wordlist", aliases=["wl"], help="Wordlist generation tools")
    wl_sub = wl.add_subparsers(dest="subcommand")

    wlt = wl_sub.add_parser("targeted", help="Generate wordlist from keywords")
    wlt.add_argument("keywords",              help="Comma-separated keywords (name, birthday, pet...)")
    wlt.add_argument("-o", "--output",        default="wordlist.txt")
    wlt.add_argument("--no-leet",             action="store_true")
    wlt.add_argument("--no-suffixes",         action="store_true")
    wlt.add_argument("--no-capitalize",       action="store_true")
    wlt.set_defaults(func=cmd_wordlist_targeted)

    wlb = wl_sub.add_parser("bruteforce", help="Generate all combinations for a charset")
    wlb.add_argument("charset", choices=["lowercase","uppercase","digits","alpha","alnum","full"])
    wlb.add_argument("--min-len", type=int, default=1)
    wlb.add_argument("--max-len", type=int, default=4)
    wlb.add_argument("-o", "--output", default="bruteforce.txt")
    wlb.add_argument("--force", action="store_true", help="Generate even if > 10M words")
    wlb.set_defaults(func=cmd_wordlist_bruteforce)

    # encode
    en = sub.add_parser("encode", help="Encode/decode strings (base64, hex, url, rot13...)")
    en.add_argument("text",                  help="String to encode or decode")
    en.add_argument("-m", "--method",        help="Method: base64, hex, url, html, rot13, binary, reverse, unicode")
    en.add_argument("-d", "--decode",        action="store_true", help="Decode instead of encode")
    en.add_argument("--auto",                action="store_true", help="Auto-detect encoding")
    en.set_defaults(func=cmd_encode)

    return parser


# ═══════════════════════════════════════════════════════ INTERACTIVE

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
            ("4", "Hash text / file"),
            ("5", "Crack -- hash / zip / jwt"),
            ("6", "Wordlist generator"),
            ("7", "Encode / Decode"),
            ("0", "Exit"),
        ])

        if choice == "0":
            console.print("\n[dim]  Goodbye.[/dim]\n"); break

        elif choice == "1":
            path       = _ask("Directory path (Enter for current dir)", ".")
            no_history = _ask("Skip git history scan? [y/N]", "n").lower() == "y"
            commits    = 200
            if not no_history:
                c = _ask("Max commits (Enter for 200)", "200")
                commits = int(c) if c.isdigit() else 200
            save_json = _ask("Save JSON report? Filename or blank", "")
            class A: pass
            a = A(); a.path = path; a.no_history = no_history
            a.commits = commits; a.json = save_json or None
            cmd_scan(a)

        elif choice == "2":
            pw = _ask("Password to check")
            if not pw: continue
            no_hibp = _ask("Skip HIBP? [y/N]", "n").lower() == "y"
            class A: pass
            a = A(); a.password = pw; a.no_hibp = no_hibp
            cmd_password_check(a)

        elif choice == "3":
            length  = _ask("Length (Enter for 16)", "16")
            no_sym  = _ask("Exclude symbols? [y/N]", "n").lower() == "y"
            no_dig  = _ask("Exclude digits? [y/N]", "n").lower() == "y"
            no_amb  = _ask("Exclude ambiguous? [y/N]", "n").lower() == "y"
            class A: pass
            a = A(); a.length = int(length) if length.isdigit() else 16
            a.no_symbols = no_sym; a.no_digits = no_dig; a.no_ambiguous = no_amb
            cmd_password_generate(a)

        elif choice == "4":
            sub = _menu("HASH", [("1","Hash text"), ("2","Hash file"), ("3","Verify hash"), ("4","HMAC")])
            class A: pass
            if sub == "1":
                a = A(); a.text = _ask("Text"); a.algorithm = _ask("Algorithm (Enter=sha256)", "sha256")
                a.all = _ask("All algorithms? [y/N]", "n").lower() == "y"
                if a.text: cmd_hash_text(a)
            elif sub == "2":
                a = A(); a.file = _ask("File path"); a.algorithm = _ask("Algorithm (Enter=sha256)", "sha256")
                if a.file: cmd_hash_file(a)
            elif sub == "3":
                a = A(); a.text = _ask("Original text"); a.expected = _ask("Expected hash")
                a.algorithm = _ask("Algorithm (Enter=sha256)", "sha256")
                if a.text and a.expected: cmd_hash_verify(a)
            elif sub == "4":
                a = A(); a.text = _ask("Text"); a.key = _ask("Key")
                a.algorithm = _ask("Algorithm (Enter=sha256)", "sha256")
                if a.text and a.key: cmd_hmac(a)

        elif choice == "5":
            sub = _menu("CRACK", [("1","Crack hash"), ("2","Crack ZIP"), ("3","Decode/crack JWT")])
            class A: pass
            if sub == "1":
                a = A(); a.hash = _ask("Hash to crack"); a.wordlist = _ask("Wordlist path")
                a.algorithm = _ask("Algorithm (Enter=sha256)", "sha256")
                if a.hash and a.wordlist: cmd_crack_hash(a)
            elif sub == "2":
                a = A(); a.zip = _ask("ZIP file path"); a.wordlist = _ask("Wordlist path")
                if a.zip and a.wordlist: cmd_crack_zip(a)
            elif sub == "3":
                a = A(); a.token = _ask("JWT token")
                a.wordlist = _ask("Wordlist to crack secret (blank to just decode)", "") or None
                if a.token: cmd_crack_jwt(a)

        elif choice == "6":
            sub = _menu("WORDLIST", [("1","Targeted (from keywords)"), ("2","Bruteforce (all combos)")])
            class A: pass
            if sub == "1":
                a = A(); a.keywords = _ask("Keywords (comma separated, e.g. john,smith,1990)")
                a.output = _ask("Output file (Enter=wordlist.txt)", "wordlist.txt")
                a.no_leet = _ask("Skip leet variations? [y/N]", "n").lower() == "y"
                a.no_suffixes = _ask("Skip suffixes? [y/N]", "n").lower() == "y"
                a.no_capitalize = _ask("Skip capitalize? [y/N]", "n").lower() == "y"
                if a.keywords: cmd_wordlist_targeted(a)
            elif sub == "2":
                console.print("  [dim]Charsets: lowercase, uppercase, digits, alpha, alnum, full[/dim]")
                a = A(); a.charset = _ask("Charset (Enter=lowercase)", "lowercase")
                a.min_len = int(_ask("Min length (Enter=1)", "1") or "1")
                a.max_len = int(_ask("Max length (Enter=4)", "4") or "4")
                a.output  = _ask("Output file (Enter=bruteforce.txt)", "bruteforce.txt")
                a.force   = False
                cmd_wordlist_bruteforce(a)

        elif choice == "7":
            sub = _menu("ENCODE", [("1","Encode"), ("2","Decode"), ("3","Auto-detect")])
            class A: pass
            from modules.encoder import METHODS
            if sub in ("1", "2"):
                console.print(f"  [dim]Methods: {', '.join(METHODS)}[/dim]")
                a = A(); a.text = _ask("Text"); a.method = _ask("Method")
                a.decode = (sub == "2"); a.auto = False
                if a.text and a.method: cmd_encode(a)
            elif sub == "3":
                a = A(); a.text = _ask("Text to detect"); a.method = None; a.decode = False; a.auto = True
                if a.text: cmd_encode(a)

        else:
            console.print("[yellow]  Invalid choice.[/yellow]")


# ═══════════════════════════════════════════════════════ ENTRY POINT

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
