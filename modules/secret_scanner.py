import re
import os
from dataclasses import dataclass, field
from typing import Generator


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    match: str
    context: str


RULES: list[dict] = [
    # API Keys & Tokens
    {"name": "AWS Access Key", "severity": "CRITICAL",
     "pattern": r"(?i)(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}"},
    {"name": "AWS Secret Key", "severity": "CRITICAL",
     "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+]{40}['\"]"},
    {"name": "GitHub Token", "severity": "CRITICAL",
     "pattern": r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"},
    {"name": "GitHub OAuth", "severity": "CRITICAL",
     "pattern": r"gho_[A-Za-z0-9]{36}"},
    {"name": "GitHub Actions", "severity": "CRITICAL",
     "pattern": r"ghs_[A-Za-z0-9]{36}"},
    {"name": "GitLab Token", "severity": "CRITICAL",
     "pattern": r"glpat-[A-Za-z0-9\-_]{20}"},
    {"name": "Slack Token", "severity": "CRITICAL",
     "pattern": r"xox[baprs]-[A-Za-z0-9\-]{10,48}"},
    {"name": "Slack Webhook", "severity": "HIGH",
     "pattern": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{24}"},
    {"name": "Stripe Secret Key", "severity": "CRITICAL",
     "pattern": r"sk_live_[A-Za-z0-9]{24,}"},
    {"name": "Stripe Publishable Key", "severity": "MEDIUM",
     "pattern": r"pk_live_[A-Za-z0-9]{24,}"},
    {"name": "Twilio API Key", "severity": "HIGH",
     "pattern": r"SK[a-z0-9]{32}"},
    {"name": "SendGrid API Key", "severity": "HIGH",
     "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"},
    {"name": "Google API Key", "severity": "HIGH",
     "pattern": r"AIza[A-Za-z0-9\-_]{35}"},
    {"name": "Google OAuth", "severity": "HIGH",
     "pattern": r"[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com"},
    {"name": "Firebase URL", "severity": "MEDIUM",
     "pattern": r"[a-z0-9-]+\.firebaseio\.com"},
    {"name": "Heroku API Key", "severity": "HIGH",
     "pattern": r"[hH]eroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"},
    {"name": "Mailchimp API Key", "severity": "HIGH",
     "pattern": r"[A-Za-z0-9]{32}-us[0-9]{1,2}"},
    {"name": "NPM Token", "severity": "HIGH",
     "pattern": r"npm_[A-Za-z0-9]{36}"},
    {"name": "PyPI Token", "severity": "HIGH",
     "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}"},
    {"name": "Telegram Bot Token", "severity": "HIGH",
     "pattern": r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"},
    {"name": "Discord Token", "severity": "HIGH",
     "pattern": r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}"},
    {"name": "Twitter Bearer Token", "severity": "HIGH",
     "pattern": r"AAAA[A-Za-z0-9%]{80,}"},
    {"name": "Shopify Token", "severity": "HIGH",
     "pattern": r"shpss_[A-Za-z0-9]{32}|shpat_[A-Za-z0-9]{32}"},
    {"name": "Azure Client Secret", "severity": "CRITICAL",
     "pattern": r"(?i)azure.{0,20}(client.secret|password).{0,5}['\"][A-Za-z0-9~._\-]{34,}['\"]"},
    {"name": "Private Key (PEM)", "severity": "CRITICAL",
     "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"},
    {"name": "JWT Token", "severity": "MEDIUM",
     "pattern": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"},
    # Passwords in code
    {"name": "Hardcoded Password", "severity": "HIGH",
     "pattern": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]"},
    {"name": "Hardcoded Secret", "severity": "HIGH",
     "pattern": r"(?i)(secret|api_secret|client_secret)\s*=\s*['\"][^'\"]{8,}['\"]"},
    {"name": "Hardcoded Token", "severity": "HIGH",
     "pattern": r"(?i)(token|auth_token|access_token)\s*=\s*['\"][^'\"]{8,}['\"]"},
    {"name": "Connection String", "severity": "CRITICAL",
     "pattern": r"(?i)(mongodb|postgresql|mysql|redis|amqp)://[^\s\"']{10,}"},
    {"name": "Basic Auth in URL", "severity": "HIGH",
     "pattern": r"https?://[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.@!#$%^&*]+@"},
    # Sensitive files committed
    {"name": ".env file content", "severity": "HIGH",
     "pattern": r"(?m)^[A-Z_]+=.+$"},
]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe",
    ".lock", ".sum",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".idea", ".vscode",
    "vendor", "target", "bin", "obj",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    "Pipfile.lock", "composer.lock", "go.sum",
}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


def _mask(value: str, visible: int = 6) -> str:
    if len(value) <= visible * 2:
        return "*" * len(value)
    return value[:visible] + "..." + value[-visible:]


def _iter_files(root: str) -> Generator[str, None, None]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            _, ext = os.path.splitext(filename)
            if ext.lower() in SKIP_EXTENSIONS:
                continue
            yield os.path.join(dirpath, filename)


def scan_directory(root: str) -> list[Finding]:
    findings: list[Finding] = []
    compiled = [(r["name"], r["severity"], re.compile(r["pattern"])) for r in RULES]

    for filepath in _iter_files(root):
        try:
            if os.path.getsize(filepath) > MAX_FILE_SIZE:
                continue
            with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except (OSError, PermissionError):
            continue

        rel = os.path.relpath(filepath, root)

        for lineno, line in enumerate(lines, start=1):
            for name, severity, pattern in compiled:
                for m in pattern.finditer(line):
                    raw = m.group(0)
                    findings.append(Finding(
                        file=rel,
                        line=lineno,
                        rule=name,
                        severity=severity,
                        match=_mask(raw),
                        context=line.rstrip(),
                    ))

    return findings


def scan_git_history(repo_path: str, max_commits: int = 200) -> list[Finding]:
    try:
        import git  # type: ignore
    except ImportError:
        return []

    findings: list[Finding] = []
    compiled = [(r["name"], r["severity"], re.compile(r["pattern"])) for r in RULES]

    try:
        repo = git.Repo(repo_path)
    except Exception:
        return []

    for commit in list(repo.iter_commits())[:max_commits]:
        try:
            diff = commit.tree.diff(commit.parents[0] if commit.parents else git.NULL_TREE)
        except Exception:
            continue

        for diff_item in diff:
            try:
                blob = diff_item.a_blob or diff_item.b_blob
                if not blob:
                    continue
                content = blob.data_stream.read().decode("utf-8", errors="ignore")
            except Exception:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for name, severity, pattern in compiled:
                    for m in pattern.finditer(line):
                        raw = m.group(0)
                        label = f"[git:{commit.hexsha[:8]}] {diff_item.b_path or diff_item.a_path}"
                        findings.append(Finding(
                            file=label,
                            line=lineno,
                            rule=name,
                            severity=severity,
                            match=_mask(raw),
                            context=line.rstrip(),
                        ))

    return findings
