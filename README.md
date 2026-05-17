# LockPick — Terminal Security Toolkit

> Find what shouldn't be there. Before someone else does.

A Python CLI security toolkit — scan repos for leaked secrets, audit passwords, hash files, and more — all from your terminal.

## Features

| Command | What it does |
|---|---|
| `scan` | Scan a directory/repo for 30+ types of hardcoded secrets & credentials |
| `password check` | Analyze password strength + check HaveIBeenPwned (k-Anonymity) |
| `password generate` | Generate a cryptographically strong password |
| `hash text/file` | Hash strings or files with 10 algorithms |
| `hash verify` | Verify a hash against a known value |
| `hash hmac` | Generate an HMAC signature |

## Installation

```bash
git clone https://github.com/sophireaks/LockPick.git
cd LockPick
pip install -r requirements.txt
```

> Optional: `pip install gitpython` to enable git history scanning.

## Usage

### Interactive mode (recommended)

Just run with no arguments to get the interactive menu:

```bash
python main.py
```

```
  [1] Scan directory for secrets
  [2] Password check
  [3] Password generate
  [4] Hash text
  [5] Hash file
  [6] Hash verify
  [7] Generate HMAC
  [0] Exit
```

Pick a number, answer the prompts, and the tool does the rest. The menu loops until you exit.

---

### Command-line mode

You can also run commands directly:

```bash
# Scan a repo for secrets
python main.py scan /path/to/repo
python main.py scan .                      # current directory
python main.py scan . --no-history         # skip git history
python main.py scan . --commits 500        # scan last 500 commits
python main.py scan . --json report.json   # save findings to JSON

# Password tools
python main.py password check "MyP@ssw0rd"
python main.py password check "hunter2" --no-hibp
python main.py password generate
python main.py password generate --length 24 --no-symbols

# Hashing
python main.py hash text "hello world"
python main.py hash text "hello world" --algorithm sha512
python main.py hash text "hello world" --all
python main.py hash file ./myfile.zip
python main.py hash verify "hello world" 2cf24d...
python main.py hash hmac "message" "secret-key"
```

## Secret Detection Rules

The scanner detects 30+ credential types including:

- AWS Access Keys & Secret Keys
- GitHub / GitLab / NPM / PyPI tokens
- Stripe, SendGrid, Twilio, Slack, Discord API keys
- Google API Keys & OAuth credentials
- Firebase, Heroku, Shopify, Azure secrets
- PEM private keys (RSA, EC, DSA, OpenSSH)
- JWT tokens
- Hardcoded passwords, tokens, connection strings
- Basic auth credentials in URLs

Findings are masked before display — the actual secret value is never printed in full.

## Privacy

- HIBP password checks use **k-Anonymity**: only the first 5 characters of the SHA-1 hash are sent to the API. Your password never leaves your machine.
- Secret scanner runs **entirely offline**.

## Severity Levels

| Level | Meaning |
|---|---|
| CRITICAL | Immediate risk — rotate now |
| HIGH | Likely exploitable credential |
| MEDIUM | Potential exposure |
| LOW | Informational |
