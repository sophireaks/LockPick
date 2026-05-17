# LockPick

> Find what shouldn't be there. Before someone else does.

LockPick is an open-source terminal security toolkit for developers. Scan your repos for leaked credentials, audit passwords against breach databases, hash and verify files — all without leaving the terminal.

---

## Requirements

- Python 3.10 or higher
- pip

---

## Installation

**1. Clone the repo**
```bash
git clone https://github.com/sophireaks/LockPick.git
cd LockPick
```

**2. (Recommended) Create a virtual environment**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. (Optional) Enable git history scanning**
```bash
pip install gitpython
```

---

## Quick Start

Run with no arguments to launch the interactive menu:

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

Pick a number, answer the prompts, results appear instantly. The menu loops until you choose `0` to exit.

---

## Features

### 1. Secret Scanner
Scans every file in a directory (and optionally the full git commit history) for hardcoded credentials.

Detects 30+ types including:
- AWS Access Keys & Secret Keys
- GitHub, GitLab, NPM, PyPI tokens
- Stripe, SendGrid, Twilio, Slack, Discord API keys
- Google API Keys & OAuth credentials
- Firebase, Heroku, Shopify, Azure secrets
- RSA / EC / OpenSSH private keys (PEM)
- JWT tokens
- Hardcoded passwords, connection strings, basic-auth URLs

> All matches are **masked** before display — the real secret value is never printed in full.

```bash
python main.py scan .                      # scan current directory
python main.py scan /path/to/repo
python main.py scan . --no-history         # skip git history
python main.py scan . --commits 500        # scan deeper into git history
python main.py scan . --json report.json   # export findings to JSON
```

Findings are sorted by severity: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW`

---

### 2. Password Audit
Checks a password's strength and whether it has appeared in known data breaches.

```bash
python main.py password check "MyP@ssw0rd"
python main.py password check "hunter2" --no-hibp   # skip breach check
```

**What it checks:**
- Length, character variety, entropy (bits)
- Repeated or sequential patterns
- Membership in a list of 30+ common passwords
- Breach exposure via the [HaveIBeenPwned](https://haveibeenpwned.com/API/v3) API

> **Privacy:** uses k-Anonymity — only the first 5 characters of the SHA-1 hash are sent. Your full password never leaves your machine.

---

### 3. Password Generator
Generates a cryptographically secure password that passes strength checks.

```bash
python main.py password generate
python main.py password generate --length 24
python main.py password generate --length 20 --no-symbols
python main.py password generate --no-ambiguous     # exclude 0, O, 1, l, I
```

---

### 4. Hashing
Hash text or files using 10 supported algorithms:
`md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha3_256`, `sha3_512`, `blake2b`, `blake2s`

```bash
python main.py hash text "hello world"
python main.py hash text "hello world" --algorithm sha512
python main.py hash text "hello world" --all          # show every algorithm at once

python main.py hash file ./archive.zip
python main.py hash file ./archive.zip --algorithm md5
```

---

### 5. Hash Verification
Verify that a value matches a known hash — useful for checking file integrity.

```bash
python main.py hash verify "hello world" b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

---

### 6. HMAC
Generate a Hash-based Message Authentication Code to sign and verify messages.

```bash
python main.py hash hmac "my message" "my-secret-key"
python main.py hash hmac "my message" "my-secret-key" --algorithm sha512
```

---

## Severity Reference

| Level | Meaning |
|---|---|
| `CRITICAL` | Active credential — assume compromised, rotate immediately |
| `HIGH` | Likely exploitable secret or token |
| `MEDIUM` | Potential exposure, review manually |
| `LOW` | Informational, low risk |

---

## Tips

- Run `python main.py scan .` before every commit to catch secrets early
- Use `--json report.json` to pipe findings into other tools or CI pipelines
- Run `password generate --length 24` whenever you need a new credential
- Add LockPick to your CI pipeline to block PRs that introduce secrets

---

## Contributing

Contributions are welcome.

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes and test them
4. Push and open a Pull Request

Ideas for contributions:
- New secret detection patterns
- Additional hash algorithms
- Export formats (HTML report, CSV)
- CI/CD integration guide

---

## License

MIT — see [LICENSE](LICENSE) for details.
