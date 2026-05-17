import hashlib
import urllib.request
import urllib.error


def check_password_pwned(password: str) -> dict:
    """
    Checks password against the Have I Been Pwned API using k-Anonymity.
    Only the first 5 chars of the SHA-1 hash are sent — the full password never leaves the machine.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "SecurityTool-CV/1.0"}

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8")
    except urllib.error.URLError as exc:
        return {"checked": False, "error": str(exc), "count": 0}

    for line in body.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix.upper() == suffix:
            return {"checked": True, "pwned": True, "count": int(count)}

    return {"checked": True, "pwned": False, "count": 0}
