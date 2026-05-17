import hashlib
import hmac
import zipfile
import base64
import json
import os
from typing import Callable


SUPPORTED_ALGORITHMS = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_256", "sha3_512", "blake2b", "blake2s",
]


def _hash_word(word: str, algorithm: str) -> str:
    algo = algorithm.lower().replace("-", "_")
    data = word.encode("utf-8", errors="ignore")
    if algo == "blake2b":
        return hashlib.blake2b(data).hexdigest()
    if algo == "blake2s":
        return hashlib.blake2s(data).hexdigest()
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def crack_hash(
    target: str,
    wordlist_path: str,
    algorithm: str = "sha256",
    progress_cb: Callable[[int], None] | None = None,
) -> dict:
    """
    Crack a hash against a wordlist file.
    Returns {"found": bool, "password": str|None, "attempts": int}
    """
    target = target.strip().lower()
    algo   = algorithm.lower().replace("-", "_")

    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    attempts = 0
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            word = line.rstrip("\n\r")
            candidate = _hash_word(word, algo)
            attempts += 1
            if progress_cb and attempts % 10_000 == 0:
                progress_cb(attempts)
            if candidate == target:
                return {"found": True, "password": word, "attempts": attempts}

    return {"found": False, "password": None, "attempts": attempts}


def crack_zip(
    zip_path: str,
    wordlist_path: str,
    progress_cb: Callable[[int], None] | None = None,
) -> dict:
    """
    Crack a password-protected ZIP file against a wordlist.
    Returns {"found": bool, "password": str|None, "attempts": int}
    """
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(f"ZIP not found: {zip_path}")
    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    attempts = 0
    with zipfile.ZipFile(zip_path) as zf:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wl:
            for line in wl:
                pwd = line.rstrip("\n\r")
                attempts += 1
                if progress_cb and attempts % 1_000 == 0:
                    progress_cb(attempts)
                try:
                    zf.extractall(pwd=pwd.encode("utf-8"))
                    return {"found": True, "password": pwd, "attempts": attempts}
                except (RuntimeError, zipfile.BadZipFile):
                    continue

    return {"found": False, "password": None, "attempts": attempts}


def _decode_jwt_part(part: str) -> dict:
    padding = 4 - len(part) % 4
    part   += "=" * (padding % 4)
    decoded = base64.urlsafe_b64decode(part)
    return json.loads(decoded)


def decode_jwt(token: str) -> dict:
    """
    Decode a JWT token without verifying the signature.
    Returns {"header": dict, "payload": dict, "signature": str, "algorithm": str}
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT — expected 3 parts separated by '.'")

    header  = _decode_jwt_part(parts[0])
    payload = _decode_jwt_part(parts[1])
    return {
        "header":    header,
        "payload":   payload,
        "signature": parts[2],
        "algorithm": header.get("alg", "unknown"),
        "raw_parts": parts,
    }


def crack_jwt(
    token: str,
    wordlist_path: str,
    progress_cb: Callable[[int], None] | None = None,
) -> dict:
    """
    Brute force a JWT HS256/HS384/HS512 secret against a wordlist.
    Returns {"found": bool, "secret": str|None, "attempts": int}
    """
    if not os.path.isfile(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    info = decode_jwt(token)
    alg  = info["algorithm"].upper()

    if alg not in ("HS256", "HS384", "HS512"):
        raise ValueError(f"Algorithm {alg} is not supported for cracking — only HS256/384/512")

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn  = hash_map[alg]

    header_payload = f"{info['raw_parts'][0]}.{info['raw_parts'][1]}".encode()
    target_sig     = info["raw_parts"][2]

    attempts = 0
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            secret = line.rstrip("\n\r").encode("utf-8")
            attempts += 1
            if progress_cb and attempts % 10_000 == 0:
                progress_cb(attempts)
            sig = base64.urlsafe_b64encode(
                hmac.new(secret, header_payload, hash_fn).digest()
            ).rstrip(b"=").decode()
            if sig == target_sig:
                return {"found": True, "secret": line.rstrip("\n\r"), "attempts": attempts}

    return {"found": False, "secret": None, "attempts": attempts}
