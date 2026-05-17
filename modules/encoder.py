import base64
import urllib.parse
import html
import codecs
import binascii
import json
import re


METHODS = ["base64", "base64url", "hex", "url", "html", "rot13", "binary", "reverse", "unicode"]


def encode(text: str, method: str) -> str:
    m = method.lower().strip()
    if m == "base64":
        return base64.b64encode(text.encode()).decode()
    if m == "base64url":
        return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()
    if m == "hex":
        return text.encode().hex()
    if m == "url":
        return urllib.parse.quote(text, safe="")
    if m == "html":
        return html.escape(text, quote=True)
    if m == "rot13":
        return codecs.encode(text, "rot_13")
    if m == "binary":
        return " ".join(format(ord(c), "08b") for c in text)
    if m == "reverse":
        return text[::-1]
    if m == "unicode":
        return text.encode("unicode_escape").decode()
    raise ValueError(f"Unknown method: {method}. Choose from: {', '.join(METHODS)}")


def decode(text: str, method: str) -> str:
    m = method.lower().strip()
    if m == "base64":
        padding = 4 - len(text) % 4
        text   += "=" * (padding % 4)
        return base64.b64decode(text).decode("utf-8", errors="replace")
    if m == "base64url":
        text   += "=" * (4 - len(text) % 4)
        return base64.urlsafe_b64decode(text).decode("utf-8", errors="replace")
    if m == "hex":
        return bytes.fromhex(text.replace(" ", "")).decode("utf-8", errors="replace")
    if m == "url":
        return urllib.parse.unquote(text)
    if m == "html":
        return html.unescape(text)
    if m == "rot13":
        return codecs.encode(text, "rot_13")
    if m == "binary":
        parts = text.strip().split()
        return "".join(chr(int(b, 2)) for b in parts)
    if m == "reverse":
        return text[::-1]
    if m == "unicode":
        return text.encode("utf-8").decode("unicode_escape")
    raise ValueError(f"Unknown method: {method}. Choose from: {', '.join(METHODS)}")


def auto_detect(text: str) -> list[dict]:
    """
    Try to auto-detect the encoding of a string and return all successful decodings.
    """
    results = []
    text = text.strip()

    # Base64
    try:
        padded = text + "=" * (4 - len(text) % 4)
        decoded = base64.b64decode(padded).decode("utf-8")
        if decoded.isprintable():
            results.append({"method": "base64", "result": decoded})
    except Exception:
        pass

    # Base64 URL-safe
    try:
        padded  = text + "=" * (4 - len(text) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        if decoded.isprintable() and decoded != text:
            results.append({"method": "base64url", "result": decoded})
    except Exception:
        pass

    # Hex
    try:
        clean = text.replace(" ", "").replace("0x", "")
        if re.fullmatch(r"[0-9a-fA-F]+", clean) and len(clean) % 2 == 0:
            decoded = bytes.fromhex(clean).decode("utf-8")
            if decoded.isprintable():
                results.append({"method": "hex", "result": decoded})
    except Exception:
        pass

    # URL encoded
    try:
        if "%" in text:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                results.append({"method": "url", "result": decoded})
    except Exception:
        pass

    # HTML entities
    try:
        if "&" in text and ";" in text:
            decoded = html.unescape(text)
            if decoded != text:
                results.append({"method": "html", "result": decoded})
    except Exception:
        pass

    # ROT13
    try:
        decoded = codecs.encode(text, "rot_13")
        if decoded.isascii() and decoded.isprintable() and decoded != text:
            results.append({"method": "rot13", "result": decoded})
    except Exception:
        pass

    # Binary
    try:
        parts = text.strip().split()
        if all(re.fullmatch(r"[01]{8}", p) for p in parts) and parts:
            decoded = "".join(chr(int(b, 2)) for b in parts)
            if decoded.isprintable():
                results.append({"method": "binary", "result": decoded})
    except Exception:
        pass

    return results
