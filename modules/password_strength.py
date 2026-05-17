import re
import math
import secrets
import string


COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password123", "admin", "welcome", "login", "solo",
}


def calculate_entropy(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^a-zA-Z\d]", password):
        pool += 32
    return len(password) * math.log2(pool) if pool > 0 else 0


def analyze_password(password: str) -> dict:
    issues = []
    score = 0

    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is a commonly used password")
        return {
            "score": 0, "strength": "CRITICAL", "entropy": 0.0,
            "length": len(password),
            "has_lower": False, "has_upper": False, "has_digit": False, "has_symbol": False,
            "issues": issues, "suggestions": ["Choose a completely different password"],
        }

    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        issues.append(f"Too short ({length} chars) — use at least 12")

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z\d]", password))

    char_types = sum([has_lower, has_upper, has_digit, has_symbol])
    score += char_types * 15

    if not has_upper:
        issues.append("Add uppercase letters")
    if not has_digit:
        issues.append("Add numbers")
    if not has_symbol:
        issues.append("Add symbols (!@#$%...)")

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        issues.append("Avoid repeated characters (aaa, 111)")

    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)", password.lower()):
        score -= 10
        issues.append("Avoid sequential patterns (123, abc)")

    entropy = calculate_entropy(password)
    if entropy >= 60:
        score += 20
    elif entropy >= 40:
        score += 10

    score = max(0, min(100, score))

    if score >= 80:
        strength = "STRONG"
    elif score >= 60:
        strength = "GOOD"
    elif score >= 40:
        strength = "FAIR"
    elif score >= 20:
        strength = "WEAK"
    else:
        strength = "CRITICAL"

    suggestions = []
    if score < 80:
        if length < 16:
            suggestions.append("Increase length to 16+ characters")
        if not has_symbol:
            suggestions.append("Add special characters: !@#$%^&*")
        if char_types < 3:
            suggestions.append("Mix lowercase, uppercase, digits, and symbols")

    return {
        "score": score,
        "strength": strength,
        "entropy": round(entropy, 2),
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "issues": issues,
        "suggestions": suggestions,
    }


def generate_password(length: int = 16, use_symbols: bool = True, use_digits: bool = True,
                       exclude_ambiguous: bool = False) -> str:
    chars = string.ascii_lowercase + string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if exclude_ambiguous:
        for ch in "0O1lI|":
            chars = chars.replace(ch, "")

    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(length))
        result = analyze_password(pwd)
        if result["score"] >= 60:
            return pwd
