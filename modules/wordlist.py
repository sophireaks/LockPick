import itertools
import string
from typing import Generator


LEET_MAP = {
    "a": ["a", "4", "@"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "$", "5"],
    "t": ["t", "7"],
    "g": ["g", "9"],
    "b": ["b", "8"],
}

COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345",
    "!", "!!", "123!", "1!", "@",
    "2024", "2025", "2026",
    "#1", "99", "00", "01", "007",
]

COMMON_PREFIXES = ["", "1", "the", "my", "its"]


def _leet_variations(word: str) -> set[str]:
    chars: list[list[str]] = []
    for ch in word.lower():
        chars.append(LEET_MAP.get(ch, [ch]))
    results: set[str] = set()
    for combo in itertools.product(*chars):
        results.add("".join(combo))
    return results


def generate_targeted(
    keywords: list[str],
    include_leet: bool = True,
    include_suffixes: bool = True,
    include_prefixes: bool = False,
    capitalize: bool = True,
    min_length: int = 4,
    max_length: int = 32,
) -> Generator[str, None, None]:
    """
    Generate a targeted wordlist from keywords (name, birthday, pet, company...).
    Yields unique passwords one at a time.
    """
    seen: set[str] = set()

    def emit(w: str):
        if min_length <= len(w) <= max_length and w not in seen:
            seen.add(w)
            yield w

    base_words: set[str] = set()

    for kw in keywords:
        kw = kw.strip()
        if not kw:
            continue
        base_words.add(kw.lower())
        base_words.add(kw.upper())
        if capitalize:
            base_words.add(kw.capitalize())

    # Combinations of 2 keywords
    kw_list = list({k.lower() for k in keywords if k.strip()})
    for a, b in itertools.permutations(kw_list, 2):
        base_words.add(a + b)
        base_words.add(a.capitalize() + b)
        base_words.add(a.capitalize() + b.capitalize())
        base_words.add(a + "_" + b)
        base_words.add(a + "." + b)

    expanded: set[str] = set(base_words)

    if include_leet:
        for w in list(base_words):
            expanded.update(_leet_variations(w))

    prefixes = COMMON_PREFIXES if include_prefixes else [""]
    suffixes = COMMON_SUFFIXES if include_suffixes else [""]

    for w in expanded:
        for pre in prefixes:
            for suf in suffixes:
                candidate = pre + w + suf
                yield from emit(candidate)


def generate_bruteforce(
    charset: str = "lowercase",
    min_len: int = 1,
    max_len: int = 4,
) -> Generator[str, None, None]:
    """
    Generate all combinations for a given charset and length range.
    WARNING: grows very fast — max_len > 6 with full charset = millions of words.
    """
    charsets = {
        "lowercase": string.ascii_lowercase,
        "uppercase": string.ascii_uppercase,
        "digits":    string.digits,
        "alpha":     string.ascii_letters,
        "alnum":     string.ascii_letters + string.digits,
        "full":      string.ascii_letters + string.digits + "!@#$%^&*",
    }

    chars = charsets.get(charset.lower(), charset)

    for length in range(min_len, max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            yield "".join(combo)


def estimate_bruteforce_count(charset: str, min_len: int, max_len: int) -> int:
    charsets = {
        "lowercase": 26,
        "uppercase": 26,
        "digits":    10,
        "alpha":     52,
        "alnum":     62,
        "full":      70,
    }
    size  = charsets.get(charset.lower(), len(charset))
    total = 0
    for length in range(min_len, max_len + 1):
        total += size ** length
    return total


def save_wordlist(words: Generator[str, None, None], output_path: str) -> int:
    count = 0
    with open(output_path, "w", encoding="utf-8") as fh:
        for word in words:
            fh.write(word + "\n")
            count += 1
    return count
