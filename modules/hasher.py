import hashlib
import hmac
import os
from typing import Optional


SUPPORTED_ALGORITHMS = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_256", "sha3_512", "blake2b", "blake2s",
]


def hash_text(text: str, algorithm: str = "sha256", encoding: str = "utf-8") -> str:
    algo = algorithm.lower().replace("-", "_")
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Choose from: {', '.join(SUPPORTED_ALGORITHMS)}")

    data = text.encode(encoding)

    if algo == "blake2b":
        return hashlib.blake2b(data).hexdigest()
    if algo == "blake2s":
        return hashlib.blake2s(data).hexdigest()

    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


def hash_file(file_path: str, algorithm: str = "sha256") -> dict:
    algo = algorithm.lower().replace("-", "_")
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    h = hashlib.new(algo) if algo not in ("blake2b", "blake2s") else (
        hashlib.blake2b() if algo == "blake2b" else hashlib.blake2s()
    )

    size = 0
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
            size += len(chunk)

    return {
        "file": file_path,
        "algorithm": algorithm,
        "hash": h.hexdigest(),
        "size_bytes": size,
    }


def verify_hash(text: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    actual = hash_text(text, algorithm)
    return hmac.compare_digest(actual.lower(), expected_hash.lower())


def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    result = hash_file(file_path, algorithm)
    return hmac.compare_digest(result["hash"].lower(), expected_hash.lower())


def hash_all_algorithms(text: str) -> dict:
    return {algo: hash_text(text, algo) for algo in SUPPORTED_ALGORITHMS}


def generate_hmac(text: str, key: str, algorithm: str = "sha256") -> str:
    algo = algorithm.lower().replace("-", "_").replace("_", "")
    if not hasattr(hashlib, algo):
        raise ValueError(f"HMAC unsupported algorithm: {algorithm}")
    return hmac.new(key.encode(), text.encode(), getattr(hashlib, algo)).hexdigest()
