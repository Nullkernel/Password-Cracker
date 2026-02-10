"""
Core cryptographic and attack primitives for the password cracker.

This module deliberately avoids any CLI- or HTTP-specific behavior.
It focuses on:
- hash type detection
- hashing / verification for supported algorithms
- dictionary and brute-force attack engines
"""

from __future__ import annotations

import hashlib
import itertools
import logging
import string
from dataclasses import dataclass
from typing import Iterable, Optional

import bcrypt
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from tqdm import tqdm


ph = PasswordHasher()


# Supported algorithms and regex patterns for hash detection.
SUPPORTED_ALGOS = [
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "sha3_256",
    "sha3_512",
    "bcrypt",
    "argon2",
]

HASH_PATTERNS = [
    (r"^\$2[aby]\$.{56}$", "bcrypt"),
    (r"^\$argon2.*\$.{20,}$", "argon2"),
    (r"^[a-fA-F0-9]{32}$", "md5"),
    (r"^[a-fA-F0-9]{40}$", "sha1"),
    (r"^[a-fA-F0-9]{64}$", "sha256"),
    (r"^[a-fA-F0-9]{128}$", "sha512"),
]


def hash_for_testing(password: str, algo: str = "md5") -> str:
    """
    Helper for quickly generating hashes in examples or tests.

    This mirrors the original development utility and is intentionally
    simple: it always generates a fresh salted hash for bcrypt/argon2.
    """
    algo = algo.lower()
    if algo == "bcrypt":
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    if algo == "argon2":
        return ph.hash(password)
    return getattr(hashlib, algo)(password.encode()).hexdigest()


def detect_hash_algo(hash_str: str) -> Optional[str]:
    """Best-effort hash type detection based on known patterns."""
    import re

    for pattern, algo in HASH_PATTERNS:
        if re.match(pattern, hash_str):
            return algo
    return None


def hash_password(password: str, algo: str, target_hash: str) -> bool:
    """
    Return True if `password` matches `target_hash` using the given algorithm.

    This mirrors the behavior from the original scripts but is side-effect free
    except for logging on unexpected errors.
    """
    algo = algo.lower()
    try:
        if algo == "bcrypt":
            return bcrypt.checkpw(password.encode(), target_hash.encode())
        if algo == "argon2":
            try:
                ph.verify(target_hash, password)
                return True
            except argon2_exceptions.VerifyMismatchError:
                return False
        return getattr(hashlib, algo)(password.encode()).hexdigest() == target_hash
    except Exception:
        logging.exception("Hashing error for algo=%s", algo)
        return False


@dataclass
class DictionaryAttackConfig:
    hash_to_crack: str
    algo: str
    candidates: Iterable[str]
    max_candidates: Optional[int] = None


def run_dictionary_attack(config: DictionaryAttackConfig) -> Optional[str]:
    """
    Run a dictionary attack over an iterable of candidate passwords.

    This is the core engine; higher layers are responsible for loading
    wordlists from disk and providing an iterator of candidates.
    """
    hash_to_crack = config.hash_to_crack
    algo = config.algo

    if config.max_candidates is not None:
        iterable = itertools.islice(config.candidates, config.max_candidates)
        total = config.max_candidates
    else:
        iterable = config.candidates
        total = None

    iterator = iterable

    if total is not None:
        iterator = tqdm(iterator, total=total, desc=f"[Dict:{algo}]")
    else:
        iterator = tqdm(iterator, desc=f"[Dict:{algo}]")

    for word in iterator:
        candidate = word.rstrip("\n")
        if hash_password(candidate, algo, hash_to_crack):
            return candidate
    return None


@dataclass
class BruteForceConfig:
    hash_to_crack: str
    algo: str
    max_length: int = 5
    charset: str = string.ascii_letters + string.digits + string.punctuation
    use_multiprocessing: bool = True


def _brute_worker(args: tuple[str, str, str]) -> Optional[str]:
    guess, algo, target = args
    if hash_password(guess, algo, target):
        return guess
    return None


def run_bruteforce_attack(config: BruteForceConfig) -> Optional[str]:
    """
    Run a brute-force attack according to the given configuration.

    This is a slightly generalized version of the original `brute_force_crack`.
    """
    from multiprocessing import Pool, cpu_count

    charset = config.charset
    algo = config.algo
    hash_to_crack = config.hash_to_crack

    for length in range(1, config.max_length + 1):
        combos = itertools.product(charset, repeat=length)
        task_args = (("".join(c), algo, hash_to_crack) for c in combos)

        if config.use_multiprocessing:
            with Pool(cpu_count()) as pool:
                for result in tqdm(
                    pool.imap_unordered(_brute_worker, task_args, chunksize=512),
                    desc=f"[Brute:{length}:{algo}]",
                ):
                    if result:
                        pool.terminate()
                        return result
        else:
            for args in tqdm(
                task_args, desc=f"[Brute:{length}:{algo}][NoMP]"
            ):
                result = _brute_worker(args)
                if result:
                    return result

    return None

