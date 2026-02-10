"""
Core cryptographic and attack primitives for the password cracker.

This module deliberately avoids any CLI- or HTTP-specific behavior.
It focuses on:
- hash type detection
- hashing / verification for supported algorithms
- dictionary, rule-based, mask, and brute-force attack engines
"""

from __future__ import annotations

import hashlib
import itertools
import logging

import string
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

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

COMMON_PASSWORDS = [
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "letmein",
    "admin",
    "welcome",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "master",
    "shadow",
    "trustno1",
    "superman",
    "secret",
    "passw0rd",
    "princess",
]

DEFAULT_RULESET: Sequence[str] = (
    "lower",
    "upper",
    "capitalize",
    "swapcase",
    "reverse",
    "leet",
    "append_digits",
    "prepend_digits",
    "append_symbols",
)

DEFAULT_MASKS: Sequence[str] = (
    "?l?l?l?l?d?d",
    "?l?l?l?d?d",
    "?u?l?l?l?d",
    "?l?l?l?l",
)

MASK_TOKENS = {
    "?l": string.ascii_lowercase,
    "?u": string.ascii_uppercase,
    "?d": string.digits,
    "?s": "!@#$%^&*()_-+=[]{}|:;,.?/",
    "?a": string.ascii_letters + string.digits,
}

LEET_TABLE = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})


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


def _verify_worker(args: tuple[str, str, str]) -> Optional[str]:
    candidate, algo, target = args
    if hash_password(candidate, algo, target):
        return candidate
    return None


def _materialize_candidates(
    candidates: Iterable[str], max_candidates: Optional[int]
) -> tuple[list[str], Optional[int]]:
    if isinstance(candidates, list):
        base = candidates
    else:
        base = list(candidates)

    if max_candidates is not None:
        base = base[:max_candidates]
        total = max_candidates
    else:
        total = len(base)

    normalized = [str(item).strip() for item in base if str(item).strip()]
    return normalized, total


@dataclass
class DictionaryAttackConfig:
    hash_to_crack: str
    algo: str
    candidates: Iterable[str]
    max_candidates: Optional[int] = None
    use_multiprocessing: bool = True
    chunk_size: int = 512


def run_dictionary_attack(config: DictionaryAttackConfig) -> Optional[str]:
    """
    Run a dictionary attack over an iterable of candidate passwords.

    This is the core engine; higher layers are responsible for loading
    wordlists from disk and providing an iterator of candidates.
    """
    hash_to_crack = config.hash_to_crack
    algo = config.algo

    candidate_list, total = _materialize_candidates(
        config.candidates, config.max_candidates
    )
    if not candidate_list:
        return None

    if config.use_multiprocessing:
        from multiprocessing import Pool, cpu_count

        with Pool(cpu_count()) as pool:
            for result in tqdm(
                pool.imap_unordered(
                    _verify_worker,
                    ((c, algo, hash_to_crack) for c in candidate_list),
                    chunksize=config.chunk_size,
                ),
                total=total,
                desc=f"[Dict:{algo}]",
            ):
                if result:
                    pool.terminate()
                    return result
    else:
        for word in tqdm(candidate_list, total=total, desc=f"[Dict:{algo}]"):
            if hash_password(word, algo, hash_to_crack):
                return word

    return None


def _generate_rule_variants(
    word: str,
    ruleset: Sequence[str],
    max_variants_per_word: int,
) -> list[str]:
    variants: list[str] = []
    seen: set[str] = set()
    base_variants: list[str] = []

    def push(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            variants.append(value)

    def push_base(value: str) -> None:
        if value and value not in base_variants:
            base_variants.append(value)
            push(value)

    base = word
    push_base(base)

    if "lower" in ruleset:
        push_base(base.lower())
    if "upper" in ruleset:
        push_base(base.upper())
    if "capitalize" in ruleset:
        push_base(base.capitalize())
    if "swapcase" in ruleset:
        push_base(base.swapcase())
    if "reverse" in ruleset:
        push_base(base[::-1])
    if "leet" in ruleset:
        push_base(base.translate(LEET_TABLE))
        push_base(base.lower().translate(LEET_TABLE))

    if any(rule in ruleset for rule in ("append_digits", "prepend_digits", "append_symbols")):
        affix_bases = list(base_variants)
        for root in affix_bases:
            if "append_digits" in ruleset:
                for i in range(0, 100):
                    push(f"{root}{i}")
                    if len(variants) >= max_variants_per_word:
                        return variants[:max_variants_per_word]
            if "prepend_digits" in ruleset:
                for i in range(0, 100):
                    push(f"{i}{root}")
                    if len(variants) >= max_variants_per_word:
                        return variants[:max_variants_per_word]
            if "append_symbols" in ruleset:
                for symbol in ("!", "@", "#", "$"):
                    push(f"{root}{symbol}")
                    if len(variants) >= max_variants_per_word:
                        return variants[:max_variants_per_word]

    return variants[:max_variants_per_word]


@dataclass
class RuleAttackConfig:
    hash_to_crack: str
    algo: str
    base_words: Iterable[str]
    ruleset: Sequence[str] = DEFAULT_RULESET
    max_candidates: Optional[int] = None
    max_variants_per_word: int = 48
    use_multiprocessing: bool = True
    chunk_size: int = 256


def _iter_rule_candidates(config: RuleAttackConfig) -> Iterable[str]:
    produced = 0
    for word in config.base_words:
        base = str(word).strip()
        if not base:
            continue
        variants = _generate_rule_variants(
            base, config.ruleset, config.max_variants_per_word
        )
        for variant in variants:
            yield variant
            produced += 1
            if config.max_candidates is not None and produced >= config.max_candidates:
                return


def run_rule_attack(config: RuleAttackConfig) -> Optional[str]:
    total = config.max_candidates
    iterable = _iter_rule_candidates(config)

    if config.use_multiprocessing:
        from multiprocessing import Pool, cpu_count

        with Pool(cpu_count()) as pool:
            for result in tqdm(
                pool.imap_unordered(
                    _verify_worker,
                    ((c, config.algo, config.hash_to_crack) for c in iterable),
                    chunksize=config.chunk_size,
                ),
                total=total,
                desc=f"[Rules:{config.algo}]",
            ):
                if result:
                    pool.terminate()
                    return result
    else:
        for candidate in tqdm(iterable, total=total, desc=f"[Rules:{config.algo}]"):
            if hash_password(candidate, config.algo, config.hash_to_crack):
                return candidate

    return None


@dataclass
class MaskAttackConfig:
    hash_to_crack: str
    algo: str
    masks: Sequence[str]
    max_candidates: Optional[int] = 200_000
    use_multiprocessing: bool = True
    chunk_size: int = 512


def _mask_to_charsets(mask: str) -> list[str]:
    charsets: list[str] = []
    idx = 0
    while idx < len(mask):
        if mask[idx] == "?" and idx + 1 < len(mask):
            token = f"?{mask[idx + 1]}"
            if token in MASK_TOKENS:
                charsets.append(MASK_TOKENS[token])
                idx += 2
                continue
        charsets.append(mask[idx])
        idx += 1
    return charsets


def _estimate_mask_space(charsets: list[str]) -> int:
    total = 1
    for charset in charsets:
        total *= len(charset)
        if total > 1_000_000_000:
            return total
    return total


def _iter_mask_candidates(
    masks: Sequence[str],
    max_candidates: Optional[int],
) -> Iterable[str]:
    produced = 0
    for mask in masks:
        charsets = _mask_to_charsets(mask)
        if not charsets:
            continue
        for combo in itertools.product(*charsets):
            yield "".join(combo)
            produced += 1
            if max_candidates is not None and produced >= max_candidates:
                return


def run_mask_attack(config: MaskAttackConfig) -> Optional[str]:
    if not config.masks:
        return None

    total = config.max_candidates
    if total is None:
        total = 0
        for mask in config.masks:
            total += _estimate_mask_space(_mask_to_charsets(mask))
        if total <= 0 or total > 5_000_000_000:
            total = None

    iterable = _iter_mask_candidates(config.masks, config.max_candidates)

    if config.use_multiprocessing:
        from multiprocessing import Pool, cpu_count

        with Pool(cpu_count()) as pool:
            for result in tqdm(
                pool.imap_unordered(
                    _verify_worker,
                    ((c, config.algo, config.hash_to_crack) for c in iterable),
                    chunksize=config.chunk_size,
                ),
                total=total,
                desc=f"[Mask:{config.algo}]",
            ):
                if result:
                    pool.terminate()
                    return result
    else:
        for candidate in tqdm(iterable, total=total, desc=f"[Mask:{config.algo}]"):
            if hash_password(candidate, config.algo, config.hash_to_crack):
                return candidate

    return None


@dataclass
class BruteForceConfig:
    hash_to_crack: str
    algo: str
    max_length: int = 5
    charset: str = string.ascii_letters + string.digits + string.punctuation
    use_multiprocessing: bool = True
    chunk_size: int = 512


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
                    pool.imap_unordered(
                        _brute_worker, task_args, chunksize=config.chunk_size
                    ),
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