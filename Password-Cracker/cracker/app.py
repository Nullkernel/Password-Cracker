"""
Application/service layer for the password cracker.

This module orchestrates:
- reading hashes from files
- loading wordlists from disk
- running dictionary + brute-force attacks from `cracker.core`
- writing results / reporting via a structured result object
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from rich.console import Console

from .core import (
    BruteForceConfig,
    DictionaryAttackConfig,
    detect_hash_algo,
    run_bruteforce_attack,
    run_dictionary_attack,
)


console = Console()


@dataclass
class CrackJobConfig:
    hashes: Sequence[str]
    wordlist_path: str
    max_bruteforce_length: int = 5
    use_multiprocessing: bool = True
    max_wordlist_lines: Optional[int] = None
    output_dir: str = "results"


@dataclass
class CrackJobResult:
    cracked: List[Tuple[str, str]] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)


def _load_wordlist(path: str) -> List[str]:
    with open(path, "r", encoding="latin-1", errors="ignore") as f:
        return f.readlines()


def list_wordlists(base_dir: Optional[str] = None) -> List[str]:
    """
    Discover available wordlists, mirroring the behavior from the original script.
    """
    if base_dir is None:
        base_dir = os.path.join(os.getcwd(), "wordlist")
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    return [
        os.path.join("wordlist", f)
        for f in os.listdir(base_dir)
        if f.endswith((".txt", ".lst"))
    ]


def load_hashes_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def run_crack_job(config: CrackJobConfig) -> CrackJobResult:
    """
    High-level helper that runs dictionary + brute-force for each hash.

    This mirrors the behavior of `crack_hashes_from_file` and `crack_single_hash`
    but returns a structured `CrackJobResult` instead of dealing with printing
    and file writing directly.
    """
    results = CrackJobResult()

    # Load wordlist once for efficiency.
    words = _load_wordlist(config.wordlist_path)

    for h in config.hashes:
        algo = detect_hash_algo(h)
        if not algo:
            results.failed.append(h)
            continue

        dict_cfg = DictionaryAttackConfig(
            hash_to_crack=h,
            algo=algo,
            candidates=words,
            max_candidates=config.max_wordlist_lines,
        )
        pwd = run_dictionary_attack(dict_cfg)

        if not pwd:
            brute_cfg = BruteForceConfig(
                hash_to_crack=h,
                algo=algo,
                max_length=config.max_bruteforce_length,
                use_multiprocessing=config.use_multiprocessing,
            )
            pwd = run_bruteforce_attack(brute_cfg)

        if pwd:
            results.cracked.append((h, pwd))
        else:
            results.failed.append(h)

    return results


def write_results(output_dir: str, result: CrackJobResult) -> None:
    """
    Persist cracked and failed hashes to disk in a simple, predictable layout.

    This keeps filesystem concerns in the application layer so that the CLI,
    HTTP API, and tools can share the same behavior.
    """
    os.makedirs(output_dir, exist_ok=True)

    cracked_path = os.path.join(output_dir, "cracked_results.txt")
    failed_path = os.path.join(output_dir, "failed_attempts.txt")

    if result.cracked:
        with open(cracked_path, "w", encoding="utf-8") as f:
            for h, pwd in result.cracked:
                f.write(f"{h} -> {pwd}\n")

    if result.failed:
        with open(failed_path, "w", encoding="utf-8") as f:
            for h in result.failed:
                f.write(f"{h}\n")


