"""
Application/service layer for the password cracker.

This module orchestrates:
- reading hashes from files
- loading wordlists from disk
- running dictionary/rule/mask/brute-force attacks from `cracker.core`
- writing results / reporting via a structured result object
"""

from __future__ import annotations

import itertools
import os
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from rich.console import Console

from .core import (
    BruteForceConfig,
    COMMON_PASSWORDS,
    DEFAULT_MASKS,
    DEFAULT_RULESET,
    DictionaryAttackConfig,
    MaskAttackConfig,
    RuleAttackConfig,
    SUPPORTED_ALGOS,
    detect_hash_algo,
    run_bruteforce_attack,
    run_dictionary_attack,
    run_mask_attack,
    run_rule_attack,
)
from .security import InvalidConfigError, resolve_hash_file_path, resolve_wordlist_path


console = Console()

ATTACK_STAGES = ("dictionary", "rules", "mask", "bruteforce")


def _normalize_attack_order(order: Optional[Sequence[str]]) -> List[str]:
    if not order:
        return ["dictionary", "rules", "mask", "bruteforce"]
    normalized: List[str] = []
    for item in order:
        stage = str(item).strip().lower()
        if not stage:
            continue
        if stage not in ATTACK_STAGES:
            raise InvalidConfigError(
                f"Unknown attack stage '{stage}'. Valid stages: {', '.join(ATTACK_STAGES)}"
            )
        if stage not in normalized:
            normalized.append(stage)
    return normalized


@dataclass
class CrackJobConfig:
    hashes: Sequence[str]
    wordlist_path: str
    max_bruteforce_length: int = 5
    use_multiprocessing: bool = True
    max_wordlist_lines: Optional[int] = None
    output_dir: str = "results"
    attack_order: Sequence[str] = field(
        default_factory=lambda: ["dictionary", "rules", "mask", "bruteforce"]
    )
    enable_rules: bool = True
    enable_mask: bool = False
    mask_patterns: Optional[Sequence[str]] = None
    max_mask_candidates: Optional[int] = 200_000
    ruleset: Sequence[str] = DEFAULT_RULESET
    max_rule_candidates: Optional[int] = 50_000
    max_rule_variants_per_word: int = 48
    algo_override: Optional[str] = None
    allow_external_wordlist: bool = False
    allow_external_hash_file: bool = False
    common_passwords: Optional[Sequence[str]] = None


@dataclass
class CrackJobResult:
    cracked: List[Tuple[str, str]] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)


def _load_wordlist(path: str, max_lines: Optional[int] = None) -> List[str]:
    with open(path, "r", encoding="latin-1", errors="ignore") as f:
        iterator = f
        if max_lines is not None:
            iterator = itertools.islice(iterator, max_lines)
        return [line.strip() for line in iterator if line.strip()]


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


def load_hashes_from_file(
    path: str,
    *,
    allow_external: bool = False,
    base_dir: Optional[str] = None,
) -> List[str]:
    resolved = resolve_hash_file_path(
        path,
        base_dir=base_dir,
        allow_outside=allow_external,
    )
    with open(resolved.path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def _validate_config(config: CrackJobConfig) -> None:
    if config.max_bruteforce_length < 1:
        raise InvalidConfigError("max_bruteforce_length must be >= 1")
    if config.max_rule_variants_per_word < 1:
        raise InvalidConfigError("max_rule_variants_per_word must be >= 1")
    if config.max_mask_candidates is not None and config.max_mask_candidates < 1:
        raise InvalidConfigError("max_mask_candidates must be >= 1")
    if config.max_rule_candidates is not None and config.max_rule_candidates < 1:
        raise InvalidConfigError("max_rule_candidates must be >= 1")
    if config.algo_override:
        algo = config.algo_override.lower()
        if algo not in SUPPORTED_ALGOS:
            raise InvalidConfigError(
                f"Unknown algo '{config.algo_override}'. Supported: {', '.join(SUPPORTED_ALGOS)}"
            )


def run_crack_job(config: CrackJobConfig) -> CrackJobResult:
    """
    High-level helper that runs dictionary + brute-force for each hash.

    This mirrors the behavior of `crack_hashes_from_file` and `crack_single_hash`
    but returns a structured `CrackJobResult` instead of dealing with printing
    and file writing directly.
    """
    _validate_config(config)
    results = CrackJobResult()

    attack_order = _normalize_attack_order(config.attack_order)
    if not config.enable_rules and "rules" in attack_order:
        attack_order = [stage for stage in attack_order if stage != "rules"]
    if not config.enable_mask and "mask" in attack_order:
        attack_order = [stage for stage in attack_order if stage != "mask"]

    wordlist_resolution = resolve_wordlist_path(
        config.wordlist_path,
        allow_outside=config.allow_external_wordlist,
    )

    # Load wordlist once for efficiency.
    words = _load_wordlist(wordlist_resolution.path, config.max_wordlist_lines)
    common_candidates = list(config.common_passwords or COMMON_PASSWORDS)

    mask_patterns = config.mask_patterns
    if config.enable_mask and not mask_patterns:
        mask_patterns = DEFAULT_MASKS

    for h in config.hashes:
        algo = config.algo_override.lower() if config.algo_override else detect_hash_algo(h)
        if not algo:
            results.failed.append(h)
            continue

        pwd = None
        for stage in attack_order:
            if stage == "dictionary":
                if common_candidates:
                    pwd = run_dictionary_attack(
                        DictionaryAttackConfig(
                            hash_to_crack=h,
                            algo=algo,
                            candidates=common_candidates,
                            max_candidates=None,
                            use_multiprocessing=False,
                        )
                    )
                if not pwd:
                    pwd = run_dictionary_attack(
                        DictionaryAttackConfig(
                            hash_to_crack=h,
                            algo=algo,
                            candidates=words,
                            max_candidates=None,
                            use_multiprocessing=config.use_multiprocessing,
                        )
                    )
            elif stage == "rules" and config.enable_rules:
                pwd = run_rule_attack(
                    RuleAttackConfig(
                        hash_to_crack=h,
                        algo=algo,
                        base_words=words,
                        ruleset=config.ruleset,
                        max_candidates=config.max_rule_candidates,
                        max_variants_per_word=config.max_rule_variants_per_word,
                        use_multiprocessing=config.use_multiprocessing,
                    )
                )
            elif stage == "mask" and config.enable_mask and mask_patterns:
                pwd = run_mask_attack(
                    MaskAttackConfig(
                        hash_to_crack=h,
                        algo=algo,
                        masks=mask_patterns,
                        max_candidates=config.max_mask_candidates,
                        use_multiprocessing=config.use_multiprocessing,
                    )
                )
            elif stage == "bruteforce":
                pwd = run_bruteforce_attack(
                    BruteForceConfig(
                        hash_to_crack=h,
                        algo=algo,
                        max_length=config.max_bruteforce_length,
                        use_multiprocessing=config.use_multiprocessing,
                    )
                )

            if pwd:
                break

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

