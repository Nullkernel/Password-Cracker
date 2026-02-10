"""
High-level public API for the password cracker package.

This module re-exports the main building blocks from the internal
submodules so callers can do `import cracker` and access the
core functionality without needing to know the internal layout.
"""

from .core import (
    COMMON_PASSWORDS,
    DEFAULT_MASKS,
    DEFAULT_RULESET,
    HASH_PATTERNS,
    MaskAttackConfig,
    RuleAttackConfig,
    SUPPORTED_ALGOS,
    detect_hash_algo,
    hash_for_testing,
    run_mask_attack,
    run_rule_attack,
)
from .app import (
    CrackJobConfig,
    CrackJobResult,
    run_crack_job,
    load_hashes_from_file,
    list_wordlists,
    write_results,
)
from .security import CrackerError, InvalidConfigError, InvalidPathError

__all__ = [
    # Core capabilities exposed at the package level.
    "SUPPORTED_ALGOS",
    "HASH_PATTERNS",
    "COMMON_PASSWORDS",
    "DEFAULT_RULESET",
    "DEFAULT_MASKS",
    "detect_hash_algo",
    "hash_for_testing",
    "RuleAttackConfig",
    "MaskAttackConfig",
    "run_rule_attack",
    "run_mask_attack",
    # High-level application API.
    "CrackJobConfig",
    "CrackJobResult",
    "run_crack_job",
    "load_hashes_from_file",
    "list_wordlists",
    "write_results",
    # Errors.
    "CrackerError",
    "InvalidConfigError",
    "InvalidPathError",
]

