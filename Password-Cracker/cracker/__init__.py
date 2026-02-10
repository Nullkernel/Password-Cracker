"""
High-level public API for the password cracker package.

This module re-exports the main building blocks from the internal
submodules so callers can do `import cracker` and access the
core functionality without needing to know the internal layout.
"""

from .core import SUPPORTED_ALGOS, HASH_PATTERNS, detect_hash_algo, hash_for_testing
from .app import (
    CrackJobConfig,
    CrackJobResult,
    run_crack_job,
    load_hashes_from_file,
    list_wordlists,
    write_results,
)

__all__ = [
    # Core capabilities exposed at the package level.
    "SUPPORTED_ALGOS",
    "HASH_PATTERNS",
    "detect_hash_algo",
    "hash_for_testing",
    # High-level application API.
    "CrackJobConfig",
    "CrackJobResult",
    "run_crack_job",
    "load_hashes_from_file",
    "list_wordlists",
    "write_results",
]

