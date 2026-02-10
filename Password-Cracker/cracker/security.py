"""
Security and validation helpers for the password cracker.

These utilities enforce safe defaults for file access and prevent
unexpected path traversal or oversized input files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable, Optional


class CrackerError(Exception):
    """Base exception for recoverable input/config issues."""


class InvalidPathError(CrackerError):
    """Raised when a path violates safety rules or does not exist."""


class InvalidConfigError(CrackerError):
    """Raised when configuration values are invalid."""


@dataclass(frozen=True)
class PathResolution:
    path: str
    base_dir: str


DEFAULT_MAX_FILE_MB = 50
WORDLIST_DIRNAME = "wordlist"
DEFAULT_WORDLIST = os.path.join(WORDLIST_DIRNAME, "rockyou.txt")


def _normalize_base_dir(base_dir: Optional[str]) -> str:
    return os.path.abspath(base_dir or os.getcwd())


def resolve_safe_path(
    path: str,
    *,
    base_dir: Optional[str] = None,
    allow_outside: bool = False,
    must_exist: bool = True,
    allowed_extensions: Optional[Iterable[str]] = None,
    max_size_mb: Optional[int] = DEFAULT_MAX_FILE_MB,
) -> PathResolution:
    if not path:
        raise InvalidPathError("Path is required")

    base_dir_abs = _normalize_base_dir(base_dir)
    raw_path = os.path.expanduser(path)
    if not os.path.isabs(raw_path):
        raw_path = os.path.join(base_dir_abs, raw_path)
    resolved = os.path.abspath(raw_path)

    if not allow_outside:
        common = os.path.commonpath([resolved, base_dir_abs])
        if common != base_dir_abs:
            raise InvalidPathError(
                f"Path must be within '{base_dir_abs}'. Provide --allow-external to override."
            )

    if allowed_extensions:
        normalized = [ext.lower() for ext in allowed_extensions]
        if not resolved.lower().endswith(tuple(normalized)):
            raise InvalidPathError(
                f"Path must end with one of: {', '.join(normalized)}"
            )

    if must_exist and not os.path.exists(resolved):
        raise InvalidPathError(f"File not found: {resolved}")

    if must_exist and max_size_mb is not None:
        size_mb = os.path.getsize(resolved) / (1024 * 1024)
        if size_mb > max_size_mb:
            raise InvalidPathError(
                f"File too large ({size_mb:.1f} MB). Max allowed: {max_size_mb} MB."
            )

    return PathResolution(path=resolved, base_dir=base_dir_abs)


def resolve_wordlist_path(
    path: str,
    *,
    allow_outside: bool = False,
    base_dir: Optional[str] = None,
    max_size_mb: Optional[int] = DEFAULT_MAX_FILE_MB,
) -> PathResolution:
    base_dir_abs = _normalize_base_dir(base_dir)
    wordlist_root = os.path.abspath(os.path.join(base_dir_abs, WORDLIST_DIRNAME))
    resolution = resolve_safe_path(
        path or DEFAULT_WORDLIST,
        base_dir=base_dir_abs,
        allow_outside=allow_outside,
        allowed_extensions=(".txt", ".lst"),
        max_size_mb=max_size_mb,
    )

    if not allow_outside:
        common = os.path.commonpath([resolution.path, wordlist_root])
        if common != wordlist_root:
            raise InvalidPathError(
                f"Wordlist must be inside '{wordlist_root}'. Provide --allow-external-wordlist to override."
            )

    return resolution


def resolve_hash_file_path(
    path: str,
    *,
    allow_outside: bool = False,
    base_dir: Optional[str] = None,
    max_size_mb: Optional[int] = DEFAULT_MAX_FILE_MB,
) -> PathResolution:
    return resolve_safe_path(
        path,
        base_dir=base_dir,
        allow_outside=allow_outside,
        allowed_extensions=(".txt", ".lst"),
        max_size_mb=max_size_mb,
    )
