"""
Utility tools for the password cracker, such as folder watching
and batch processing helpers.

These functions are thin wrappers around the application layer
(`cracker.app`) and are intentionally free of any CLI or HTTP
knowledge.
"""

from __future__ import annotations

import datetime
import os
import time
from typing import Optional, Sequence

from rich.console import Console

from .app import (
    CrackJobConfig,
    load_hashes_from_file,
    run_crack_job,
    write_results,
)
from .core import DEFAULT_MASKS, DEFAULT_RULESET
from .security import CrackerError


console = Console()


def watch_folder(
    folder: str = "incoming_hashes",
    *,
    wordlist: str = "wordlist/rockyou.txt",
    max_bruteforce_length: int = 5,
    use_multiprocessing: bool = True,
    poll_interval: float = 5.0,
    output_root: str = "results_watch",
    max_wordlist_lines: Optional[int] = None,
    enable_rules: bool = True,
    enable_mask: bool = False,
    mask_patterns: Optional[Sequence[str]] = None,
    max_mask_candidates: Optional[int] = None,
    ruleset: Sequence[str] = DEFAULT_RULESET,
    max_rule_candidates: Optional[int] = None,
    max_rule_variants_per_word: Optional[int] = None,
    attack_order: Optional[Sequence[str]] = None,
    allow_external_wordlist: bool = False,
    allow_external_hash_file: bool = False,
) -> None:
    """
    Watch a folder for new `.txt` files and automatically crack hashes
    found inside them.

    Each discovered file is processed once; results are written to a
    timestamped subfolder inside `output_root`.
    """
    os.makedirs(folder, exist_ok=True)
    os.makedirs(output_root, exist_ok=True)

    if enable_mask and not mask_patterns:
        mask_patterns = list(DEFAULT_MASKS)

    console.print(f"[blue]👀 Watching folder:[/] {folder}")

    seen: set[str] = set()

    while True:
        for fname in os.listdir(folder):
            if not fname.lower().endswith(".txt"):
                continue

            fpath = os.path.join(folder, fname)
            if fpath in seen:
                continue

            seen.add(fpath)
            console.print(f"[cyan]→ Auto-cracking:[/] {fname}")

            try:
                hashes = load_hashes_from_file(
                    fpath,
                    allow_external=allow_external_hash_file,
                    base_dir=folder,
                )
            except CrackerError as exc:
                console.print(f"[red]❌ Failed to read hashes:[/] {exc}")
                continue

            if not hashes:
                console.print(f"[yellow]⚠️ No hashes found in:[/] {fname}")
                continue

            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            job_name = os.path.splitext(fname)[0]
            output_dir = os.path.join(output_root, f"{timestamp}_{job_name}")

            cfg = CrackJobConfig(
                hashes=hashes,
                wordlist_path=wordlist,
                max_bruteforce_length=max_bruteforce_length,
                use_multiprocessing=use_multiprocessing,
                max_wordlist_lines=max_wordlist_lines,
                output_dir=output_dir,
                attack_order=attack_order or [
                    "dictionary",
                    "rules",
                    "mask",
                    "bruteforce",
                ],
                enable_rules=enable_rules,
                enable_mask=enable_mask,
                mask_patterns=mask_patterns,
                max_mask_candidates=max_mask_candidates,
                ruleset=ruleset,
                max_rule_candidates=max_rule_candidates,
                max_rule_variants_per_word=max_rule_variants_per_word or 48,
                allow_external_wordlist=allow_external_wordlist,
                allow_external_hash_file=allow_external_hash_file,
            )

            try:
                result = run_crack_job(cfg)
            except CrackerError as exc:
                console.print(f"[red]❌ Failed to crack hashes:[/] {exc}")
                continue

            write_results(output_dir, result)

            console.print(
                f"[green][✓] Finished job for {fname}; results saved to '{output_dir}'.[/]"
            )

        time.sleep(poll_interval)