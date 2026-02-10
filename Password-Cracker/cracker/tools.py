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
from typing import Optional

from rich.console import Console

from .app import (
    CrackJobConfig,
    load_hashes_from_file,
    run_crack_job,
    write_results,
)


console = Console()


def watch_folder(
    folder: str = "incoming_hashes",
    *,
    wordlist: str = "wordlist/rockyou.txt",
    max_bruteforce_length: int = 5,
    use_multiprocessing: bool = True,
    poll_interval: float = 5.0,
    output_root: str = "results_watch",
) -> None:
    """
    Watch a folder for new `.txt` files and automatically crack hashes
    found inside them.

    Each discovered file is processed once; results are written to a
    timestamped subfolder inside `output_root`.
    """
    os.makedirs(folder, exist_ok=True)
    os.makedirs(output_root, exist_ok=True)

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
                hashes = load_hashes_from_file(fpath)
            except Exception:
                console.print(f"[red]❌ Failed to read hashes from:[/] {fpath}")
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
                output_dir=output_dir,
            )

            result = run_crack_job(cfg)
            write_results(output_dir, result)

            console.print(
                f"[green][✓] Finished job for {fname}; results saved to '{output_dir}'.[/]"
            )

        time.sleep(poll_interval)

