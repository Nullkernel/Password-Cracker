"""
CLI interface layer for the password cracker.

This module is responsible for:
- parsing command-line arguments
- interactive prompts (single hash vs file, wordlist selection, etc.)
- wiring user inputs into `cracker.app.run_crack_job`
- writing human-friendly summaries and result files

All cracking logic lives in `cracker.core` / `cracker.app`.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
from typing import Optional, Sequence

from rich.console import Console

from .app import (
    CrackJobConfig,
    CrackJobResult,
    list_wordlists,
    load_hashes_from_file,
    run_crack_job,
    write_results,
)


console = Console()

RESUME_FILENAME = "cracker_resume.json"


def _setup_output_dir(custom: Optional[str] = None) -> str:
    if custom:
        output_dir = custom
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"results_{timestamp}"

    os.makedirs(output_dir, exist_ok=True)

    logging.basicConfig(
        filename=os.path.join(output_dir, "debug.log"),
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s: %(message)s",
    )

    console.print(
        f"[bold green]Log:[/] Writing debug logs to [italic]{output_dir}/debug.log"
    )

    return output_dir


def _resume_path(output_dir: str) -> str:
    return os.path.join(output_dir, RESUME_FILENAME)


def _load_resume(output_dir: str) -> Optional[dict]:
    path = _resume_path(output_dir)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            logging.exception("Failed to load resume file")
    return None


def _save_resume(output_dir: str, config: CrackJobConfig) -> None:
    """
    Persist enough information to re-run a previous job.
    """
    path = _resume_path(output_dir)
    try:
        payload = {
            "hashes": list(config.hashes),
            "wordlist_path": config.wordlist_path,
            "max_bruteforce_length": config.max_bruteforce_length,
            "use_multiprocessing": config.use_multiprocessing,
            "max_wordlist_lines": config.max_wordlist_lines,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
    except Exception:
        logging.exception("Failed to save resume file")


def _remove_resume(output_dir: str) -> None:
    path = _resume_path(output_dir)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        logging.exception("Failed to remove resume file")


def _interactive_choose_hashes() -> Sequence[str]:
    mode = input("Input a [s]ingle hash or [f]ile of hashes? ").strip().lower()

    if mode == "s":
        h = input("Enter hash: ").strip()
        return [h] if h else []

    if mode == "f":
        filepath = input("Enter path to hash file: ").strip()
        if not filepath:
            return []
        try:
            return load_hashes_from_file(filepath)
        except Exception:
            console.print("[red]❌ Hash file not found or unreadable.[/]")
            logging.exception("Hash file issue")
            return []

    console.print("[yellow]⚠️ Unknown mode, expected 's' or 'f'.[/]")
    return []


def _interactive_choose_wordlist() -> str:
    wls = list_wordlists()
    console.print("[cyan]Detected wordlists:[/]")
    for wl in wls:
        console.print(f" - {wl}")
    return input("Enter path to wordlist (default: wordlist/rockyou.txt): ").strip() or "wordlist/rockyou.txt"


def _interactive_max_length() -> int:
    raw = input("Max brute-force length (default 5): ").strip() or "5"
    try:
        return int(raw)
    except ValueError:
        console.print("[yellow]⚠️ Invalid number, using 5.[/]")
        return 5


def _run_job_and_report(output_dir: str, config: CrackJobConfig) -> CrackJobResult:
    _save_resume(output_dir, config)
    result = run_crack_job(config)
    write_results(output_dir, result)

    console.print(
        f"\n[bold green][+] Cracked {len(result.cracked)} hash(es); "
        f"{len(result.failed)} failed. Results saved to '{output_dir}'.[/]"
    )

    # Successful completion; safe to clear resume file.
    _remove_resume(output_dir)
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Password Cracker CLI")
    parser.add_argument(
        "--no-mp",
        action="store_true",
        help="Disable multiprocessing (safe mode)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Custom output folder for results/logs",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        help="Max number of wordlist lines to check (optional)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch a folder for new hash files and auto-crack them",
    )
    parser.add_argument(
        "--watch-folder",
        type=str,
        default="incoming_hashes",
        help="Folder to watch when using --watch (default: incoming_hashes)",
    )

    args = parser.parse_args(argv)

    # Special case: folder watcher mode delegates to `cracker.tools`.
    if args.watch:
        from .tools import watch_folder

        console.print("[bold blue]=== Folder Watch Mode ===[/]")
        watch_folder(
            folder=args.watch_folder,
            wordlist="wordlist/rockyou.txt",
            max_bruteforce_length=5,
            use_multiprocessing=not args.no_mp,
        )
        return 0

    output_dir = _setup_output_dir(args.output_dir)

    console.print("[bold blue]=== Real-Time Terminal Hash Cracker ===[/]")

    # Resume support.
    resume_data = _load_resume(output_dir)
    if resume_data:
        resume = input("[!] Resume previous session? (y/n): ").strip().lower() == "y"
        if resume:
            hashes = resume_data.get("hashes") or []
            if not hashes:
                console.print("[yellow]⚠️ Resume file is empty or invalid; starting new job.[/]")
            else:
                cfg = CrackJobConfig(
                    hashes=hashes,
                    wordlist_path=resume_data.get("wordlist_path", "wordlist/rockyou.txt"),
                    max_bruteforce_length=int(resume_data.get("max_bruteforce_length", 5)),
                    use_multiprocessing=bool(resume_data.get("use_multiprocessing", True)),
                    max_wordlist_lines=resume_data.get("max_wordlist_lines"),
                    output_dir=output_dir,
                )
                _run_job_and_report(output_dir, cfg)
                return 0

    hashes = _interactive_choose_hashes()
    if not hashes:
        console.print("[red]❌ No hashes provided; exiting.[/]")
        return 1

    wordlist = _interactive_choose_wordlist()
    maxlen = _interactive_max_length()

    cfg = CrackJobConfig(
        hashes=hashes,
        wordlist_path=wordlist,
        max_bruteforce_length=maxlen,
        use_multiprocessing=not args.no_mp,
        max_wordlist_lines=args.max_lines,
        output_dir=output_dir,
    )

    _run_job_and_report(output_dir, cfg)
    return 0


if __name__ == "__main__":
    # Allow running `python -m cracker.cli` directly.
    from multiprocessing import freeze_support

    freeze_support()
    raise SystemExit(main())

