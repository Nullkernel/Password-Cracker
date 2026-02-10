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
from typing import List, Optional, Sequence

from rich.console import Console

from .app import (
    CrackJobConfig,
    CrackJobResult,
    list_wordlists,
    load_hashes_from_file,
    run_crack_job,
    write_results,
)
from .core import DEFAULT_MASKS, DEFAULT_RULESET, SUPPORTED_ALGOS
from .security import CrackerError


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
            "attack_order": list(config.attack_order),
            "enable_rules": config.enable_rules,
            "enable_mask": config.enable_mask,
            "mask_patterns": list(config.mask_patterns) if config.mask_patterns else None,
            "max_mask_candidates": config.max_mask_candidates,
            "ruleset": list(config.ruleset),
            "max_rule_candidates": config.max_rule_candidates,
            "max_rule_variants_per_word": config.max_rule_variants_per_word,
            "algo_override": config.algo_override,
            "allow_external_wordlist": config.allow_external_wordlist,
            "allow_external_hash_file": config.allow_external_hash_file,
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


def _interactive_choose_hashes(allow_external_hash_file: bool) -> Sequence[str]:
    mode = input("Input a [s]ingle hash or [f]ile of hashes? ").strip().lower()

    if mode == "s":
        h = input("Enter hash: ").strip()
        return [h] if h else []

    if mode == "f":
        filepath = input("Enter path to hash file: ").strip()
        if not filepath:
            return []
        try:
            return load_hashes_from_file(
                filepath, allow_external=allow_external_hash_file
            )
        except CrackerError as exc:
            console.print(f"[red]❌ {exc}[/]")
            logging.exception("Hash file issue")
            return []

    console.print("[yellow]⚠️ Unknown mode, expected 's' or 'f'.[/]")
    return []


def _interactive_choose_wordlist() -> str:
    wls = list_wordlists()
    console.print("[cyan]Detected wordlists:[/]")
    for wl in wls:
        console.print(f" - {wl}")
    return (
        input("Enter path to wordlist (default: wordlist/rockyou.txt): ").strip()
        or "wordlist/rockyou.txt"
    )


def _interactive_max_length() -> int:
    raw = input("Max brute-force length (default 5): ").strip() or "5"
    try:
        return int(raw)
    except ValueError:
        console.print("[yellow]⚠️ Invalid number, using 5.[/]")
        return 5


def _parse_attack_order(raw: Optional[str]) -> Optional[List[str]]:
    if not raw:
        return None
    return [part.strip() for part in raw.split(",") if part.strip()]


def _parse_ruleset(raw: Optional[str]) -> Sequence[str]:
    if not raw:
        return DEFAULT_RULESET
    rules = [part.strip() for part in raw.split(",") if part.strip()]
    return rules or DEFAULT_RULESET


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
        "--hash",
        type=str,
        help="Single hash to crack (non-interactive)",
    )
    parser.add_argument(
        "--hash-file",
        type=str,
        help="Path to a file containing hashes (non-interactive)",
    )
    parser.add_argument(
        "--wordlist",
        type=str,
        help="Wordlist path (default: wordlist/rockyou.txt)",
    )
    parser.add_argument(
        "--maxlen",
        type=int,
        help="Max brute-force length (default: 5)",
    )
    parser.add_argument(
        "--algo",
        type=str,
        choices=SUPPORTED_ALGOS,
        help="Override hash algorithm detection",
    )
    parser.add_argument(
        "--attack-order",
        type=str,
        help="Comma-separated attack stages (dictionary,rules,mask,bruteforce)",
    )
    parser.add_argument(
        "--ruleset",
        type=str,
        help="Comma-separated rule names (default: basic rules)",
    )
    parser.add_argument(
        "--no-rules",
        action="store_true",
        help="Disable rule-based attack stage",
    )
    parser.add_argument(
        "--enable-mask",
        action="store_true",
        help="Enable default mask patterns",
    )
    parser.add_argument(
        "--mask",
        action="append",
        help="Custom mask pattern (repeatable). Example: ?l?l?d?d",
    )
    parser.add_argument(
        "--max-mask-candidates",
        type=int,
        help="Max candidates generated by mask attack",
    )
    parser.add_argument(
        "--max-rule-candidates",
        type=int,
        help="Max candidates generated by rule attack",
    )
    parser.add_argument(
        "--max-rule-variants",
        type=int,
        help="Max variants per word in rule attack",
    )
    parser.add_argument(
        "--allow-external-wordlist",
        action="store_true",
        help="Allow wordlists outside the wordlist/ directory",
    )
    parser.add_argument(
        "--allow-external-hash-file",
        action="store_true",
        help="Allow hash files outside the working directory",
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

    attack_order = _parse_attack_order(args.attack_order)
    ruleset = _parse_ruleset(args.ruleset)
    mask_patterns = args.mask if args.mask else None
    enable_mask = bool(args.enable_mask or mask_patterns)
    enable_rules = not args.no_rules

    if args.hash and args.hash_file:
        console.print("[red]❌ Please provide either --hash or --hash-file (not both).[/]")
        return 1

    # Special case: folder watcher mode delegates to `cracker.tools`.
    if args.watch:
        from .tools import watch_folder

        console.print("[bold blue]=== Folder Watch Mode ===[/]")
        watch_folder(
            folder=args.watch_folder,
            wordlist=args.wordlist or "wordlist/rockyou.txt",
            max_bruteforce_length=args.maxlen or 5,
            use_multiprocessing=not args.no_mp,
            max_wordlist_lines=args.max_lines,
            enable_rules=enable_rules,
            enable_mask=enable_mask,
            mask_patterns=mask_patterns or list(DEFAULT_MASKS) if enable_mask else None,
            max_mask_candidates=args.max_mask_candidates,
            ruleset=ruleset,
            max_rule_candidates=args.max_rule_candidates,
            max_rule_variants_per_word=args.max_rule_variants,
            attack_order=attack_order,
            allow_external_wordlist=args.allow_external_wordlist,
            allow_external_hash_file=args.allow_external_hash_file,
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
                    attack_order=resume_data.get("attack_order") or [
                        "dictionary",
                        "rules",
                        "mask",
                        "bruteforce",
                    ],
                    enable_rules=bool(resume_data.get("enable_rules", True)),
                    enable_mask=bool(resume_data.get("enable_mask", False)),
                    mask_patterns=resume_data.get("mask_patterns"),
                    max_mask_candidates=resume_data.get("max_mask_candidates"),
                    ruleset=resume_data.get("ruleset") or list(DEFAULT_RULESET),
                    max_rule_candidates=resume_data.get("max_rule_candidates"),
                    max_rule_variants_per_word=resume_data.get(
                        "max_rule_variants_per_word", 48
                    ),
                    algo_override=resume_data.get("algo_override"),
                    allow_external_wordlist=bool(
                        resume_data.get("allow_external_wordlist", False)
                    ),
                    allow_external_hash_file=bool(
                        resume_data.get("allow_external_hash_file", False)
                    ),
                )
                try:
                    _run_job_and_report(output_dir, cfg)
                except CrackerError as exc:
                    console.print(f"[red]❌ {exc}[/]")
                    logging.exception("Resume job failed")
                    return 1
                return 0

    if args.hash:
        hashes = [args.hash.strip()] if args.hash.strip() else []
    elif args.hash_file:
        try:
            hashes = load_hashes_from_file(
                args.hash_file, allow_external=args.allow_external_hash_file
            )
        except CrackerError as exc:
            console.print(f"[red]❌ {exc}[/]")
            logging.exception("Hash file issue")
            return 1
    else:
        hashes = _interactive_choose_hashes(args.allow_external_hash_file)

    if not hashes:
        console.print("[red]❌ No hashes provided; exiting.[/]")
        return 1

    wordlist = args.wordlist or _interactive_choose_wordlist()
    maxlen = args.maxlen if args.maxlen is not None else _interactive_max_length()

    cfg = CrackJobConfig(
        hashes=hashes,
        wordlist_path=wordlist,
        max_bruteforce_length=maxlen,
        use_multiprocessing=not args.no_mp,
        max_wordlist_lines=args.max_lines,
        output_dir=output_dir,
        attack_order=attack_order or ["dictionary", "rules", "mask", "bruteforce"],
        enable_rules=enable_rules,
        enable_mask=enable_mask,
        mask_patterns=mask_patterns,
        max_mask_candidates=args.max_mask_candidates,
        ruleset=ruleset,
        max_rule_candidates=args.max_rule_candidates,
        max_rule_variants_per_word=
        args.max_rule_variants if args.max_rule_variants is not None else 48,
        algo_override=args.algo,
        allow_external_wordlist=args.allow_external_wordlist,
        allow_external_hash_file=args.allow_external_hash_file,
    )

    try:
        _run_job_and_report(output_dir, cfg)
    except CrackerError as exc:
        console.print(f"[red]❌ {exc}[/]")
        logging.exception("Cracker job failed")
        return 1

    return 0


if __name__ == "__main__":
    # Allow running `python -m cracker.cli` directly.
    from multiprocessing import freeze_support

    freeze_support()
    raise SystemExit(main())

