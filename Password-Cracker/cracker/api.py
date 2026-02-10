"""
HTTP API layer for the password cracker.

This module exposes a small Flask application that translates HTTP
requests into calls on the application service layer (`cracker.app`).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence

from flask import Flask, jsonify, request

from .app import CrackJobConfig, load_hashes_from_file, run_crack_job
from .core import DEFAULT_MASKS, DEFAULT_RULESET
from .security import CrackerError


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024


@app.before_request
def _local_only() -> Optional[tuple[dict, int]]:
    remote = request.remote_addr
    if remote not in (None, "127.0.0.1", "::1"):
        return jsonify({"error": "Local requests only"}), 403
    return None


def _parse_hash_inputs(
    payload: Dict[str, Any], allow_external_hash_file: bool
) -> List[str]:
    """
    Accept a single hash, a list of hashes, or a path to a hash file.
    """
    hashes: List[str] = []

    if "hashes" in payload and isinstance(payload["hashes"], list):
        hashes = [str(h).strip() for h in payload["hashes"] if str(h).strip()]
    elif "hash" in payload:
        h = str(payload["hash"]).strip()
        if h:
            hashes = [h]
    elif "hash_file" in payload:
        path = str(payload["hash_file"]).strip()
        if path:
            hashes = load_hashes_from_file(
                path, allow_external=allow_external_hash_file
            )

    return hashes


def _parse_attack_order(raw: Any) -> Optional[Sequence[str]]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return None


def _parse_ruleset(raw: Any) -> Sequence[str]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        parsed = [item.strip() for item in raw.split(",") if item.strip()]
        return parsed or DEFAULT_RULESET
    return DEFAULT_RULESET


@app.route("/crack", methods=["POST"])
def crack() -> Any:
    """
    Crack one or more hashes.

    Expected JSON body (examples):

    - Single hash:
        {"hash": "...", "wordlist": "wordlist/rockyou.txt", "maxlen": 5}

    - Multiple hashes:
        {"hashes": ["...", "..."], "wordlist": "wordlist/rockyou.txt"}

    - Hash file:
        {"hash_file": "hashes.txt", "wordlist": "wordlist/rockyou.txt"}
    """
    payload = request.get_json(silent=True) or {}

    allow_external_hash_file = bool(payload.get("allow_external_hash_file", False))
    allow_external_wordlist = bool(payload.get("allow_external_wordlist", False))

    try:
        hashes = _parse_hash_inputs(payload, allow_external_hash_file)
    except CrackerError as exc:
        return jsonify({"error": str(exc)}), 400

    if not hashes:
        return jsonify({"error": "No hashes provided"}), 400

    wordlist = payload.get("wordlist", "wordlist/rockyou.txt")
    try:
        maxlen = int(payload.get("maxlen", 5))
    except (TypeError, ValueError):
        maxlen = 5

    use_mp = bool(payload.get("use_multiprocessing", True))
    max_lines = payload.get("max_wordlist_lines")
    attack_order = _parse_attack_order(payload.get("attack_order"))
    ruleset = _parse_ruleset(payload.get("ruleset"))

    mask_patterns = payload.get("mask_patterns")
    if isinstance(mask_patterns, str):
        mask_patterns = [mask_patterns]

    enable_mask = bool(payload.get("enable_mask", False) or mask_patterns)
    enable_rules = bool(payload.get("enable_rules", True))

    if enable_mask and not mask_patterns:
        mask_patterns = list(DEFAULT_MASKS)

    cfg = CrackJobConfig(
        hashes=hashes,
        wordlist_path=wordlist,
        max_bruteforce_length=maxlen,
        use_multiprocessing=use_mp,
        max_wordlist_lines=max_lines,
        attack_order=attack_order or ["dictionary", "rules", "mask", "bruteforce"],
        enable_rules=enable_rules,
        enable_mask=enable_mask,
        mask_patterns=mask_patterns,
        max_mask_candidates=payload.get("max_mask_candidates"),
        ruleset=ruleset,
        max_rule_candidates=payload.get("max_rule_candidates"),
        max_rule_variants_per_word=payload.get("max_rule_variants_per_word", 48),
        algo_override=payload.get("algo"),
        allow_external_wordlist=allow_external_wordlist,
        allow_external_hash_file=allow_external_hash_file,
    )

    try:
        result = run_crack_job(cfg)
    except CrackerError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logging.exception("Unhandled error in /crack")
        return jsonify({"error": "Internal error"}), 500

    return jsonify(
        {
            "cracked": [
                {"hash": h, "password": pwd} for (h, pwd) in result.cracked
            ],
            "failed": result.failed,
        }
    )


if __name__ == "__main__":
    # Allow running `python -m cracker.api` directly for local testing.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    app.run(host="127.0.0.1", port=5000, debug=False)