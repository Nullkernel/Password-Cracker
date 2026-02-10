"""
HTTP API layer for the password cracker.

This module exposes a small Flask application that translates HTTP
requests into calls on the application service layer (`cracker.app`).
"""

from __future__ import annotations

from typing import Any, Dict, List

from flask import Flask, jsonify, request

from .app import CrackJobConfig, load_hashes_from_file, run_crack_job


app = Flask(__name__)


def _parse_hash_inputs(payload: Dict[str, Any]) -> List[str]:
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
            hashes = load_hashes_from_file(path)

    return hashes


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

    hashes = _parse_hash_inputs(payload)
    if not hashes:
        return jsonify({"error": "No hashes provided"}), 400

    wordlist = payload.get("wordlist", "wordlist/rockyou.txt")
    try:
        maxlen = int(payload.get("maxlen", 5))
    except (TypeError, ValueError):
        maxlen = 5

    use_mp = bool(payload.get("use_multiprocessing", True))
    max_lines = payload.get("max_wordlist_lines")

    cfg = CrackJobConfig(
        hashes=hashes,
        wordlist_path=wordlist,
        max_bruteforce_length=maxlen,
        use_multiprocessing=use_mp,
        max_wordlist_lines=max_lines,
    )

    result = run_crack_job(cfg)

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
    app.run(debug=True)

