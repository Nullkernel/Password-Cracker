# Password Cracker — Cleaned & Repository-Ready
**Purpose:** Educational / authorized security research only. Do **NOT** use this tool on systems you do not own or have explicit consent to test.

## What this cleaned package contains
- Source code (cleaned to exclude bundled virtual environment)
- `.gitignore`
- `requirements.txt` (original)
- `requirements-pinned.txt` (example pinned entries — verify before use)
- `LICENSE` (MIT suggested)
- Suggested `README_suggested.md` (this file)

## Responsible use & disclaimer
This repository is intended for defensive, educational, and authorized security testing. By using this code you agree to only run it against systems and hashes you own or have explicit permission to test. The authors are **not** responsible for misuse.

## Quick start (example)
```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
# Run CLI (example)
python -m cracker.cli --help
```

## Contributing
- Follow coding standards (PEP8)
- Add unit tests using pytest and keep test data synthetic & non-sensitive
- Open an issue or PR for proposed changes