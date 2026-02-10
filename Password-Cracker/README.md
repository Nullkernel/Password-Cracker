# Password Cracker

> **Authorized security research only.** Do not run this tool against systems or hashes you do not own or have explicit written permission to test.

## Overview

This project is a terminal-focused password hash cracking tool written in Python. It now supports **smarter attack strategies** (rule + mask attacks), **multiprocessing across dictionary/rule/mask/brute-force stages**, a non-interactive CLI, a safe-by-default HTTP API, and a folder-watching utility for batch jobs.

The codebase is structured as a reusable Python package (`cracker`) with thin front-ends for CLI, HTTP, and tools.

---

## Features

- **Attack strategies** (configurable order):
  - Dictionary attack (with multiprocessing)
  - Rule-based attack (leet/case/affix mangling)
  - Mask attack (e.g. `?l?l?d?d` patterns)
  - Brute-force fallback up to a configurable length
- **Supported hash algorithms**:
  - MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512
  - bcrypt
  - argon2
- **Smart defaults**:
  - Built-in common password list checked first
  - Safe path validation for wordlists and hash files
  - API restricted to local-only access
- **Wordlists**:
  - Discovers `.txt` and `.lst` files under `wordlist/`
  - External wordlists require explicit opt-in flags
- **Resume support**:
  - Stores job configuration in a `cracker_resume.json` file per output directory
- **Results**:
  - Writes `cracked_results.txt` and `failed_attempts.txt` into a job-specific output folder
- **CLI**:
  - Interactive mode for single hash or file-of-hashes
  - Non-interactive flags for automated usage
  - Watch mode for auto-cracking incoming files
- **HTTP API**:
  - Flask-based `/crack` endpoint wrapping the full attack pipeline
  - Local-only by default and defensive error handling

---

## Architecture

At a high level:

- **`cracker.core`** – Pure domain logic:
  - Hash algorithm detection
  - Hash verification across supported algorithms
  - Dictionary, rule-based, mask, and brute-force attack engines
- **`cracker.app`** – Application/service layer:
  - `CrackJobConfig` and `CrackJobResult` data structures
  - High-level `run_crack_job` function that orchestrates attacks for one or more hashes
  - Helpers for reading hashes from files and listing wordlists
  - `write_results` to persist cracked/failed hashes to disk
- **Interface layers:**
  - **CLI (`cracker.cli`)**
  - **HTTP API (`cracker.api`)**
  - **Tools (`cracker.tools`)**
  - **Entry script (`password_cracker.py`)**

---

## Installation

Prerequisites:

- Python 3 (with `pip`)
- On Windows, PowerShell is used by `run.bat` and `install.py`.

Basic steps:

```bash
cd Password-Cracker
python install.py --upgrade-pip
# or
pip install -r requirements.txt
```

---

## CLI Usage

### Interactive mode

```bash
python -m cracker.cli
```

### Non-interactive mode

```bash
# Crack a single hash with a custom wordlist
python -m cracker.cli \
  --hash 5d41402abc4b2a76b9719d911017c592 \
  --wordlist wordlist/rockyou.txt \
  --maxlen 5
```

### Attack customization

```bash
# Enable mask attack with custom pattern
python -m cracker.cli \
  --hash 5d41402abc4b2a76b9719d911017c592 \
  --mask "?l?l?d?d" \
  --attack-order dictionary,rules,mask,bruteforce

# Disable rule-based attacks
python -m cracker.cli --hash <hash> --no-rules

# Override detected algorithm
python -m cracker.cli --hash <hash> --algo sha256
```

### Folder watch mode

```bash
python -m cracker.cli --watch
python -m cracker.cli --watch --watch-folder incoming_hashes_custom
```

---

## HTTP API Usage

> **Local-only:** the API rejects non-local requests by default.

Start the Flask app (from `Password-Cracker` directory):

```bash
flask --app cracker.api run
```

Example request:

```bash
curl -X POST http://127.0.0.1:5000/crack \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "5d41402abc4b2a76b9719d911017c592",
    "wordlist": "wordlist/rockyou.txt",
    "maxlen": 5,
    "use_multiprocessing": false,
    "enable_mask": true,
    "mask_patterns": ["?l?l?d?d"]
  }'
```

Response:

```json
{
  "cracked": [
    { "hash": "5d41402abc4b2a76b9719d911017c592", "password": "hello" }
  ],
  "failed": []
}
```

---

## Safe Defaults & Security

- **Local-only API**: non-local requests receive HTTP 403.
- **Path validation**: wordlists must live inside `wordlist/` unless you pass `--allow-external-wordlist` (or `allow_external_wordlist` in API).
- **Hash files**: only files inside the working directory are accepted unless explicitly allowed.
- **Debug disabled**: the API defaults to `debug=False` when launched directly.

---

## Testing

```bash
pytest
```

Test suite coverage:

- `test_core.py`: hashing + attack engines (dictionary, rule, mask, brute-force)
- `test_app.py`: job configuration, file safety, results writing
- `test_cli_api_tools.py`: CLI, API, and folder watcher wiring

---

## Performance Notes

- Dictionary, rule, mask, and brute-force attacks all support multiprocessing.
- Brute-force grows exponentially with `maxlen`—use with care.
- Mask attacks are the best trade-off when you have a predictable pattern.

---

## Contributing

- Add tests for new behavior under `tests/`.
- Keep core logic (`cracker.core`) free of CLI/API-specific assumptions.
- Keep `cracker.app` focused on orchestration and I/O, with UI concerns in CLI/API/tools.