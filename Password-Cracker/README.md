# Password Cracker

### Overview

This project is a terminal-focused password hash cracking tool written in Python.  
It supports dictionary attacks with optional brute-force fallback, multiple hash algorithms (including bcrypt and argon2), an interactive CLI, a simple HTTP API, and a folder-watching utility for batch jobs.

The codebase is structured as a reusable Python package (`cracker`) with thin front-ends for CLI, HTTP, and tools.

---

## Features

- Crack one or more hashes using:
  - Dictionary attack against a wordlist file
  - Optional brute-force fallback up to a configurable maximum length
- Supported hash algorithms:
  - MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512
  - bcrypt
  - argon2
- Hash type detection from hash string format
- Wordlists:
  - Discovers `.txt` and `.lst` files under a `wordlist/` directory
  - Uses a specified wordlist file for attacks
- Resume support:
  - Stores job configuration in a `cracker_resume.json` file per output directory
- Results:
  - Writes `cracked_results.txt` and `failed_attempts.txt` into a job-specific output folder
- CLI:
  - Interactive mode for single hash or file-of-hashes
  - Command-line options for multiprocessing, output directory, wordlist truncation, and folder watch
- HTTP API:
  - Flask-based `/crack` endpoint to crack single or multiple hashes
- Tools:
  - Folder watcher that auto-cracks new `.txt` files in a configured directory using a chosen wordlist

Everything above is implemented in the codebase.

---

## Architecture

At a high level:

- **`cracker.core`** – Pure domain logic:
  - Hash algorithm detection
  - Hash verification across supported algorithms
  - Dictionary and brute-force attack engines
- **`cracker.app`** – Application/service layer:
  - `CrackJobConfig` and `CrackJobResult` data structures
  - High-level `run_crack_job` function that orchestrates attacks for one or more hashes
  - Helpers for reading hashes from files and listing wordlists
  - `write_results` to persist cracked/failed hashes to disk
- **Interface layers:**
  - **CLI (`cracker.cli`)**
    - Argument parsing
    - Interactive prompts
    - Resume handling
    - Delegates to `cracker.app.run_crack_job` and `write_results`
  - **HTTP API (`cracker.api`)**
    - Flask app exposing `POST /crack` that wraps `run_crack_job`
  - **Tools (`cracker.tools`)**
    - Folder watcher (`watch_folder`) that detects new `.txt` files and triggers `run_crack_job` for each file
  - **Entry script (`password_cracker.py`)**
    - Thin wrapper that calls `cracker.cli.main()` for legacy `python password_cracker.py` usage

A typical flow (CLI):

- User invokes CLI → arguments parsed → interactive prompts determine:
  - Hashes (single or from file)
  - Wordlist path
  - Max brute-force length
- CLI builds `CrackJobConfig` → calls `run_crack_job` → gets `CrackJobResult`
- CLI calls `write_results` to produce `cracked_results.txt` and `failed_attempts.txt`
- Resume state is saved and cleared appropriately

---

## Module Breakdown

### `cracker/core.py`

Responsibilities:

- **Supported algorithm & pattern definitions**
  - `SUPPORTED_ALGOS`: list of supported algorithm names
  - `HASH_PATTERNS`: regex patterns used to infer algorithm type from hash string

- **Hash utilities**
  - `hash_for_testing(password: str, algo: str = "md5") -> str`  
    Generates a hash for the given password and algorithm:
    - For `bcrypt`: uses `bcrypt.gensalt()`
    - For `argon2`: uses an `argon2.PasswordHasher`
    - For others: calls `hashlib.<algo>(password).hexdigest()`

  - `detect_hash_algo(hash_str: str) -> Optional[str]`  
    Tries regex patterns in `HASH_PATTERNS` and returns the best-guess algorithm name or `None`.

  - `hash_password(password: str, algo: str, target_hash: str) -> bool`  
    Returns `True` if `password` matches `target_hash` with the given algorithm.  
    Handles bcrypt and argon2 with their respective libraries; other algorithms use `hashlib`.

- **Dictionary attack**
  - `@dataclass DictionaryAttackConfig`:
    - `hash_to_crack: str`
    - `algo: str`
    - `candidates: Iterable[str]`
    - `max_candidates: Optional[int] = None`
  - `run_dictionary_attack(config: DictionaryAttackConfig) -> Optional[str]`:
    - Iterates through candidate passwords (optionally truncated to `max_candidates`)
    - Wraps iteration in a `tqdm` progress bar
    - Returns the first candidate that matches or `None` if none match

- **Brute-force attack**
  - `@dataclass BruteForceConfig`:
    - `hash_to_crack: str`
    - `algo: str`
    - `max_length: int = 5`
    - `charset: str` (defaults to ASCII letters, digits, punctuation)
    - `use_multiprocessing: bool = True`
  - `run_bruteforce_attack(config: BruteForceConfig) -> Optional[str]`:
    - Iterates over all combinations of the charset up to `max_length`
    - Can use multiprocessing (`multiprocessing.Pool`) or a single process
    - Wraps iterations in `tqdm` progress bars
    - Returns the first matching candidate or `None` if not found

### `cracker/app.py`

Responsibilities:

- **Job configuration & result types**
  - `@dataclass CrackJobConfig`:
    - `hashes: Sequence[str]`
    - `wordlist_path: str`
    - `max_bruteforce_length: int = 5`
    - `use_multiprocessing: bool = True`
    - `max_wordlist_lines: Optional[int] = None`
    - `output_dir: str = "results"` (used by callers like CLI and tools)
  - `@dataclass CrackJobResult`:
    - `cracked: List[Tuple[str, str]]` (pairs of hash and password)
    - `failed: List[str]` (hashes that could not be cracked)

- **Helpers**
  - `_load_wordlist(path: str) -> List[str]`  
    Reads wordlist file as `latin-1`, ignoring errors, and returns lines.
  - `list_wordlists(base_dir: Optional[str] = None) -> List[str]`  
    Ensures the wordlist directory exists, then returns relative paths like `wordlist/<name>` for `.txt`/`.lst` files in `base_dir` (or `./wordlist` by default).
  - `load_hashes_from_file(path: str) -> List[str]`  
    Reads non-empty lines from a hash file as UTF-8 and returns them.

- **Job execution**
  - `run_crack_job(config: CrackJobConfig) -> CrackJobResult`:
    - Loads wordlist once.
    - For each hash:
      - Detects algorithm with `detect_hash_algo`. If unknown, adds to `failed` and continues.
      - Runs dictionary attack (`run_dictionary_attack`).
      - If not found, runs brute-force attack (`run_bruteforce_attack`) with config values.
      - Records cracked or failed for each hash.
    - Returns a populated `CrackJobResult`.

- **Result persistence**
  - `write_results(output_dir: str, result: CrackJobResult) -> None`:
    - Ensures `output_dir` exists.
    - Writes `cracked_results.txt` (one `hash -> password` per line) if there are cracked entries.
    - Writes `failed_attempts.txt` (one hash per line) if there are failed entries.

### `cracker/cli.py`

Responsibilities:

- **Argument parsing**
  - `main(argv: Optional[Sequence[str]] = None) -> int` supports:
    - `--no-mp`: disable multiprocessing in brute-force phase
    - `--output-dir DIR`: custom output directory for this run’s results/logs
    - `--max-lines N`: limit number of wordlist lines checked
    - `--watch`: run folder watcher mode instead of interactive cracking
    - `--watch-folder PATH`: folder to watch when using `--watch` (default: `incoming_hashes`)

- **Watch mode**
  - If `--watch` is provided, `main` imports and calls:
    - `tools.watch_folder(folder=..., wordlist="wordlist/rockyou.txt", max_bruteforce_length=5, use_multiprocessing=not args.no_mp)`

- **Normal interactive mode**
  - `_setup_output_dir(custom: Optional[str]) -> str`:
    - Creates output directory (default: `results_<timestamp>`) and configures logging to `debug.log` inside it.
  - Resume:
    - Uses `RESUME_FILENAME = "cracker_resume.json"` stored in the output directory.
    - `_load_resume`, `_save_resume`, `_remove_resume` manage this JSON file.
    - On start, if resume data exists, user can choose to resume the previous job, in which case a `CrackJobConfig` is reconstructed and `run_crack_job` is called.
  - New job:
    - `_interactive_choose_hashes()`:
      - Prompts: `[s]ingle hash` or `[f]ile of hashes`.
      - For file mode, reads hashes via `load_hashes_from_file`.
    - `_interactive_choose_wordlist()`:
      - Lists available wordlists via `list_wordlists`.
      - Prompts for path (default: `wordlist/rockyou.txt`).
    - `_interactive_max_length()`:
      - Prompts for max brute-force length (default 5).
    - Builds `CrackJobConfig` and calls `_run_job_and_report()`, which:
      - Saves resume info.
      - Calls `run_crack_job` and `write_results`.
      - Prints a summary of cracked/failed counts.
      - Removes resume file on completion.

- **Module entry point**
  - Running `python -m cracker.cli` executes `main()` and exits with its code.

### `cracker/api.py`

Responsibilities:

- Creates a Flask app:

  - `app = Flask(__name__)`

- Request parsing helper:

  - `_parse_hash_inputs(payload: Dict[str, Any]) -> List[str]`:
    - Accepts:
      - `"hashes": [...]` (list of hashes)
      - `"hash": "..."` (single hash)
      - `"hash_file": "path/to/file.txt"` (path to file with hashes, one per line)
    - Returns a list of hash strings (or empty list).

- Endpoint:

  - `@app.route("/crack", methods=["POST"])` → `crack()`:
    - Reads JSON payload.
    - Gets hashes via `_parse_hash_inputs`.
    - If no hashes, returns `{"error": "No hashes provided"}`, HTTP 400.
    - Reads other parameters from JSON:
      - `"wordlist"` (default `"wordlist/rockyou.txt"`)
      - `"maxlen"` (max brute-force length, default 5)
      - `"use_multiprocessing"` (default `True`)
      - `"max_wordlist_lines"` (optional limit for wordlist)
    - Builds a `CrackJobConfig` and calls `run_crack_job`.
    - Returns JSON:
      - `"cracked"`: list of `{ "hash": ..., "password": ... }`
      - `"failed"`: list of hashes that were not cracked

- Module can be run directly:

  - `if __name__ == "__main__": app.run(debug=True)`

### `cracker/tools.py`

Responsibilities:

- `watch_folder(...) -> None`:
  - Parameters:
    - `folder: str = "incoming_hashes"`
    - `wordlist: str = "wordlist/rockyou.txt"`
    - `max_bruteforce_length: int = 5`
    - `use_multiprocessing: bool = True`
    - `poll_interval: float = 5.0`
    - `output_root: str = "results_watch"`
  - Behavior:
    - Ensures `folder` and `output_root` exist.
    - Logs that it is watching the folder.
    - Infinite loop:
      - Scans `folder` for `.txt` files.
      - Each unseen file:
        - Reads hashes via `load_hashes_from_file`.
        - Builds a `CrackJobConfig` with those hashes and the configured wordlist and brute-force parameters.
        - Calls `run_crack_job` and `write_results`, writing to a subdirectory `<output_root>/<timestamp>_<filename-base>/`.
        - Logs that the job is finished and where results are saved.
      - Sleeps for `poll_interval` seconds and repeats.

### `password_cracker.py`

- Thin legacy entry point:

  - Imports `cracker.cli.main` and calls it under `if __name__ == "__main__"` with `multiprocessing.freeze_support()`.

### `tests/`

- `tests/test_core.py` – Unit tests for `cracker.core`.
- `tests/test_app.py` – Unit tests for `cracker.app`.
- `tests/test_cli_api_tools.py` – Integration-style tests for CLI, API, and `watch_folder`.

### `install.py`

- Helper script to create and manage a virtual environment, install dependencies from `requirements.txt`, and optionally clean/recreate the venv and upgrade `pip`.

---

## Installation

Prerequisites:

- Python 3 (with `pip`)
- On Windows, PowerShell is used by `run.bat` and `install.py`.

Basic steps:

1. Change into the `Password-Cracker` directory:

   ```bash
   cd Password-Cracker
   ```

2. Optionally create and use a virtual environment (recommended):

   ```bash
   python install.py --upgrade-pip
   ```

   This will:
   - Create a `.venv` folder (if needed)
   - Install packages listed in `requirements.txt` into that venv
   - Print instructions for activation

3. Alternatively, install dependencies manually:

   ```bash
   pip install -r requirements.txt
   ```

Dependencies (derived from code and typical `requirements.txt`):

- `bcrypt`
- `argon2-cffi`
- `tqdm`
- `rich`
- `flask` (for HTTP API)
- `pytest` (for running tests)

---

## Usage

### CLI (recommended entry point)

From the `Password-Cracker` directory with dependencies installed:

```bash
python -m cracker.cli
```

Example usage:

- Interactive session:

  1. CLI asks: `Input a [s]ingle hash or [f]ile of hashes?`
  2. For `[s]`:
     - Enter the hash string.
  3. CLI prints detected wordlists (e.g. under `wordlist/`).
  4. Prompt: `Enter path to wordlist (default: wordlist/rockyou.txt):`
  5. Prompt: `Max brute-force length (default 5):`
  6. Cracking begins; results saved to a folder `results_<timestamp>/`.

- With command-line options:

  ```bash
  # Use a specific output directory, disable multiprocessing
  python -m cracker.cli --output-dir results/run1 --no-mp
  ```

- Folder watch mode:

  ```bash
  # Watch default folder "incoming_hashes"
  python -m cracker.cli --watch

  # Watch a specific folder
  python -m cracker.cli --watch --watch-folder incoming_hashes_custom
  ```

### Legacy entry point

You can still use the older-style invocation:

```bash
python password_cracker.py
```

This simply delegates to `cracker.cli.main()`.

### Windows helper script

`run.bat` runs the canonical CLI entry point as admin:

```bat
run.bat
```

It uses:

```powershell
Start-Process 'python.exe' -ArgumentList '-m cracker.cli' -Verb runAs
```

---

## HTTP API Usage

Start the Flask app (from `Password-Cracker` directory):

```bash
flask --app cracker.api run
```

This will serve the API at `http://127.0.0.1:5000` by default.

Example request (single hash):

```bash
curl -X POST http://127.0.0.1:5000/crack \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "5d41402abc4b2a76b9719d911017c592",
    "wordlist": "wordlist/rockyou.txt",
    "maxlen": 5,
    "use_multiprocessing": false
  }'
```

Expected JSON structure:

```json
{
  "cracked": [
    { "hash": "5d41402abc4b2a76b9719d911017c592", "password": "hello" }
  ],
  "failed": []
}
```

Other request shapes supported by the API:

- Multiple hashes:

  ```json
  {
    "hashes": ["...", "..."],
    "wordlist": "wordlist/rockyou.txt"
  }
  ```

- Hash file:

  ```json
  {
    "hash_file": "path/to/hashes.txt",
    "wordlist": "wordlist/rockyou.txt"
  }
  ```

---

## Configuration

There are no environment variables used for configuration. Configuration is driven by:

- **CLI arguments (`cracker.cli`)**
  - `--no-mp`: disable multiprocessing
  - `--output-dir DIR`: custom directory for results and logs
  - `--max-lines N`: limit number of wordlist lines checked
  - `--watch`: run folder watch mode
  - `--watch-folder PATH`: watched folder in watch mode

- **Tools (`cracker.tools.watch_folder`) parameters**
  - `folder`: directory to watch for new `.txt` files
  - `wordlist`: path to the wordlist file
  - `max_bruteforce_length`
  - `use_multiprocessing`
  - `poll_interval`
  - `output_root`: base directory where result subdirectories are created

- **HTTP API (`cracker.api`) request body**
  - `hash` / `hashes` / `hash_file`
  - `wordlist`: wordlist file path
  - `maxlen`: max brute-force length
  - `use_multiprocessing`
  - `max_wordlist_lines`

---

## Testing

The project includes a test suite under `tests/` using `pytest`.

From the `Password-Cracker` directory:

```bash
pytest
```

This runs:

- `test_core.py`: unit tests for hashing and attacks.
- `test_app.py`: tests for `CrackJobConfig`, `CrackJobResult`, `run_crack_job`, `write_results`, wordlist/hash loading.
- `test_cli_api_tools.py`: integration-oriented tests for:
  - CLI single-hash flow
  - CLI `--watch` wiring
  - Flask `/crack` endpoint
  - `watch_folder` behavior against a temporary directory

---

## Limitations / Non-goals

- **Performance constraints**
  - Brute-force attack is exponential in `max_bruteforce_length` and charset size; large values can take a very long time and consume significant CPU.
  - Multiprocessing is available but not fully exercised in tests; behavior on some platforms or environments may vary.

- **Security & safety**
  - The Flask API performs no authentication or authorization.
  - File paths for `wordlist` and `hash_file` are taken from the request; invalid paths can lead to server errors.
  - This tool is intended for educational and authorized security testing only.

- **Hash detection**
  - `detect_hash_algo` is pattern-based and may misidentify or fail to recognize non-standard or unusual hash formats. Unknown hashes are simply marked as failed.

- **Folder watcher**
  - `watch_folder` runs indefinitely until the process is stopped; there is no built-in shutdown or signal handling abstraction.
  - Only new `.txt` files (by path) are processed once; modifications to existing files are not reprocessed.

- **Wordlists**
  - The code expects wordlist files to be available on the filesystem.  
    It does not include functionality to download or manage wordlists.

---

## Contributing

The project does not define a formal contributing process in code or documentation, but a typical approach would be:

- Add tests for any new behavior under `tests/`.
- Keep core logic (`cracker.core`) free of CLI/API-specific assumptions.
- Keep `cracker.app` focused on orchestration and I/O, with UI concerns in CLI/API/tools.

You can adapt this to your own workflow as needed.

