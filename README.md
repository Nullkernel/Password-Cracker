Here’s a quick local run guide:

**1) Install deps (recommended in `venv`):**
```bash
cd Password-Cracker
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# or: python install.py --upgrade-pip
```
**2) Ensure a wordlist exists under `wordlist/`**  
(e.g., `wordlist/rockyou.txt`).  
External wordlists require `--allow-external-wordlist`.

---
## CLI (Interactive):
```bash
python -m cracker.cli
```
## CLI (Non-interactive):
```bash
python -m cracker.cli \
  --hash 5d41402abc4b2a76b9719d911017c592 \
  --wordlist wordlist/rockyou.txt \
  --maxlen 5
```
## Watch mode (auto-crack new files):
```bash
python -m cracker.cli --watch --watch-folder incoming_hashes
```
---

## HTTP API (local-only)
```bash
flask --app cracker.api run
```
Then:
```bash
curl -X POST http://127.0.0.1:5000/crack \
  -H "Content-Type: application/json" \
  -d '{"hash":"5d41402abc4b2a76b9719d911017c592","wordlist":"wordlist/rockyou.txt","maxlen":5}'
```
If you want external hash files, add `--allow-external-hash-file` (CLI) or `allow_external_hash_file: true` (API).
