import hashlib
import os

import pytest

from cracker import api, tools
from cracker import cli as cli_mod


def test_cli_single_hash_flow(tmp_path, monkeypatch):
    """
    Simulate an end-to-end CLI run for a single hash, using a tiny
    local wordlist so the test stays fast and deterministic.
    """
    # Run CLI from an isolated working directory with a small wordlist.
    monkeypatch.chdir(tmp_path)

    wordlist_dir = tmp_path / "wordlist"
    wordlist_dir.mkdir()
    wordlist_path = wordlist_dir / "rockyou.txt"

    password = "secret"
    target_hash = hashlib.md5(password.encode()).hexdigest()
    wordlist_path.write_text(f"{password}\nother\n", encoding="latin-1")

    # Prepare fake user input sequence:
    # 1) choose single-hash mode
    # 2) provide the hash
    # 3) accept default wordlist (blank input)
    # 4) provide max brute-force length (won't be used because dict finds it)
    inputs = iter(["s", target_hash, "", "5"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))

    output_dir = tmp_path / "results"
    exit_code = cli_mod.main(["--output-dir", str(output_dir), "--no-mp"])

    assert exit_code == 0
    cracked_path = output_dir / "cracked_results.txt"
    assert cracked_path.exists()
    content = cracked_path.read_text(encoding="utf-8")
    assert password in content


def test_cli_watch_invokes_watch_folder(monkeypatch):
    """
    Ensure that --watch wiring passes the correct parameters to tools.watch_folder.
    """
    called = {}

    def fake_watch_folder(**kwargs):
        called.update(kwargs)

    monkeypatch.setattr(tools, "watch_folder", fake_watch_folder)

    exit_code = cli_mod.main(["--watch", "--watch-folder", "somefolder", "--no-mp"])
    assert exit_code == 0

    assert called["folder"] == "somefolder"
    assert called["wordlist"] == "wordlist/rockyou.txt"
    assert called["max_bruteforce_length"] == 5
    # no-mp -> use_multiprocessing=False
    assert called["use_multiprocessing"] is False


def test_api_crack_single_hash(tmp_path, monkeypatch):
    """
    Use Flask's test client to verify that POST /crack can successfully
    crack a single hash with a small custom wordlist.
    """
    monkeypatch.chdir(tmp_path)

    wordlist_dir = tmp_path / "wordlist"
    wordlist_dir.mkdir()
    wordlist_path = wordlist_dir / "api_list.txt"

    password = "secret"
    target_hash = hashlib.md5(password.encode()).hexdigest()
    wordlist_path.write_text(f"{password}\nother\n", encoding="latin-1")

    client = api.app.test_client()
    resp = client.post(
        "/crack",
        json={
            "hash": target_hash,
            "wordlist": str(wordlist_path),
            "maxlen": 5,
            "use_multiprocessing": False,
        },
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert any(item["password"] == password for item in data["cracked"])
    assert data["failed"] == []


def test_api_crack_missing_hash_returns_400():
    client = api.app.test_client()
    resp = client.post("/crack", json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data


def test_watch_folder_processes_new_file_and_writes_results(tmp_path, monkeypatch):
    """
    Run watch_folder in a controlled way by forcing the polling loop to stop
    after the first sleep, and assert that a result directory was created.
    """
    incoming_dir = tmp_path / "incoming"
    incoming_dir.mkdir()

    wordlist_path = tmp_path / "wordlist.txt"
    password = "secret"
    target_hash = hashlib.md5(password.encode()).hexdigest()
    wordlist_path.write_text(f"{password}\nother\n", encoding="latin-1")

    hash_file = incoming_dir / "job1.txt"
    hash_file.write_text(f"{target_hash}\n", encoding="utf-8")

    output_root = tmp_path / "watch_results"

    class StopWatch(Exception):
        pass

    def fake_sleep(_seconds):
        raise StopWatch()

    # Cause the watcher loop to exit after the first sleep call.
    monkeypatch.setattr(tools.time, "sleep", fake_sleep)

    with pytest.raises(StopWatch):
        tools.watch_folder(
            folder=str(incoming_dir),
            wordlist=str(wordlist_path),
            max_bruteforce_length=5,
            use_multiprocessing=False,
            poll_interval=0.0,
            output_root=str(output_root),
        )

    # After the first iteration, a results subdirectory should have been created.
    subdirs = [p for p in output_root.iterdir() if p.is_dir()]
    assert subdirs, "Expected at least one results directory to be created"
    cracked_files = [
        p / "cracked_results.txt" for p in subdirs if (p / "cracked_results.txt").exists()
    ]
    assert cracked_files, "Expected cracked_results.txt in at least one results directory"
    content = cracked_files[0].read_text(encoding="utf-8")
    assert password in content

