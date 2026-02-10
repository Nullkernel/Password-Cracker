import hashlib
import os

from cracker.app import (
    CrackJobConfig,
    CrackJobResult,
    list_wordlists,
    load_hashes_from_file,
    run_crack_job,
    write_results,
)


def test_run_crack_job_with_small_wordlist(tmp_path):
    wordlist_path = tmp_path / "wordlist.txt"
    hashes_path = tmp_path / "hashes.txt"

    password = "secret"
    target_hash = hashlib.md5(password.encode()).hexdigest()

    wordlist_path.write_text(f"{password}\nother\n", encoding="latin-1")
    hashes_path.write_text(f"{target_hash}\n", encoding="utf-8")

    config = CrackJobConfig(
        hashes=[target_hash],
        wordlist_path=str(wordlist_path),
        max_bruteforce_length=3,
        use_multiprocessing=False,
        max_wordlist_lines=None,
        output_dir=str(tmp_path / "results"),
    )

    result = run_crack_job(config)
    assert result.cracked == [(target_hash, password)]
    assert result.failed == []


def test_write_results_creates_expected_files(tmp_path):
    output_dir = tmp_path / "out"
    result = CrackJobResult(
        cracked=[("h1", "p1"), ("h2", "p2")],
        failed=["h3", "h4"],
    )

    write_results(str(output_dir), result)

    cracked_path = output_dir / "cracked_results.txt"
    failed_path = output_dir / "failed_attempts.txt"

    assert cracked_path.exists()
    assert failed_path.exists()

    cracked_content = cracked_path.read_text(encoding="utf-8").strip().splitlines()
    failed_content = failed_path.read_text(encoding="utf-8").strip().splitlines()

    assert "h1 -> p1" in cracked_content
    assert "h2 -> p2" in cracked_content
    assert "h3" in failed_content
    assert "h4" in failed_content


def test_list_wordlists_and_load_hashes_from_file(tmp_path, monkeypatch):
    # Create a fake wordlist directory and ensure it is discovered.
    base_dir = tmp_path
    wordlist_file = base_dir / "mylist.lst"
    wordlist_file.write_text("one\ntwo\nthree\n", encoding="latin-1")

    files = list_wordlists(base_dir=str(base_dir))
    # list_wordlists always prefixes entries with \"wordlist/\" regardless of base_dir.
    assert any("wordlist/mylist.lst" in f for f in files)

    # Now test load_hashes_from_file separately.
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text("h1\n\nh2\n", encoding="utf-8")

    hashes = load_hashes_from_file(str(hashes_file))
    assert hashes == ["h1", "h2"]

