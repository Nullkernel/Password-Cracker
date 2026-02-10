import hashlib

import bcrypt
from argon2 import PasswordHasher

from cracker.core import (
    BruteForceConfig,
    DictionaryAttackConfig,
    MaskAttackConfig,
    RuleAttackConfig,
    detect_hash_algo,
    hash_password,
    run_bruteforce_attack,
    run_dictionary_attack,
    run_mask_attack,
    run_rule_attack,
)


def test_detect_hash_algo_known_algorithms():
    md5_hash = hashlib.md5(b"hello").hexdigest()
    sha1_hash = hashlib.sha1(b"hello").hexdigest()
    sha256_hash = hashlib.sha256(b"hello").hexdigest()
    sha512_hash = hashlib.sha512(b"hello").hexdigest()

    ph = PasswordHasher()
    argon_hash = ph.hash("hello")
    bcrypt_hash = bcrypt.hashpw(b"hello", bcrypt.gensalt()).decode()

    assert detect_hash_algo(md5_hash) == "md5"
    assert detect_hash_algo(sha1_hash) == "sha1"
    assert detect_hash_algo(sha256_hash) == "sha256"
    assert detect_hash_algo(sha512_hash) == "sha512"
    assert detect_hash_algo(argon_hash) == "argon2"
    assert detect_hash_algo(bcrypt_hash) == "bcrypt"


def test_hash_password_positive_and_negative():
    password = "secret"

    md5_hash = hashlib.md5(password.encode()).hexdigest()
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()

    ph = PasswordHasher()
    argon_hash = ph.hash(password)
    bcrypt_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Positive cases
    assert hash_password(password, "md5", md5_hash)
    assert hash_password(password, "sha256", sha256_hash)
    assert hash_password(password, "argon2", argon_hash)
    assert hash_password(password, "bcrypt", bcrypt_hash)

    # Negative cases
    assert not hash_password("wrong", "md5", md5_hash)
    assert not hash_password("wrong", "sha256", sha256_hash)
    assert not hash_password("wrong", "argon2", argon_hash)
    assert not hash_password("wrong", "bcrypt", bcrypt_hash)


def test_run_dictionary_attack_finds_password():
    target = hashlib.md5(b"secret").hexdigest()
    candidates = ["foo\n", "bar\n", "secret\n"]

    config = DictionaryAttackConfig(
        hash_to_crack=target,
        algo="md5",
        candidates=candidates,
        max_candidates=None,
        use_multiprocessing=False,
    )

    result = run_dictionary_attack(config)
    assert result == "secret"


def test_run_dictionary_attack_respects_max_candidates():
    target = hashlib.md5(b"secret").hexdigest()
    candidates = ["foo\n", "bar\n", "secret\n"]

    config = DictionaryAttackConfig(
        hash_to_crack=target,
        algo="md5",
        candidates=candidates,
        max_candidates=2,
        use_multiprocessing=False,
    )

    result = run_dictionary_attack(config)
    assert result is None

def test_run_rule_attack_finds_password():
    password = "Secret1"
    target = hashlib.sha256(password.encode()).hexdigest()

    config = RuleAttackConfig(
        hash_to_crack=target,
        algo="sha256",
        base_words=["secret"],
        ruleset=["capitalize", "append_digits"],
        max_candidates=200,
        max_variants_per_word=100,
        use_multiprocessing=False,
    )

    result = run_rule_attack(config)
    assert result == password


def test_run_mask_attack_finds_password():
    password = "ab1"
    target = hashlib.sha1(password.encode()).hexdigest()

    config = MaskAttackConfig(
        hash_to_crack=target,
        algo="sha1",
        masks=["?l?l?d"],
        max_candidates=100,
        use_multiprocessing=False,
    )

    result = run_mask_attack(config)
    assert result == password


def test_run_bruteforce_attack_finds_password_no_multiprocessing():
    # Very small search space so this stays fast.
    password = "ba"
    target = hashlib.sha1(password.encode()).hexdigest()

    cfg = BruteForceConfig(
        hash_to_crack=target,
        algo="sha1",
        max_length=2,
        charset="ab",
        use_multiprocessing=False,
    )

    result = run_bruteforce_attack(cfg)
    assert result == password


def test_run_bruteforce_attack_respects_charset_and_max_length():
    # With a single-character charset and length 1, a length-2 password
    # should never be found.
    password = "bb"
    target = hashlib.sha1(password.encode()).hexdigest()

    cfg = BruteForceConfig(
        hash_to_crack=target,
        algo="sha1",
        max_length=1,
        charset="b",
        use_multiprocessing=False,
    )

    result = run_bruteforce_attack(cfg)
    assert result is None

