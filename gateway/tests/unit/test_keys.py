import pytest

from app.auth.keys import (
    extract_presented_key,
    generate_key,
    hash_key,
    hashes_match,
    parse_key,
)


def test_generated_key_round_trips():
    new = generate_key()
    parsed = parse_key(new.plaintext)
    assert parsed is not None
    assert parsed.prefix == new.prefix
    assert hash_key(new.plaintext) == new.key_hash
    assert hashes_match(new.key_hash, new.plaintext)


def test_generated_keys_are_unique():
    assert len({generate_key().plaintext for _ in range(200)}) == 200


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "",
        "not-a-key",
        "cmpsk_abc_secret",  # prefix too short
        "cmpsk_ZZZZZZZZZZ_secret",  # prefix not hex
        "sk_0123456789_secret",  # wrong scheme
        "cmpsk_0123456789_",  # empty secret
        "cmpsk_0123456789_" + "x" * 200,  # absurdly long
    ],
)
def test_malformed_keys_are_rejected(raw):
    assert parse_key(raw) is None


def test_hash_mismatch_detected():
    a, b = generate_key(), generate_key()
    assert not hashes_match(a.key_hash, b.plaintext)


def test_presented_key_from_headers():
    assert extract_presented_key("Bearer abc", None) == "abc"
    assert extract_presented_key("bearer  abc ", None) == "abc"
    assert extract_presented_key(None, "xyz") == "xyz"
    assert extract_presented_key("Bearer abc", "xyz") == "xyz"  # X-API-Key wins
    assert extract_presented_key("Basic abc", None) is None
    assert extract_presented_key(None, None) is None
