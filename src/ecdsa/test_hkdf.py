"""
Tests for the HKDF implementation (RFC 5869).
"""

import hashlib

import pytest
from binascii import unhexlify

from .hkdf import (
    hkdf,
    hkdf_extract,
    hkdf_expand,
    HKDFError,
)


# Test cases A.1, A.2 and A.3 from RFC 5869 (SHA-256) and A.7 (SHA-1).
# https://www.rfc-editor.org/rfc/rfc5869#appendix-A
@pytest.mark.parametrize(
    "hash_name,ikm,salt,info,length,prk,okm",
    [
        pytest.param(
            "sha256",
            unhexlify("0b" * 22),
            unhexlify("000102030405060708090a0b0c"),
            unhexlify("f0f1f2f3f4f5f6f7f8f9"),
            42,
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
            id="rfc5869-A1-sha256",
        ),
        pytest.param(
            "sha256",
            unhexlify("".join("%02x" % i for i in range(0x00, 0x50))),
            unhexlify("".join("%02x" % i for i in range(0x60, 0xB0))),
            unhexlify("".join("%02x" % i for i in range(0xB0, 0x100))),
            82,
            "06a6b88c5853361a06104c9ceb35b45c"
            "ef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87",
            id="rfc5869-A2-sha256-long",
        ),
        pytest.param(
            "sha256",
            unhexlify("0b" * 22),
            b"",
            b"",
            42,
            "19ef24a32c717b167f33a91d6f648bdf"
            "96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8",
            id="rfc5869-A3-sha256-empty-salt-info",
        ),
        pytest.param(
            "sha1",
            unhexlify("0c" * 22),
            b"",
            b"",
            42,
            "2adccada18779e7c2077ad2eb19d3f3e731385dd",
            "2c91117204d745f3500d636a62f64f0a"
            "b3bae548aa53d423b0d1f27ebba6f5e5"
            "673a081d70cce7acfc48",
            id="rfc5869-A7-sha1-empty-salt-info",
        ),
    ],
)
def test_rfc5869_vectors(hash_name, ikm, salt, info, length, prk, okm):
    computed_prk = hkdf_extract(salt, ikm, hash_name)
    assert computed_prk == unhexlify(prk)

    computed_okm = hkdf_expand(computed_prk, length, info, hash_name)
    assert computed_okm == unhexlify(okm)

    # and the combined function produces the same output
    assert hkdf(ikm, length, salt=salt, info=info, hash_name=hash_name) == (
        unhexlify(okm)
    )


def test_extract_missing_salt_uses_zero_octets():
    ikm = b"input key material"
    prk_default = hkdf_extract(None, ikm, "sha256")
    prk_empty = hkdf_extract(b"", ikm, hashlib.sha256)
    prk_zero = hkdf_extract(b"\x00" * 32, ikm, "sha256")

    assert prk_default == prk_empty == prk_zero
    assert len(prk_default) == 32


def test_hkdf_expand_max_length_per_block():
    prk = hkdf_extract(None, b"ikm", "sha256")
    okm = hkdf_expand(prk, 255 * 32, b"info", "sha256")
    assert len(okm) == 255 * 32


def test_hkdf_expand_invalid_lengths():
    prk = hkdf_extract(None, b"ikm", "sha256")
    for length in (0, -1, 255 * 32 + 1):
        with pytest.raises(HKDFError):
            hkdf_expand(prk, length, b"", "sha256")


def test_hkdf_expand_rejects_short_prk():
    with pytest.raises(HKDFError):
        hkdf_expand(b"\x00" * 31, 32, b"", "sha256")


def test_hkdf_unknown_hash_name():
    with pytest.raises(HKDFError):
        hkdf(b"ikm", 32, hash_name="not-a-hash")


def test_hkdf_hash_callable():
    ikm = unhexlify("0b" * 22)
    assert hkdf(ikm, 42, hash_name=hashlib.sha256) == hkdf(
        ikm, 42, hash_name="sha256"
    )


def test_hkdf_error_messages_dont_leak_input():
    ikm = b"\xAB" * 32
    try:
        hkdf_expand(ikm, -1, b"", "sha256")
    except HKDFError as error:
        message = str(error)
    else:  # pragma: no cover
        pytest.fail("HKDFError not raised")
    assert ikm not in message.encode("latin-1", "replace")
    assert ikm.hex() not in message
