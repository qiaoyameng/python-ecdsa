"""
Tests for the RFC 5869 HKDF implementation.
"""

from binascii import unhexlify

import pytest

from .hkdf import (
    HKDFError,
    hkdf,
    hkdf_expand,
    hkdf_extract,
)


# Test vectors from Appendix A of RFC 5869.
# https://www.rfc-editor.org/rfc/rfc5869#appendix-A
@pytest.mark.parametrize(
    "hashfunc,ikm,salt,info,length,prk,okm",
    [
        pytest.param(
            "sha256",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            42,
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
            id="sha256-test-case-1-basic",
        ),
        pytest.param(
            "sha256",
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f"
            "707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbeb"
            "fc0c1c2c3c4c5c6c7c8c9cacbcccdcec"
            "fd0d1d2d3d4d5d6d7d8d9dadbdcddded"
            "fe0e1e2e3e4e5e6e7e8e9eaebecedee"
            "eff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            82,
            "06a6b88c5853361a06104c9ceb35b45c"
            "ef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87",
            id="sha256-test-case-2-long",
        ),
        pytest.param(
            "sha256",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            42,
            "19ef24a32c717b167f33a91d6f648bdf"
            "96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31"
            "b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8",
            id="sha256-test-case-3-empty-salt-info",
        ),
        pytest.param(
            "sha1",
            "0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            42,
            "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
            "085a01ea1b10f36933068b56efa5ad81"
            "a4f14b822f5b091568a9cdd4f155fda2"
            "c22e422478d305f3f896",
            id="sha1-test-case-4-basic",
        ),
        pytest.param(
            "sha1",
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            "202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f"
            "404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f"
            "707172737475767778797a7b7c7d7e7f"
            "808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbeb"
            "fc0c1c2c3c4c5c6c7c8c9cacbcccdcec"
            "fd0d1d2d3d4d5d6d7d8d9dadbdcddded"
            "fe0e1e2e3e4e5e6e7e8e9eaebecedee"
            "eff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            82,
            "8adae09a2a307059478d309b26c4115a224cfaf6",
            "0bd770a74d1160f7c9f12cd5912a06eb"
            "ff6adcae899d92191fe4305673ba2ffe"
            "8fa3f1a4e5ad79f3f334b3b202b2173c4"
            "86ea37ce3d397ed034c7f9dfeb15c5e9"
            "27336d0441f4c4300e2cff0d0900b52d3b4",
            id="sha1-test-case-5-long",
        ),
        pytest.param(
            "sha1",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            42,
            "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
            "0ac1af7002b3d761d1e55298da9d0506"
            "b9ae52057220a306e07b6b87e8df21d0"
            "ea00033de03984d34918",
            id="sha1-test-case-6-empty-salt-info",
        ),
        pytest.param(
            "sha1",
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            None,
            "",
            42,
            "2adccada18779e7c2077ad2eb19d3f3e731385dd",
            "2c91117204d745f3500d636a62f64f0a"
            "b3bae548aa53d423b0d1f27ebba6f5e5"
            "673a081d70cce7acfc48",
            id="sha1-test-case-7-salt-not-provided",
        ),
    ],
)
def test_hkdf_rfc5869_vectors(
    hashfunc, ikm, salt, info, length, prk, okm
):
    import hashlib

    hashfunc = getattr(hashlib, hashfunc)
    ikm = unhexlify(ikm)
    salt = b"" if salt is None else unhexlify(salt)
    info = unhexlify(info)
    prk = unhexlify(prk)
    okm = unhexlify(okm)

    assert hkdf_extract(salt, ikm, hashfunc) == prk
    assert hkdf_expand(prk, info, length, hashfunc) == okm
    assert hkdf(salt, ikm, info, length, hashfunc) == okm


def test_hkdf_accepts_hash_instance():
    import hashlib

    ikm = unhexlify("0b" * 22)
    result_constructor = hkdf(b"", ikm, b"", 42, hashlib.sha256)
    result_instance = hkdf(b"", ikm, b"", 42, hashlib.sha256())
    assert result_constructor == result_instance


def test_hkdf_zero_length_rejected():
    import hashlib

    with pytest.raises(HKDFError):
        hkdf(b"", b"ikm", b"", 0, hashlib.sha256)


def test_hkdf_negative_length_rejected():
    import hashlib

    with pytest.raises(HKDFError):
        hkdf(b"", b"ikm", b"", -1, hashlib.sha256)


def test_hkdf_non_integer_length_rejected():
    import hashlib

    with pytest.raises(HKDFError):
        hkdf(b"", b"ikm", b"", 42.0, hashlib.sha256)


def test_hkdf_bool_length_rejected():
    import hashlib

    with pytest.raises(HKDFError):
        hkdf(b"", b"ikm", b"", True, hashlib.sha256)


def test_hkdf_too_long_length_rejected():
    import hashlib

    with pytest.raises(HKDFError):
        hkdf(b"", b"ikm", b"", 255 * 32 + 1, hashlib.sha256)


def test_hkdf_short_prk_rejected():
    import hashlib

    with pytest.raises(HKDFError):
        hkdf_expand(b"\x00" * 31, b"", 42, hashlib.sha256)


def test_hkdf_invalid_hashfunc_rejected():
    with pytest.raises(HKDFError):
        hkdf(b"", b"ikm", b"", 42, None)


def test_hkdf_invalid_info_type_rejected():
    import hashlib

    with pytest.raises(HKDFError):
        hkdf(b"", b"ikm", u"not-bytes", 42, hashlib.sha256)


def test_hkdf_different_salt_info_length_change_output():
    import hashlib

    ikm = unhexlify("0b" * 22)
    base = hkdf(b"salt", ikm, b"info", 42, hashlib.sha256)
    assert hkdf(b"salt", ikm, b"info", 41, hashlib.sha256) == base[:41]
    assert hkdf(b"salt", ikm, b"other", 42, hashlib.sha256) != base
    assert hkdf(b"other", ikm, b"info", 42, hashlib.sha256) != base
