"""Tests for the BIP 32 hierarchical deterministic key derivation."""

import struct
from binascii import unhexlify

import pytest

from . import bip32
from .bip32 import (
    HARDENED,
    MAX_INDEX,
    ORDER,
    HDPrivateKey,
    HDPublicKey,
    InvalidExtendedKeyError,
    InvalidPathError,
    HardenedDerivationError,
    DerivationError,
    parse_path,
)
from .ellipticcurve import INFINITY


# BIP 32 test vector 1 (seed 000102030405060708090a0b0c0d0e0f).
VECTOR1_SEED = unhexlify(b"000102030405060708090a0b0c0d0e0f")
VECTOR1_COMPONENTS = ["0h", "1", "2h", "2", "1000000000"]
VECTOR1_XPRV = [
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChk"
    "VvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV"
    "1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu5"
    "3Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
    "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT"
    "7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
    "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8R"
    "fQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
    "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmH"
    "ScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
]
VECTOR1_XPUB = [
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ2"
    "9ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LH"
    "hwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkN"
    "AWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJP"
    "MM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
    "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyi"
    "LjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
    "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcY"
    "FgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
]

# BIP 32 test vector 2 (a mostly non-hardened chain).
VECTOR2_SEED = unhexlify(
    b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
    b"9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
)
VECTOR2_MASTER_XPUB = (
    "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6o"
    "DMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
)


def _vector1_chain():
    """Return the master key and the keys along the vector 1 path."""
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    nodes = [master]
    current = master
    for component in VECTOR1_COMPONENTS:
        current, _ = current.derive_path(component)
        nodes.append(current)
    return master, nodes


def test_vector1_private_serialisation():
    _, nodes = _vector1_chain()
    assert [str(key) for key in nodes] == VECTOR1_XPRV


def test_vector1_public_serialisation():
    _, nodes = _vector1_chain()
    assert [str(key.neuter()) for key in nodes] == VECTOR1_XPUB


def test_vector1_roundtrip_through_base58():
    _, nodes = _vector1_chain()
    for private, public in zip(nodes, VECTOR1_XPRV):
        decoded = HDPrivateKey.deserialize(public)
        assert decoded == private
        assert bip32.deserialize(public) == private
        decoded_public = HDPublicKey.deserialize(str(private.neuter()))
        assert decoded_public == private.neuter()


def test_vector2_master_public_serialisation():
    master = HDPrivateKey.from_seed(VECTOR2_SEED)
    assert str(master.neuter()) == VECTOR2_MASTER_XPUB
    assert master.fingerprint().hex() == "bd16bee5"


def test_master_metadata():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    assert master.depth == 0
    assert master.child_number == 0
    assert master.parent_fingerprint == b"\x00" * 4
    assert len(master.chain_code) == 32
    assert master.fingerprint().hex() == "3442193e"
    assert not master.is_hardened

    child, used = master.derive(HARDENED + 7)
    assert used == HARDENED + 7
    assert child.depth == 1
    assert child.child_number == HARDENED + 7
    assert child.is_hardened and child.index == 7
    assert child.parent_fingerprint == master.fingerprint()

    grandchild, _ = child.derive(3)
    assert grandchild.depth == 2
    assert grandchild.parent_fingerprint == child.fingerprint()
    assert not grandchild.is_hardened


def test_derive_path_reports_used_indexes():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    child, used = master.derive_path("m/0'/1/2h/2/1000000000")
    assert used == [HARDENED, 1, HARDENED + 2, 2, 1000000000]
    assert str(child) == VECTOR1_XPRV[-1]


def test_neuter_and_derive_commute_for_nonhardened():
    # The required property:
    # neuter(derive(private)) == derive(neuter(private)).
    master = HDPrivateKey.from_seed(VECTOR1_SEED)

    private_child, index_p = master.derive(5)
    public_child, index_x = master.neuter().derive(5)
    assert index_p == index_x == 5
    assert private_child.neuter() == public_child

    private_chain, _ = master.derive_path("1/2/3")
    public_chain, _ = master.neuter().derive_path("1/2/3")
    assert private_chain.neuter() == public_chain

    # A non-hardened suffix is derivable from the neutered prefix.
    hardened, _ = master.derive_path("7h/4")
    neutered_prefix, _ = master.derive_path("7h")
    tail, _ = neutered_prefix.neuter().derive(4)
    assert hardened.neuter() == tail


def test_hardened_public_derivation_fails():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    public = master.neuter()
    with pytest.raises(HardenedDerivationError):
        public.derive(HARDENED)
    with pytest.raises(HardenedDerivationError):
        public.derive(HARDENED + 1)
    with pytest.raises(HardenedDerivationError):
        public.derive_path("0h")
    # the private key can still derive hardened children
    private_child, _ = master.derive(HARDENED)
    assert private_child.is_hardened


def test_private_retries_out_of_range_index():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    real_hmac = bip32._hmac_sha512

    def forced_invalid(key, data):
        # Only the first attempted index (0) is faked as out of range.
        if len(data) == 37 and data[-4:] == struct.pack(">I", 0):
            return b"\xff" * 32 + b"\x11" * 32
        return real_hmac(key, data)

    bip32._hmac_sha512 = forced_invalid
    try:
        child, used = master.derive(0)
    finally:
        bip32._hmac_sha512 = real_hmac

    expected, _ = master.derive(1)
    assert used == 1
    assert child.child_number == 1
    assert child == expected


def test_public_retries_point_at_infinity():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    public = master.neuter()
    real_hmac = bip32._hmac_sha512
    # IL = -k_par makes IL*G + K_par the point at infinity.
    infinity_il = (-master.private_key) % ORDER
    forced = infinity_il.to_bytes(32, "big") + b"\x22" * 32

    def forced_infinity(key, data):
        if data[-4:] == struct.pack(">I", 0):
            return forced
        return real_hmac(key, data)

    bip32._hmac_sha512 = forced_infinity
    try:
        child, used = public.derive(0)
    finally:
        bip32._hmac_sha512 = real_hmac

    assert used == 1
    assert child.child_number == 1


def test_derivation_exhausted_at_last_index():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    real_hmac = bip32._hmac_sha512
    call_count = {"n": 0}

    def always_invalid(key, data):
        call_count["n"] += 1
        return b"\xff" * 64

    bip32._hmac_sha512 = always_invalid
    try:
        with pytest.raises(DerivationError):
            master.derive(MAX_INDEX)
        assert call_count["n"] == 1
        with pytest.raises(DerivationError):
            master.neuter().derive(HARDENED - 1)
        # just the single failed attempt, no billion-index busy loop
        assert call_count["n"] == 2
    finally:
        bip32._hmac_sha512 = real_hmac


def test_maximum_depth_rejected():
    deep = HDPrivateKey(
        1,
        b"\x01" * 32,
        depth=255,
        parent_fingerprint=b"\x01\x02\x03\x04",
        child_number=1,
    )
    with pytest.raises(DerivationError):
        deep.derive(0)
    with pytest.raises(DerivationError):
        deep.neuter().derive(0)


def test_invalid_seed_length():
    with pytest.raises(ValueError):
        HDPrivateKey.from_seed(b"\x00" * 15)
    with pytest.raises(ValueError):
        HDPrivateKey.from_seed(b"\x00" * 65)


def test_invalid_construction():
    with pytest.raises(ValueError):
        HDPrivateKey(0, b"\x01" * 32)
    with pytest.raises(ValueError):
        HDPrivateKey(ORDER, b"\x01" * 32)
    with pytest.raises(ValueError):
        HDPrivateKey(1, b"\x01" * 31)
    with pytest.raises(ValueError):
        HDPublicKey(INFINITY, b"\x01" * 32)
    with pytest.raises(ValueError):
        HDPrivateKey(1, b"\x01" * 32, depth=0,
                     parent_fingerprint=b"\x01\x02\x03\x04")

@pytest.mark.parametrize(
    "path,expected",
    [
        ("m", []),
        ("M", []),
        ("m/0", [0]),
        ("0/1", [0, 1]),
        ("m/0'/1h/2H/3", [HARDENED, HARDENED + 1, HARDENED + 2, 3]),
        ("m/2147483647", [2147483647]),
        ("m/2147483647h", [MAX_INDEX]),
        (b"m/0", [0]),
    ],
)
def test_parse_path_valid(path, expected):
    assert parse_path(path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "",
        "   ",
        "m/",
        "/0",
        "x/0",
        "m//0",
        "m/0/",
        "m/a",
        "m/0x1",
        "m/-1",
        "m/2147483648",
        "m/2147483648h",
        "eval(1)",
        "__import__('os')",
    ],
)
def test_parse_path_invalid(path):
    with pytest.raises(InvalidPathError):
        parse_path(path)


def test_derive_rejects_bad_index_type():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    for bad in (1.0, -1, 1 << 32, True, "1"):
        with pytest.raises((InvalidPathError, TypeError)):
            master.derive(bad)
        with pytest.raises((InvalidPathError, TypeError)):
            master.neuter().derive(bad)


def _corrupt_master_serialised(master):
    raw = bip32.b58decode_check(master.serialize())
    return raw


def test_import_rejects_unknown_version():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    raw = _corrupt_master_serialised(master)
    bad = b"\xff\xff\xff\xff" + raw[4:]
    with pytest.raises(InvalidExtendedKeyError):
        bip32.deserialize(bip32.b58encode_check(bad))


def test_import_rejects_bad_checksum():
    with pytest.raises(InvalidExtendedKeyError):
        bip32.deserialize(
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChk"
            "VvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHj"
        )


def test_import_rejects_bad_base58_character():
    with pytest.raises(InvalidExtendedKeyError):
        bip32.deserialize("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stb0")


def test_import_rejects_inconsistent_depth():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    raw = _corrupt_master_serialised(master)

    # depth 1 but parent fingerprint and child number left as zero
    bad = raw[:4] + b"\x01" + raw[5:]
    with pytest.raises(InvalidExtendedKeyError):
        bip32.deserialize(bip32.b58encode_check(bad))

    # depth 0 but with a non-zero child number
    bad = raw[:9] + b"\x00\x00\x00\x01" + raw[13:]
    with pytest.raises(InvalidExtendedKeyError):
        bip32.deserialize(bip32.b58encode_check(bad))


def test_import_rejects_wrong_private_marker():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    raw = _corrupt_master_serialised(master)
    bad = raw[:45] + b"\x01" + raw[46:]
    with pytest.raises(InvalidExtendedKeyError):
        HDPrivateKey.deserialize(bip32.b58encode_check(bad))


def test_import_rejects_private_scalar_zero():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    raw = _corrupt_master_serialised(master)
    bad = raw[:46] + b"\x00" * 32
    with pytest.raises(InvalidExtendedKeyError):
        HDPrivateKey.deserialize(bip32.b58encode_check(bad))


def test_import_rejects_non_curve_public_point():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    raw = _corrupt_master_serialised(master.neuter())
    # flip the odd/even byte to a value other than 0x02/0x03
    bad = raw[:45] + b"\x04" + raw[46:]
    with pytest.raises(InvalidExtendedKeyError):
        HDPublicKey.deserialize(bip32.b58encode_check(bad))


def test_import_wrong_key_kind():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    with pytest.raises(InvalidExtendedKeyError):
        HDPrivateKey.deserialize(str(master.neuter()))
    with pytest.raises(InvalidExtendedKeyError):
        HDPublicKey.deserialize(str(master))


def test_import_preserves_network():
    testnet_master = HDPrivateKey.from_seed(
        VECTOR1_SEED, network="testnet"
    )
    assert str(testnet_master).startswith("tprv")
    assert str(testnet_master.neuter()).startswith("tpub")
    decoded = bip32.deserialize(str(testnet_master))
    assert decoded.network == "testnet"
    assert decoded == testnet_master


def test_signing_key_unchanged_interface():
    master = HDPrivateKey.from_seed(VECTOR1_SEED)
    signing_key = master.to_signing_key()
    message = b"bip32-message"
    signature = signing_key.sign(message)
    assert signing_key.get_verifying_key().verify(signature, message)
    assert signing_key.get_verifying_key().pubkey.point == (
        master.public_point().to_affine()
    )


def test_base58_roundtrip():
    values = [b"", b"\x00", b"\x00\x00abc", b"\xff" * 40]
    for value in values:
        encoded = bip32.b58encode(value)
        assert bip32.b58decode(encoded) == value
        checked = bip32.b58encode_check(value)
        assert bip32.b58decode_check(checked) == value
