"""Tests for the independent BIP 32 module."""

import hashlib
import os

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from . import bip32
from .bip32 import (
    HARDENED_INDEX,
    MAX_INDEX,
    ExtendedKey,
    InvalidExtendedKeyError,
    InvalidPathError,
    InvalidSeedError,
    HardPublicDerivationError,
    base58_encode,
    base58_decode,
    base58check_encode,
    base58check_decode,
    parse_path,
    master_key_from_seed,
)
from .curves import SECP256k1


# BIP 32 test vector 1 (seed 00010203...0f). The private keys, chain codes
# and compressed public keys are the values published in BIP 32.
V1_SEED = bytes(bytearray(range(16)))

V1_CHAIN = {
    "m": "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
    "m/0H": (
        "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
    ),
    "m/0H/1": (
        "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
    ),
}

V1_PRIV = {
    "m": "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    "m/0H": (
        "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
    ),
    "m/0H/1": (
        "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
    ),
}

# The official base58 serialisations from BIP 32 test vector 1.
V1_XPRV_M = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvv"
    "NKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)

# A simple known answer for hash160 of the empty input via SHA-256.
RIPEMD160_OF_SHA256_EMPTY = (
    "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
)


class Hash160Tests(unittest.TestCase):
    def test_hash160_known_answer(self):
        # hash160 = RIPEMD160(SHA-256(data))
        digest = bip32.hash160(b"")
        self.assertEqual(digest.hex(), RIPEMD160_OF_SHA256_EMPTY)

    def test_hash160_abc(self):
        expected = hashlib.new(
            "ripemd160", hashlib.sha256(b"abc").digest()
        ).digest()
        self.assertEqual(bip32.hash160(b"abc"), expected)



class Base58Tests(unittest.TestCase):
    def test_roundtrip(self):
        for data in (b"", b"\x00", b"\x00\x00abc", os.urandom(40),
                     b"\xff" * 32):
            encoded = base58_encode(data)
            self.assertEqual(base58_decode(encoded), data)

    def test_leading_zeroes(self):
        self.assertEqual(base58_decode(b"1112"), b"\x00\x00\x00\x01")

    def test_invalid_character(self):
        self.assertRaises(
            InvalidExtendedKeyError, base58_decode, b"0OIlbad"
        )

    def test_checksum_roundtrip(self):
        data = os.urandom(78)
        encoded = base58check_encode(data)
        self.assertEqual(base58check_decode(encoded), data)

    def test_bad_checksum(self):
        data = b"\x04\x88\xad\xe4" + b"\x00" * 74
        encoded = bytearray(base58check_encode(data))
        encoded[-1] = ord("Z") if encoded[-1] != ord("Z") else ord("y")
        self.assertRaises(
            InvalidExtendedKeyError,
            base58check_decode,
            bytes(encoded),
        )


class PathTests(unittest.TestCase):
    def test_absolute(self):
        self.assertEqual(parse_path("m"), ())
        self.assertEqual(parse_path("M/0"), (0,))
        self.assertEqual(parse_path("m/0/1"), (0, 1))

    def test_relative(self):
        self.assertEqual(parse_path("0/1"), (0, 1))
        self.assertEqual(parse_path((0, 1)), (0, 1))

    def test_hardened_markers(self):
        expected = (0, HARDENED_INDEX + 1, HARDENED_INDEX + 2)
        self.assertEqual(parse_path("m/0/1'/2h"), expected)
        self.assertEqual(parse_path("m/0/1H/2P"), expected)

    def test_invalid(self):
        for bad in ("m/", "m//0", "m/0/", "0+1", "m/abc",
                    "m/2147483648", "m/4294967296", "m/-1", "m/0/"):
            self.assertRaises(InvalidPathError, parse_path, bad)

    def test_requires_hardened_marker(self):
        self.assertRaises(
            InvalidPathError, parse_path, "m/2147483648"
        )


class MasterKeyTests(unittest.TestCase):
    def setUp(self):
        self.master = master_key_from_seed(V1_SEED)

    def test_master_values(self):
        self.assertEqual(
            self.master.chain_code.hex(), V1_CHAIN["m"]
        )
        self.assertEqual(
            "%064x" % self.master.private_exponent, V1_PRIV["m"]
        )

    def test_master_serialization(self):
        self.assertEqual(
            self.master.export_key().decode("ascii"), V1_XPRV_M
        )

    def test_master_metadata(self):
        self.assertEqual(self.master.depth, 0)
        self.assertEqual(self.master.child_number, 0)
        self.assertEqual(self.master.parent_fingerprint, b"\x00" * 4)

    def test_bad_seed_length(self):
        self.assertRaises(InvalidSeedError, master_key_from_seed, b"")
        self.assertRaises(
            InvalidSeedError, master_key_from_seed, b"\x00" * 15
        )
        self.assertRaises(
            InvalidSeedError, master_key_from_seed, b"\x00" * 65
        )

    def test_testnet_version(self):
        testnet = master_key_from_seed(V1_SEED, testnet=True)
        self.assertEqual(
            testnet.version, bip32.TESTNET_PRIVATE
        )
        self.assertEqual(
            testnet.neuter().version, bip32.TESTNET_PUBLIC
        )


class DerivationTests(unittest.TestCase):
    def setUp(self):
        self.master = master_key_from_seed(V1_SEED)

    def test_hardened_derivation(self):
        child = self.master.child(HARDENED_INDEX)
        self.assertEqual(child.depth, 1)
        self.assertEqual(child.child_number, HARDENED_INDEX)
        self.assertEqual(child.chain_code.hex(), V1_CHAIN["m/0H"])
        self.assertEqual(
            "%064x" % child.private_exponent, V1_PRIV["m/0H"]
        )
        self.assertEqual(child.parent_fingerprint,
                         self.master.fingerprint)

    def test_non_hardened_derivation(self):
        child = self.master.child(HARDENED_INDEX).child(1)
        self.assertEqual(child.depth, 2)
        self.assertEqual(child.chain_code.hex(), V1_CHAIN["m/0H/1"])
        self.assertEqual(
            "%064x" % child.private_exponent, V1_PRIV["m/0H/1"]
        )

    def test_derive_path_string(self):
        child = self.master.derive("m/0H/1")
        self.assertEqual(
            "%064x" % child.private_exponent, V1_PRIV["m/0H/1"]
        )

    def test_getitem(self):
        child = self.master[HARDENED_INDEX]
        self.assertEqual(
            child.chain_code.hex(), V1_CHAIN["m/0H"]
        )

    def test_public_and_private_derivation_match(self):
        # neuter(parent) -> child must equal neuter(parent -> child) for
        # non-hardened indices.
        for index in (0, 1, 2, 1000):
            private_parent = self.master.child(HARDENED_INDEX)
            public_parent = private_parent.neuter()
            via_public = public_parent.child(index)
            via_private = private_parent.child(index).neuter()
            self.assertEqual(
                via_public.serialize(), via_private.serialize()
            )

    def test_hardened_from_public_fails(self):
        public = self.master.neuter()
        self.assertRaises(
            HardPublicDerivationError,
            public.child,
            HARDENED_INDEX,
        )

    def test_derived_public_equals_private_times_g(self):
        child = self.master.derive("m/0H/1/2H")
        expected_point = (
            SECP256k1.generator * child.private_exponent
        )
        self.assertEqual(child._public_point, expected_point)

    def test_invalid_child_index(self):
        self.assertRaises(
            InvalidPathError, self.master.child, MAX_INDEX + 1
        )
        self.assertRaises(InvalidPathError, self.master.child, -1)
        self.assertRaises(InvalidPathError, self.master.child, "0")


class SerializationTests(unittest.TestCase):
    def setUp(self):
        self.master = master_key_from_seed(V1_SEED)

    def test_xprv_xpub_roundtrip(self):
        for key in (self.master, self.master.neuter()):
            serialized = key.serialize()
            self.assertEqual(len(serialized), 78)
            decoded = ExtendedKey.deserialize(serialized)
            self.assertEqual(decoded.serialize(), serialized)

    def test_base58_roundtrip(self):
        key = self.master.derive("m/0H/1")
        text = key.export_key()
        decoded = ExtendedKey.from_key(text)
        self.assertEqual(decoded.export_key(), text)

    def test_xprv_to_xpub(self):
        private = self.master.child(HARDENED_INDEX)
        public = private.neuter()
        self.assertFalse(public.is_private())
        self.assertEqual(public.compressed_public_key,
                         private.compressed_public_key)
        self.assertEqual(public.chain_code, private.chain_code)
        self.assertEqual(public.depth, private.depth)

    def test_unknown_version_rejected(self):
        raw = bytearray(self.master.serialize())
        raw[0:4] = b"\xde\xad\xbe\xef"
        self.assertRaises(
            InvalidExtendedKeyError,
            ExtendedKey.deserialize,
            bytes(raw),
        )

    def test_private_key_pad_byte(self):
        raw = bytearray(self.master.serialize())
        raw[45] = 0x01
        self.assertRaises(
            InvalidExtendedKeyError,
            ExtendedKey.deserialize,
            bytes(raw),
        )

    def test_bad_public_prefix(self):
        public_raw = bytearray(self.master.neuter().serialize())
        public_raw[45] = 0x04
        self.assertRaises(
            InvalidExtendedKeyError,
            ExtendedKey.deserialize,
            bytes(public_raw),
        )

    def test_signing_and_verifying_key(self):
        private = self.master.child(0)
        signing = private.to_signing_key()
        self.assertEqual(
            signing.to_string(),
            bip32._i2o256(private.private_exponent),
        )
        verifying = private.neuter().to_verifying_key()
        self.assertEqual(
            verifying.to_string("compressed"),
            private.compressed_public_key,
        )


if __name__ == "__main__":
    unittest.main()
