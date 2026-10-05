# -*- coding: utf-8 -*-
# Tests for the BIP 340 Schnorr signature implementation in `schnorr.py`.
#
# The official BIP 340 test vectors (bips.xyz/340, "test-vectors.csv") are
# used as the primary acceptance data. The exact 32-byte values for the
# "special" rows are derived deterministically from the curve constants with
# the same construction the BIP generator script uses, then checked against
# the verbatim hexadecimal that appears in the official CSV. The fully-valid
# vector (official CSV index 0) plus an extra fixed-aux-rand vector are
# pinned byte-for-byte.
from __future__ import division

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from . import schnorr
from .schnorr import (
    p,
    n,
    G,
    tagged_hash,
    lift_x,
    sign,
    verify,
    SchnorrSigningKey,
    SchnorrPublicKey,
    InvalidPrivateKeyError,
    InvalidPublicKeyError,
    InvalidSignatureError,
)
from .keys import BadSignatureError, SigningKey, VerifyingKey
from .curves import SECP256k1


def h(value):
    return bytes(bytearray.fromhex(value))


ZERO = b"\x00" * 32


# Official BIP 340 test-vectors.csv index 0 (valid, sk = 3).
OFFICIAL_0 = dict(
    sk=h("0000000000000000000000000000000000000000000000000000000000000003"),
    pubkey=h(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    ),
    aux=ZERO,
    msg=ZERO,
    sig=h(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    ),
)


def _on_curve(x):
    c = (pow(x, 3, p) + 7) % p
    y = pow(c, (p + 1) // 4, p)
    return (y * y) % p == c


def _f(k):
    # Official generator helper: on-curve x at/above n + k*(p-n)/4.
    candidate = n + k * (p - n) // 4
    while not _on_curve(candidate):
        candidate += 1
    return candidate


def _special_rows():
    rows = []
    # rows 5..8: x = p-1+i for i=0..3 (p-1 happens to be off-curve too).
    for k in range(4):
        rows.append((5 + k, (p - 1 + k).to_bytes(32, "big")))
    # rows 9..12: on-curve points whose x coordinate is >= n.
    for k in range(4):
        rows.append((9 + k, _f(k).to_bytes(32, "big")))
    # rows 13..14: pubkey derived from invalid scalars d=0 and d=n.
    for index, scalar in ((13, 0), (14, n)):
        rows.append(
            (index, tagged_hash(b"sk", scalar.to_bytes(32, "big")))
        )
    result = []
    for index, pubkey in rows:
        msg = tagged_hash(b"msg", pubkey)
        try:
            SchnorrPublicKey(pubkey)
            kind = "sig"
        except InvalidPublicKeyError:
            kind = "pub"
        result.append((index, pubkey, msg, kind))
    return result


SPECIAL_ROWS = _special_rows()


# Verbatim hex of the official CSV rows 5..14 (x-only pubkey, message),
# guarding the construction against drift from the published vectors.
OFFICIAL_SPECIAL_HEX = {
    5: ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
        "ac4e9bf3cee798f661e36aad681bdbb122d71ab3720414bdd26abf0ef5fb8041"),
    6: ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        "fbb45455339bf6d11838218f6f2c28a117999c667870fc94a619cd232ba81f68"),
    7: ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
        "cee66f693bd6a1df5dac5d7d80d5f9f00c8bcc7231eab75d6be439d6afb1612e"),
    8: ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc31",
        "955dd2a95008a0b28999006b8220d111acd157e535ab00abce50af3a54449450"),
    9: ("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        "2fa128284e4402aa8830f61c33384c209b921f0f084facb43f8915825b59086f"),
    10: ("ffffffffffffffffffffffffffffffff0c0325ad0376782ccfddc6e95c28affc",
         "b95d664d486ba1ffa7ea1dfe12780c52ccc725bed252e2bbca18468a291f4734"),
    11: ("ffffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f45e81b1eb8",
         "9462e8d58359f346075a359a6c47a41f4bba1cbf300649a3b816e7ff85d6046a"),
    12: ("ffffffffffffffffffffffffffffffffaeabb739abd2280eeff497a2740d8d74",
         "6269ff60492191a914cbad2cb92ecd34c3c694f34b00d9c1b99c5c2a634b00d3"),
    13: ("0a28fc1d349f1aa70bedeefbdef639c31cafc6272f3c5405290302120b674417",
         "09a838bee5c86f9eec4825e0c5727b63c4d1f74aa2b541c4548f2e0031da0901"),
    14: ("07778f7c58334303e3d1e484799eff917980634754328d3c729c1bbb1fffd39d",
         "842b402ea3f65ce927ed8d0c3a174b445b16bd041b3ec37da11dcf4b5df7b373"),
}

class TestTaggedHash(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(
            tagged_hash(b"BIP0340/challenge", b"").hex(),
            "c216d352f5818b7b4beacd4ae0a26fe888080823d2a598856661bcd54f1b3713",
        )
        self.assertEqual(
            tagged_hash(b"BIP0340/nonce", b"").hex(),
            "5301f1001a8be6253a3583927793565cef360de8bac2bdcbf37b195e699435a8",
        )
        self.assertEqual(
            tagged_hash(b"BIP0340/aux", b"").hex(),
            "07fab5f97e680abb8389d1fa164281e124439468f5bd699fcbd1ae86e6405d69",
        )


class TestOfficialVectors(unittest.TestCase):
    def test_row0_verify(self):
        self.assertTrue(
            verify(OFFICIAL_0["pubkey"], OFFICIAL_0["sig"], OFFICIAL_0["msg"])
        )

    def test_row0_sign_reproduces_official(self):
        key = SchnorrSigningKey.from_string(OFFICIAL_0["sk"])
        self.assertEqual(key.to_string(), OFFICIAL_0["sk"])
        self.assertEqual(
            key.get_verifying_key().to_string(), OFFICIAL_0["pubkey"]
        )
        self.assertEqual(
            key.sign(OFFICIAL_0["msg"], OFFICIAL_0["aux"]), OFFICIAL_0["sig"]
        )

    def test_special_rows_match_official_hex(self):
        by_index = {row[0]: row for row in SPECIAL_ROWS}
        self.assertEqual(sorted(by_index), list(range(5, 15)))
        for index, (pub_hex, msg_hex) in OFFICIAL_SPECIAL_HEX.items():
            _, pubkey, msg, _ = by_index[index]
            self.assertEqual(pubkey.hex(), pub_hex, index)
            self.assertEqual(msg.hex(), msg_hex, index)

    def test_special_rows_all_rejected(self):
        for index, pubkey, msg, kind in SPECIAL_ROWS:
            if kind == "pub":
                self.assertRaises(
                    InvalidPublicKeyError, SchnorrPublicKey, pubkey
                )
            else:
                key = SchnorrPublicKey(pubkey)
                # Official CSV signature column is empty for these rows.
                self.assertRaises(InvalidSignatureError, key.verify, b"", msg)

    def test_special_rows_reject_zero_signature(self):
        zero_sig = b"\x00" * 64
        for index, pubkey, msg, kind in SPECIAL_ROWS:
            if kind == "pub":
                self.assertRaises(
                    InvalidPublicKeyError, SchnorrPublicKey, pubkey
                )
                continue
            key = SchnorrPublicKey(pubkey)
            self.assertRaises(
                InvalidSignatureError, key.verify, zero_sig, msg
            )


class TestFixedAuxVector(unittest.TestCase):
    """An extra reproducible signature with non-zero msg and aux."""

    sk = h("0000000000000000000000000000000000000000000000000000000000000003")
    msg = h("0000000000000000000000000000000000000000000000000000000000000001")
    aux = h("0000000000000000000000000000000000000000000000000000000000000002")
    sig = h(
        "69CF6FCF4D3F1F4DCBC1C802E516E2173B8D219F86C2CBC00DBED8FB0461D660"
        "5F36DDA65E9D45EAA4B1772F1C570EB5A3FC8F9D2C0EFCB02E76D3617FF49993"
    )

    def test_sign_is_reproducible(self):
        first = sign(self.sk, self.msg, self.aux)
        second = sign(self.sk, self.msg, self.aux)
        self.assertEqual(first, self.sig)
        self.assertEqual(second, self.sig)

    def test_verify_fixed_vector(self):
        pubkey = SchnorrSigningKey.from_string(self.sk).get_verifying_key()
        self.assertTrue(pubkey.verify(self.sig, self.msg))

    def test_different_aux_changes_signature(self):
        other = sign(self.sk, self.msg, ZERO)
        self.assertNotEqual(other, self.sig)
        self.assertTrue(
            verify(
                OFFICIAL_0["pubkey"], other, self.msg
            )
        )


class TestRoundTrip(unittest.TestCase):
    def test_random_round_trip(self):
        import os

        for _ in range(3):
            key = SchnorrSigningKey.generate(entropy=os.urandom)
            msg = os.urandom(32)
            signature = key.sign(msg)
            self.assertTrue(
                key.get_verifying_key().verify(signature, msg)
            )
            self.assertTrue(
                verify(key.get_verifying_key().to_string(), signature, msg)
            )

    def test_wrong_message_rejected(self):
        key = SchnorrSigningKey.generate()
        signature = key.sign(b"a" * 32)
        self.assertRaises(
            InvalidSignatureError,
            key.get_verifying_key().verify,
            signature,
            b"b" * 32,
        )

    def test_wrong_pubkey_rejected(self):
        key1 = SchnorrSigningKey(12345)
        key2 = SchnorrSigningKey(67890)
        signature = key1.sign(b"m" * 32, b"r" * 32)
        self.assertRaises(
            InvalidSignatureError,
            key2.get_verifying_key().verify,
            signature,
            b"m" * 32,
        )

    def test_flip_each_byte_is_rejected_or_differs(self):
        key = SchnorrSigningKey(12345)
        msg = b"q" * 32
        signature = bytearray(key.sign(msg, b"x" * 32))
        for pos in range(64):
            tampered = bytearray(signature)
            tampered[pos] ^= 0x01
            try:
                result = key.get_verifying_key().verify(bytes(tampered), msg)
            except InvalidSignatureError:
                result = False
            self.assertFalse(result, pos)


class TestParityNormalization(unittest.TestCase):
    def test_negated_scalar_same_xonly_key(self):
        even = SchnorrSigningKey(3)
        odd = SchnorrSigningKey(n - 3)
        # The raw point for n-3 has an odd y, while the point for 3 has an
        # even y; both normalize to the same x-only public key.
        self.assertTrue(((n - 3) * G).y() & 1)
        self.assertFalse((3 * G).y() & 1)
        self.assertEqual(
            even.get_verifying_key().to_string(),
            odd.get_verifying_key().to_string(),
        )

    def test_negated_scalar_signatures_verify(self):
        msg = b"\x00" * 31 + b"\x01"
        aux = b"\x00" * 31 + b"\x02"
        for scalar in (3, n - 3):
            key = SchnorrSigningKey(scalar)
            signature = key.sign(msg, aux)
            self.assertTrue(
                verify(key.get_verifying_key().to_string(), signature, msg)
            )

    def test_even_y_of_generator(self):
        # G has odd y, so lifting its x yields a different (even) point.
        lifted = lift_x(G.x())
        self.assertEqual(lifted.y() & 1, 0)
        self.assertEqual(lifted.x(), G.x())


class TestRangesAndPoints(unittest.TestCase):
    def test_private_scalar_zero(self):
        self.assertRaises(InvalidPrivateKeyError, SchnorrSigningKey, 0)

    def test_private_scalar_n(self):
        self.assertRaises(InvalidPrivateKeyError, SchnorrSigningKey, n)

    def test_private_scalar_above_n(self):
        self.assertRaises(InvalidPrivateKeyError, SchnorrSigningKey, n + 1)

    def test_private_scalar_negative(self):
        self.assertRaises(InvalidPrivateKeyError, SchnorrSigningKey, -1)

    def test_pubkey_x_p(self):
        self.assertRaises(
            InvalidPublicKeyError,
            SchnorrPublicKey,
            p.to_bytes(32, "big"),
        )

    def test_pubkey_x_off_curve(self):
        # x = p-1: in range but y^2 has no root for secp256k1.
        self.assertRaises(
            InvalidPublicKeyError,
            SchnorrPublicKey,
            (p - 1).to_bytes(32, "big"),
        )

    def test_pubkey_wrong_length(self):
        self.assertRaises(ValueError, SchnorrPublicKey, b"\x02" * 31)
        self.assertRaises(ValueError, SchnorrPublicKey, b"\x02" * 33)

    def test_message_must_be_32_bytes(self):
        key = SchnorrSigningKey(1)
        for bad in (b"", b"a" * 31, b"a" * 33):
            self.assertRaises(ValueError, key.sign, bad, b"a" * 32)
            self.assertRaises(
                ValueError, key.get_verifying_key().verify, b"\x00" * 64, bad
            )

    def test_aux_must_be_32_bytes(self):
        key = SchnorrSigningKey(1)
        for bad in (b"", b"a" * 31, b"a" * 33):
            self.assertRaises(ValueError, key.sign, b"m" * 32, bad)

    def test_signature_wrong_length(self):
        key = SchnorrSigningKey(1).get_verifying_key()
        self.assertRaises(
            InvalidSignatureError, key.verify, b"\x00" * 63, b"m" * 32
        )
        self.assertRaises(
            InvalidSignatureError, key.verify, b"\x00" * 65, b"m" * 32
        )

    def test_r_equal_p_rejected(self):
        # r == p is out of range even though s is valid.
        signature = p.to_bytes(32, "big") + b"\x01" * 32
        key = SchnorrSigningKey(1).get_verifying_key()
        self.assertRaises(
            InvalidSignatureError, key.verify, signature, b"m" * 32
        )

    def test_s_equal_n_rejected(self):
        # r == 0 lifts to G? r=0 is a valid x (point on curve); s == n is out
        # of range and must be rejected before any equation is evaluated.
        signature = b"\x00" * 32 + n.to_bytes(32, "big")
        key = SchnorrSigningKey(1).get_verifying_key()
        self.assertRaises(
            InvalidSignatureError, key.verify, signature, b"m" * 32
        )

    def test_r_off_curve_rejected(self):
        # r = p-1 is in range but does not lift to a curve point.
        signature = (p - 1).to_bytes(32, "big") + b"\x01" * 32
        key = SchnorrSigningKey(1).get_verifying_key()
        self.assertRaises(
            InvalidSignatureError, key.verify, signature, b"m" * 32
        )

    def test_invalid_signature_is_bad_signature(self):
        # Schnorr failure is also a library-wide BadSignatureError.
        self.assertTrue(
            issubclass(InvalidSignatureError, BadSignatureError)
        )
        key = SchnorrSigningKey(1).get_verifying_key()
        try:
            key.verify(b"\x00" * 64, b"m" * 32)
        except BadSignatureError:
            pass
        else:  # pragma: no cover
            self.fail("expected BadSignatureError")


class TestSecretSafety(unittest.TestCase):
    def test_repr_has_no_scalar(self):
        scalar = 123456789
        key = SchnorrSigningKey(scalar)
        rendered = repr(key)
        self.assertNotIn(format(scalar, "x"), rendered)
        self.assertNotIn(format(scalar, "064x"), rendered)
        self.assertNotIn("123456789", rendered)
        self.assertIn(
            key.get_verifying_key().to_string().hex(), rendered
        )

    def test_error_messages_have_no_scalar(self):
        scalar = 987654321
        for bad in (0, n, n + 1, -5):
            try:
                SchnorrSigningKey(bad)
            except InvalidPrivateKeyError as exc:
                message = str(exc)
                self.assertNotIn(format(scalar, "x"), message)
                self.assertNotIn("987654321", message)

    def test_to_string_roundtrip_does_not_leak_in_repr(self):
        key = SchnorrSigningKey(42)
        restored = SchnorrSigningKey.from_string(key.to_string())
        self.assertEqual(key, restored)
        # repr must only show the public key, never the scalar bytes.
        self.assertEqual(key.to_string().hex()[:8], "00000000")
        self.assertNotIn(key.to_string().hex(), repr(key))


class TestInterfaceSeparation(unittest.TestCase):
    """A 64-byte BIP340 signature must never be consumed as an ECDSA one."""

    def test_ecdsa_interface_does_not_accept_schnorr_signature(self):
        import hashlib

        key = SchnorrSigningKey(7)
        signature = key.sign(b"m" * 32, b"a" * 32)
        # Build an ECDSA verifying key from the *compressed* SEC1 encoding
        # of the same x-only key (0x02 prefix selects the even y).
        ecdsa_key = VerifyingKey.from_string(
            b"\x02" + key.get_verifying_key().to_string(), curve=SECP256k1
        )
        # Interpreted as an ECDSA signature over SHA-256(m), the 64-byte
        # BIP340 signature must never validate as an ECDSA signature.
        self.assertRaises(
            BadSignatureError,
            ecdsa_key.verify,
            signature,
            b"m" * 32,
            hashfunc=hashlib.sha256,
        )

    def test_schnorr_interface_rejects_der_ecdsa_signature(self):
        import hashlib
        from .util import sigencode_der

        ecdsa_signing_key = SigningKey.generate(curve=SECP256k1)
        der_signature = ecdsa_signing_key.sign_deterministic(
            b"m" * 32, hashfunc=hashlib.sha256, sigencode=sigencode_der
        )
        compressed = ecdsa_signing_key.get_verifying_key().to_string(
            "compressed"
        )
        xonly = compressed[1:]
        verifying_key = SchnorrPublicKey(xonly)
        # The DER framing makes the encoding 70-72 bytes, never the fixed
        # 64-byte BIP340 layout, so Schnorr verification rejects it outright.
        self.assertNotEqual(len(der_signature), 64)
        self.assertRaises(
            InvalidSignatureError,
            verifying_key.verify,
            der_signature,
            b"m" * 32,
        )

    def test_schnorr_and_ecdsa_are_distinct_entry_points(self):
        self.assertTrue(hasattr(schnorr, "sign"))
        self.assertTrue(hasattr(schnorr, "verify"))
        self.assertIs(schnorr.sign, sign)
        self.assertIs(schnorr.verify, verify)
        # SigningKey.sign (ECDSA) is a bound method on a different class.
        ecdsa_key = SigningKey.generate(curve=SECP256k1)
        self.assertIsNot(ecdsa_key.sign, SchnorrSigningKey.sign)


class TestIndependentReference(unittest.TestCase):
    """Cross-check signatures with a standalone BIP340 verifier.

    This re-implements the verification equation with the low-level point
    arithmetic instead of the production ``verify`` path, so an error shared
    by both the signer and the production verifier is still caught.
    """

    @staticmethod
    def _reference_verify(pubkey, signature, msg):
        import hashlib
        from . import ecdsa as _ecdsa
        from .ellipticcurve import PointJacobi

        prime = _ecdsa.curve_secp256k1.p()
        order = _ecdsa.generator_secp256k1.order()
        generator = _ecdsa.generator_secp256k1

        def tagged(tag, data):
            digest = hashlib.sha256(tag).digest()
            return hashlib.sha256(digest + digest + data).digest()

        def lift(x):
            c = (pow(x, 3, prime) + 7) % prime
            y = pow(c, (prime + 1) // 4, prime)
            assert (y * y) % prime == c
            if y & 1:
                y = prime - y
            return PointJacobi(_ecdsa.curve_secp256k1, x, y, 1, order)

        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        px = int.from_bytes(pubkey, "big")
        assert r < prime and s < order
        e = int.from_bytes(
            tagged(b"BIP0340/challenge", signature[:32] + pubkey + msg),
            "big",
        ) % order
        R = lift(r)
        P = lift(px)
        return s * generator == R + e * P

    def test_official_row0_against_reference(self):
        self.assertTrue(
            self._reference_verify(
                OFFICIAL_0["pubkey"], OFFICIAL_0["sig"], OFFICIAL_0["msg"]
            )
        )

    def test_fixed_aux_vector_against_reference(self):
        vector = TestFixedAuxVector
        self.assertTrue(
            self._reference_verify(
                OFFICIAL_0["pubkey"], vector.sig, vector.msg
            )
        )
