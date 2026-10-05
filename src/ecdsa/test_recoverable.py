"""
Tests for compact, recoverable ECDSA signatures.

A recoverable signature consists of the regular ECDSA parameters ``r``
and ``s`` plus a one byte :term:`recovery ID` that identifies the public
key of the signer. The high level API supports secp256k1 and NIST256p.
"""

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import hashlib

from .keys import (
    SigningKey,
    VerifyingKey,
    BadSignatureError,
    BadDigestError,
    InvalidRecoveryError,
)
from .curves import NIST256p, SECP256k1, NIST192p
from .ecdsa import (
    Signature,
    Private_key,
    Public_key,
    InvalidPointError,
    ellipticcurve,
    generator_112r2,
)
from .util import (
    number_to_string,
    string_to_number,
    sigencode_string_recoverable,
    sigdecode_string_recoverable,
    MalformedSignature,
)


# A fixed private exponent so the signatures below are reproducible.
SECRET_EXPONENT = int(
    "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6724", 16
)

DIGEST = hashlib.sha256(b"recoverable-ecdsa").digest()
DIGEST_NUMBER = string_to_number(DIGEST)

# Deterministic (RFC6979), low-s recoverable signatures of DIGEST.
FIXED_SIGNATURES = {
    "SECP256k1": bytes.fromhex(
        "016d207801bc9cc9e74c3ba23df3ac7bcf5e6ba71af994436d5874dcc380f48a86"
        "6aec5ca4be81c6354ed1558004e680d03957ebb842d93990d09616b4d5968001"
    ),
    "NIST256p": bytes.fromhex(
        "012d66537af8b93b1b2a04586e0dda84e59e45914d5d5c9d1713cbb0e3c2e2820a"
        "5c32713ed86ea138f5bc76a503e569e71b7b3f472184042143f87ebd74cc874b"
    ),
}

# A digest for which RFC6979 produces a high-s signature on secp256k1.
FLIP_K1_DIGEST = hashlib.sha256(b"flip-1").digest()
FLIP_K1_RAW = bytes.fromhex(
    "00c47dbab943f02043f05c8f1a2cbd5335a82452fe913edcfe558d9f2ab0251f74"
    "c9c3b4274628f943c5881e8c146743c367178b099e0ce3e7cb9a181fbef2e2c1"
)
FLIP_K1_LOW = bytes.fromhex(
    "01c47dbab943f02043f05c8f1a2cbd5335a82452fe913edcfe558d9f2ab0251f74"
    "363c4bd8b9d706bc3a77e173eb98bc3b539751dd113bbc53f438466d11435e80"
)

# Same kind of vector for NIST256p (sha256(b"flip-0")).
FLIP_P256_DIGEST = hashlib.sha256(b"flip-0").digest()
FLIP_P256_RAW = bytes.fromhex(
    "015dad81ec00fc21b4eb29cdb90a51b137bf1b9302ee1fa12cd451481d306ebcb"
    "18db485817cc9767dc60ec1f8d14a85de145a03f67c2d18db3e3439c84a9f9db9"
)
FLIP_P256_LOW = bytes.fromhex(
    "005dad81ec00fc21b4eb29cdb90a51b137bf1b9302ee1fa12cd451481d306ebcb"
    "1724b7a7d8336898339f13e072eb57a21a88cf6b72aea85a9b58590fab1c38798"
)


class TestRecoverableCodec(unittest.TestCase):
    """Tests for the recoverable signature byte encoding."""

    order = NIST256p.order

    def test_roundtrip(self):
        encoded = sigencode_string_recoverable(
            0x1234, 0x5678, 2, self.order
        )
        self.assertEqual(encoded[0], 2)
        r, s, recovery_id = sigdecode_string_recoverable(encoded, self.order)
        self.assertEqual((r, s, recovery_id), (0x1234, 0x5678, 2))

    def test_length_is_two_base_lengths_plus_one(self):
        encoded = sigencode_string_recoverable(1, 1, 0, self.order)
        self.assertEqual(len(encoded), 1 + 2 * NIST256p.baselen)

    def test_encode_rejects_invalid_recovery_id(self):
        for recovery_id in (-1, 4, 255):
            with self.assertRaises(MalformedSignature):
                sigencode_string_recoverable(1, 1, recovery_id, self.order)

    def test_decode_rejects_bad_length(self):
        encoded = sigencode_string_recoverable(1, 1, 0, self.order)
        for tampered in (b"", encoded[:-1], encoded + b"\x00"):
            with self.assertRaises(MalformedSignature):
                sigdecode_string_recoverable(tampered, self.order)

    def test_decode_rejects_invalid_recovery_byte(self):
        encoded = bytearray(
            sigencode_string_recoverable(1, 1, 0, self.order)
        )
        encoded[0] = 4
        with self.assertRaises(MalformedSignature):
            sigdecode_string_recoverable(bytes(encoded), self.order)

    def test_values_are_fixed_length_big_endian(self):
        # the r and s fields are fixed length, big endian numbers; setting
        # the last byte is decoded as a small value
        encoded = bytearray(
            sigencode_string_recoverable(0, 0xFF, 3, self.order)
        )
        r, s, recovery_id = sigdecode_string_recoverable(
            bytes(encoded), self.order
        )
        self.assertEqual((r, s, recovery_id), (0, 0xFF, 3))


class TestHighLevelRecoverableECDSA(unittest.TestCase):
    """End to end tests over SECP256k1 and NIST256p."""

    def _key(self, curve):
        return SigningKey.from_secret_exponent(
            SECRET_EXPONENT, curve=curve, hashfunc=hashlib.sha256
        )

    def test_fixed_vectors_are_reproducible(self):
        for curve in (SECP256k1, NIST256p):
            sk = self._key(curve)
            first = sk.sign_digest_recoverable(
                DIGEST, hashfunc=hashlib.sha256
            )
            second = sk.sign_digest_recoverable(
                DIGEST, hashfunc=hashlib.sha256
            )
            self.assertEqual(first, second)
            self.assertEqual(
                first, FIXED_SIGNATURES[curve.name]
            )

    def test_signature_length_and_low_s_form(self):
        for curve in (SECP256k1, NIST256p):
            sk = self._key(curve)
            signature = sk.sign_digest_recoverable(
                DIGEST, hashfunc=hashlib.sha256, low_s=True
            )
            self.assertEqual(len(signature), 1 + 2 * curve.baselen)
            _, s, _ = sigdecode_string_recoverable(
                signature, curve.order
            )
            self.assertLessEqual(s, curve.order // 2)

    def test_recover_returns_signer_key(self):
        for curve in (SECP256k1, NIST256p):
            sk = self._key(curve)
            vk = sk.get_verifying_key()
            signature = FIXED_SIGNATURES[curve.name]
            recovered = (
                VerifyingKey
                .from_public_key_recovery_recoverable_with_digest(
                    signature, DIGEST, curve, hashfunc=hashlib.sha256
                )
            )
            self.assertEqual(recovered.curve, curve)
            self.assertEqual(recovered.pubkey.point, vk.pubkey.point)

    def test_recovered_key_verifies_with_plain_verify_digest(self):
        # The recovered public key must validate the signature through
        # the regular, independent verification path (raw r||s encoding).
        for curve in (SECP256k1, NIST256p):
            signature = FIXED_SIGNATURES[curve.name]
            recovered = (
                VerifyingKey
                .from_public_key_recovery_recoverable_with_digest(
                    signature, DIGEST, curve, hashfunc=hashlib.sha256
                )
            )
            raw_signature = signature[1:]
            self.assertTrue(
                recovered.verify_digest(raw_signature, DIGEST)
            )

    def test_sign_and_recover_over_data(self):
        data = b"service to service message"
        digest = hashlib.sha256(data).digest()
        for curve in (SECP256k1, NIST256p):
            sk = SigningKey.generate(curve=curve)
            vk = sk.get_verifying_key()
            signature = sk.sign_recoverable(
                data, hashfunc=hashlib.sha256
            )
            recovered = (
                VerifyingKey
                .from_public_key_recovery_recoverable(
                    signature, data, curve, hashfunc=hashlib.sha256
                )
            )
            self.assertEqual(recovered.pubkey.point, vk.pubkey.point)
            self.assertTrue(
                recovered.verify_digest(signature[1:], digest)
            )

    def test_low_s_flips_recovery_id_parity_bit(self):
        # When s is normalised, negating it negates R and so the y parity
        # bit of the recovery ID has to change as well; replacing just s
        # with n-s (leaving the recovery ID untouched) is wrong.
        for curve, raw, low in (
            (SECP256k1, FLIP_K1_RAW, FLIP_K1_LOW),
            (NIST256p, FLIP_P256_RAW, FLIP_P256_LOW),
        ):
            digest = (
                FLIP_K1_DIGEST if curve is SECP256k1 else FLIP_P256_DIGEST
            )
            rr, rs, rid_raw = sigdecode_string_recoverable(
                raw, curve.order
            )
            lr, ls, rid_low = sigdecode_string_recoverable(
                low, curve.order
            )
            self.assertEqual(rr, lr)
            self.assertGreater(rs, curve.order // 2)
            self.assertEqual(ls, curve.order - rs)
            self.assertLessEqual(ls, curve.order // 2)
            self.assertEqual(rid_raw ^ 1, rid_low)

            # just negating s without adjusting the recovery ID does not
            # recover the signer's key
            sk = self._key(curve)
            vk = sk.get_verifying_key()
            wrong = (
                bytes([rid_raw])
                + number_to_string(lr, curve.order)
                + number_to_string(ls, curve.order)
            )
            recovered_wrong = (
                VerifyingKey
                .from_public_key_recovery_recoverable_with_digest(
                    wrong, digest, curve, hashfunc=hashlib.sha256
                )
            )
            self.assertNotEqual(
                recovered_wrong.pubkey.point, vk.pubkey.point
            )

            # both correct encodings recover the actual signer
            for signature in (raw, low):
                recovered = (
                    VerifyingKey
                    .from_public_key_recovery_recoverable_with_digest(
                        signature,
                        digest,
                        curve,
                        hashfunc=hashlib.sha256,
                    )
                )
                self.assertEqual(
                    recovered.pubkey.point, vk.pubkey.point
                )

    def test_wrong_recovery_id_does_not_return_signer(self):
        for curve in (SECP256k1, NIST256p):
            sk = self._key(curve)
            vk = sk.get_verifying_key()
            signature = bytearray(FIXED_SIGNATURES[curve.name])
            signature[0] ^= 1
            recovered = (
                VerifyingKey
                .from_public_key_recovery_recoverable_with_digest(
                    bytes(signature),
                    DIGEST,
                    curve,
                    hashfunc=hashlib.sha256,
                )
            )
            # the first recovery candidate must not be mistaken for the key
            self.assertNotEqual(
                recovered.pubkey.point, vk.pubkey.point
            )

    def test_unrecoverable_x_candidate_rejected(self):
        # on 256 bit curves r + n is outside of the field, so bit 1 of the
        # recovery ID can never be set
        for curve in (SECP256k1, NIST256p):
            signature = bytearray(FIXED_SIGNATURES[curve.name])
            for recovery_id in (2, 3):
                signature[0] = recovery_id
                with self.assertRaises(InvalidRecoveryError):
                    (
                        VerifyingKey
                        .from_public_key_recovery_recoverable_with_digest(
                            bytes(signature),
                            DIGEST,
                            curve,
                            hashfunc=hashlib.sha256,
                        )
                    )

    def test_recovery_byte_out_of_range_is_bad_signature(self):
        for curve in (SECP256k1, NIST256p):
            signature = bytearray(FIXED_SIGNATURES[curve.name])
            signature[0] = 4
            with self.assertRaises(BadSignatureError):
                (
                    VerifyingKey
                    .from_public_key_recovery_recoverable_with_digest(
                        bytes(signature),
                        DIGEST,
                        curve,
                        hashfunc=hashlib.sha256,
                    )
                )

    def test_bad_signature_length_is_bad_signature(self):
        for curve in (SECP256k1, NIST256p):
            signature = FIXED_SIGNATURES[curve.name]
            for tampered in (signature[:-1], signature + b"\x00"):
                with self.assertRaises(BadSignatureError):
                    (
                        VerifyingKey
                        .from_public_key_recovery_recoverable_with_digest(
                            tampered,
                            DIGEST,
                            curve,
                            hashfunc=hashlib.sha256,
                        )
                    )

    def test_r_and_s_out_of_range(self):
        order = NIST256p.order
        valid_r = number_to_string(0x1234, order)
        valid_s = number_to_string(0x5678, order)
        zero = number_to_string(0, order)
        n_value = number_to_string(order, order)
        for bad_r, bad_s in (
            (zero, valid_s),
            (n_value, valid_s),
            (valid_r, zero),
            (valid_r, n_value),
        ):
            signature = b"\x00" + bad_r + bad_s
            with self.assertRaises(InvalidRecoveryError):
                (
                    VerifyingKey
                    .from_public_key_recovery_recoverable_with_digest(
                        signature,
                        DIGEST,
                        NIST256p,
                        hashfunc=hashlib.sha256,
                    )
                )

    def test_digest_truncation_matches_verify_digest(self):
        # A SHA-384 digest is longer than the NIST256p order; both signing
        # and recovery/re-verification must truncate it the same way.
        digest = hashlib.sha384(b"truncation vector").digest()
        sk = self._key(NIST256p)
        vk = sk.get_verifying_key()
        signature = sk.sign_digest_recoverable(
            digest,
            hashfunc=hashlib.sha384,
            allow_truncate=True,
        )
        recovered = (
            VerifyingKey
            .from_public_key_recovery_recoverable_with_digest(
                signature,
                digest,
                NIST256p,
                hashfunc=hashlib.sha384,
                allow_truncate=True,
            )
        )
        self.assertEqual(recovered.pubkey.point, vk.pubkey.point)
        self.assertTrue(
            recovered.verify_digest(
                signature[1:], digest, allow_truncate=True
            )
        )

    def test_long_digest_rejected_without_truncation(self):
        digest = hashlib.sha384(b"truncation vector").digest()
        sk = self._key(NIST256p)
        with self.assertRaises(BadDigestError):
            sk.sign_digest_recoverable(
                digest, hashfunc=hashlib.sha384, allow_truncate=False
            )
        signature = sk.sign_digest_recoverable(
            digest, hashfunc=hashlib.sha384, allow_truncate=True
        )
        with self.assertRaises(BadDigestError):
            (
                VerifyingKey
                .from_public_key_recovery_recoverable_with_digest(
                    signature,
                    digest,
                    NIST256p,
                    hashfunc=hashlib.sha384,
                    allow_truncate=False,
                )
            )

    def test_unsupported_curve_rejected(self):
        sk = SigningKey.generate(curve=NIST192p)
        with self.assertRaises(ValueError):
            sk.sign_digest_recoverable(
                hashlib.sha256(b"x").digest(), hashfunc=hashlib.sha256
            )
        with self.assertRaises(ValueError):
            VerifyingKey.from_public_key_recovery_recoverable_with_digest(
                b"\x00" * (1 + 2 * NIST192p.baselen),
                hashlib.sha256(b"x").digest(),
                NIST192p,
            )

    def test_custom_codec_roundtrip(self):
        def encode(r, s, recovery_id, order):
            return recovery_id, r, s, order

        def decode(signature, order):
            recovery_id, r, s, signature_order = signature
            self.assertEqual(signature_order, order)
            return r, s, recovery_id

        sk = self._key(NIST256p)
        signature = sk.sign_digest_recoverable(
            DIGEST, hashfunc=hashlib.sha256, sigencode=encode
        )
        recovered = (
            VerifyingKey
            .from_public_key_recovery_recoverable_with_digest(
                signature,
                DIGEST,
                NIST256p,
                hashfunc=hashlib.sha256,
                sigdecode=decode,
            )
        )
        self.assertEqual(
            recovered.pubkey.point, sk.get_verifying_key().pubkey.point
        )


class TestLowLevelRecoverableSignature(unittest.TestCase):
    """Tests for the low level Signature/Private_key recovery API."""

    def test_sign_recoverable_roundtrip_secp256k1(self):
        curve = SECP256k1
        generator = curve.generator
        sk = SigningKey.from_secret_exponent(
            SECRET_EXPONENT, curve=curve, hashfunc=hashlib.sha256
        )
        private_key = sk.privkey
        r, s, recovery_id = private_key.sign_recoverable(
            DIGEST_NUMBER, 0x1234567
        )
        signature = Signature(r, s)
        public_key = signature.recover_public_key(
            DIGEST_NUMBER, generator, recovery_id
        )
        self.assertEqual(public_key.point, sk.get_verifying_key().pubkey.point)
        self.assertTrue(public_key.verifies(DIGEST_NUMBER,
                                            signature))

    def test_recover_public_keys_uses_parity_bit(self):
        # the legacy helper returns both y parity candidates, neither of
        # them is guaranteed to be the signer's key on its own
        curve = SECP256k1
        sk = SigningKey.from_secret_exponent(
            SECRET_EXPONENT, curve=curve, hashfunc=hashlib.sha256
        )
        r, s, recovery_id = sk.privkey.sign_recoverable(
            DIGEST_NUMBER, 0x98765
        )
        candidates = Signature(r, s).recover_public_keys(
            DIGEST_NUMBER, curve.generator
        )
        self.assertEqual(len(candidates), 2)
        # the recovery ID, not the order of the candidates, identifies it
        actual = Signature(r, s).recover_public_key(
            DIGEST_NUMBER,
            curve.generator,
            recovery_id,
        )
        self.assertEqual(actual.point, sk.get_verifying_key().pubkey.point)

    def test_recovery_id_out_of_range(self):
        generator = SECP256k1.generator
        for recovery_id in (-1, 4, 5):
            with self.assertRaises(InvalidRecoveryError):
                Signature(1, 1).recover_public_key(
                    1, generator, recovery_id
                )

    def test_r_s_range_enforced(self):
        order = SECP256k1.order
        generator = SECP256k1.generator
        for r, s in ((0, 1), (order, 1), (1, 0), (1, order)):
            with self.assertRaises(InvalidRecoveryError):
                Signature(r, s).recover_public_key(1, generator, 0)

    def test_non_existent_point_rejected(self):
        # r=5 does not correspond to any point on secp256k1 and r=2 does
        # not correspond to any point on NIST256p
        for curve, r in ((SECP256k1, 5), (NIST256p, 2)):
            for recovery_id in (0, 1):
                with self.assertRaises(InvalidRecoveryError):
                    Signature(r, 1).recover_public_key(
                        1, curve.generator, recovery_id
                    )

    def test_x_candidate_outside_field_rejected(self):
        # r = n - 1 makes r + n >= p for both curves, so bit 1 of the
        # recovery ID cannot select such a candidate
        for curve in (SECP256k1, NIST256p):
            for recovery_id in (2, 3):
                with self.assertRaises(InvalidRecoveryError):
                    Signature(curve.order - 1, 1).recover_public_key(
                        1, curve.generator, recovery_id
                    )

    def test_point_at_infinity_rejected(self):
        # a tiny toy curve (p = 97, order = 79, cofactor 1) lets us build
        # a deterministic tuple that recovers the point at infinity:
        # R = G (x = 1), s = z makes s*R - z*G = O
        curve = ellipticcurve.CurveFp(97, 0, 7, 1)
        generator = ellipticcurve.PointJacobi(
            curve, 1, 69, 1, 79, generator=True
        )
        with self.assertRaises(InvalidRecoveryError):
            Signature(1, 1).recover_public_key(1, generator, 1)

    def test_bit_one_selects_x_candidate(self):
        # on the same toy curve the gap p - order is large enough for
        # x = r + order to be a real point, exercising bit 1 of the ID
        curve = ellipticcurve.CurveFp(97, 0, 7, 1)
        order = 79
        generator = ellipticcurve.PointJacobi(
            curve, 1, 69, 1, order, generator=True
        )
        signer = Private_key(Public_key(generator, generator), 1)
        for nonce, r, s, recovery_id in (
            (9, 17, 2, 2),
            (22, 3, 72, 3),
        ):
            nr, ns, nid = signer.sign_recoverable(1, nonce)
            self.assertEqual((nr, ns, nid), (r, s, recovery_id))
            public_key = Signature(r, s).recover_public_key(
                1, generator, recovery_id
            )
            self.assertEqual(public_key.point, generator)
            # the j = 0 candidate must not be presented as the signer
            parity_only = recovery_id & 1
            try:
                wrong = Signature(r, s).recover_public_key(
                    1, generator, parity_only
                )
            except InvalidRecoveryError:
                continue
            self.assertNotEqual(wrong.point, generator)

    def test_bit_one_is_not_the_parity_bit(self):
        # regression test: the candidate index j occupies bit 1, it must
        # not be OR-ed directly into the low bits of the recovery ID
        curve = ellipticcurve.CurveFp(97, 0, 7, 1)
        generator = ellipticcurve.PointJacobi(
            curve, 1, 69, 1, 79, generator=True
        )
        signer = Private_key(Public_key(generator, generator), 1)
        _, _, recovery_id = signer.sign_recoverable(1, 9)
        self.assertEqual(recovery_id, 2)

    def test_recovered_key_must_have_correct_order(self):
        # secp112r2 has cofactor 4; an ephemeral point from a different
        # coset leads to a public key outside of the generator group
        generator = generator_112r2
        with self.assertRaises(InvalidRecoveryError):
            Signature(2, 13).recover_public_key(7, generator, 0)

    def test_recovered_key_must_validate_signature(self):
        # same curve, a point in another coset gives a public key inside
        # of the group but still unable to validate the signature
        with self.assertRaises(InvalidRecoveryError):
            Signature(2, 67890).recover_public_key(
                12345, generator_112r2, 0
            )

    def test_invalid_point_error_is_recovery_error(self):
        # sanity check that the wrapping class is the one users get
        self.assertTrue(issubclass(InvalidPointError, RuntimeError))
        self.assertTrue(issubclass(InvalidRecoveryError, RuntimeError))
