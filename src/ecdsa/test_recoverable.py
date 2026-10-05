from binascii import unhexlify
from hashlib import sha256, sha512

import pytest
from six import int2byte

from . import ecdsa
from .curves import BRAINPOOLP160r1, NIST256p, SECP256k1
from .keys import BadDigestError, SigningKey, VerifyingKey
from .recoverable import recover_public_key, sign_recoverable_digest
from .util import (
    MalformedSignature,
    number_to_string,
    sigdecode_string_recoverable,
    sigencode_string_recoverable,
    string_to_number,
)


PRIVATE_EXPONENT = int(
    "1234567890abcdef1234567890abcdef"
    "1234567890abcdef1234567890abcdef",
    16,
)
NONCE = int(
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef",
    16,
)
DIGEST = sha256(b"recoverable ecdsa vector").digest()
LONG_DIGEST = sha512(b"recoverable ecdsa truncation").digest()

VECTORS = [
    (
        SECP256k1,
        "4646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8ff"
        "f267d8641a8fa3092067e385fc3c7d5168a8a448f4323f29d91f055ed2f8cd6ca"
        "00",
    ),
    (
        NIST256p,
        "d8cd12ea5c67f2f8a00c1124893edcfa6754c4d6cede6be13bdf2295c810a97"
        "f200c8ed87eca6a6ea3a1cdefa3d8862792a5f30e0ebe7e3b156ca007d960ab94"
        "01",
    ),
]

HIGH_S_VECTORS = [
    (
        SECP256k1,
        "4646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8ff"
        "fd98279be5705cf6df981c7a03c382ae8302498576c24ad9e2de2089fa0a96a77"
        "01",
    ),
    (
        NIST256p,
        "d8cd12ea5c67f2f8a00c1124893edcfa6754c4d6cede6be13bdf2295c810a97"
        "fdff37126813595925c5e32105c2779d82a41079f98592049de4d2abb230279bd"
        "00",
    ),
]


def signing_key(curve):
    return SigningKey.from_secret_exponent(
        PRIVATE_EXPONENT, curve, sha256
    )


@pytest.mark.parametrize("curve,signature_hex", VECTORS)
def test_fixed_recoverable_vector(curve, signature_hex):
    signature = unhexlify(signature_hex)
    sk = signing_key(curve)

    assert (
        sign_recoverable_digest(
            sk, DIGEST, k=NONCE, low_s=True
        )
        == signature
    )

    vk = recover_public_key(signature, DIGEST, curve, sha256)

    assert vk == sk.get_verifying_key()
    assert vk.verify_digest(signature[:-1], DIGEST)


@pytest.mark.parametrize("curve,high_s_hex", HIGH_S_VECTORS)
def test_low_s_adjusts_recovery_id(curve, high_s_hex):
    sk = signing_key(curve)
    high_s = unhexlify(high_s_hex)

    assert sign_recoverable_digest(
        sk, DIGEST, k=NONCE, low_s=False
    ) == high_s

    low_s = sign_recoverable_digest(
        sk, DIGEST, k=NONCE, low_s=True
    )
    assert low_s[-1] == high_s[-1] ^ 1
    assert string_to_number(low_s[32:64]) <= curve.order // 2

    rewritten = low_s[:-1] + int2byte(high_s[-1])
    wrong_vk = recover_public_key(rewritten, DIGEST, curve, sha256)

    assert wrong_vk != sk.get_verifying_key()


@pytest.mark.parametrize("curve,signature_hex", VECTORS)
def test_recovery_id_selects_exact_candidate(curve, signature_hex):
    signature = unhexlify(signature_hex)
    sk = signing_key(curve)
    expected_vk = sk.get_verifying_key()

    alternate_id = signature[-1] ^ 1
    alternate = signature[:-1] + int2byte(alternate_id)
    alternate_vk = recover_public_key(
        alternate, DIGEST, curve, sha256
    )

    assert alternate_vk != expected_vk
    assert (
        VerifyingKey.from_recoverable_signature_digest(
            signature, DIGEST, curve, sha256
        )
        == expected_vk
    )


@pytest.mark.parametrize("curve,signature_hex", VECTORS)
def test_recovery_ids_for_unavailable_x_candidate(curve, signature_hex):
    signature = unhexlify(signature_hex)

    for recovery_id in (2, 3):
        invalid = signature[:-1] + int2byte(recovery_id)
        with pytest.raises(ecdsa.InvalidRecoveryIdError):
            recover_public_key(invalid, DIGEST, curve, sha256)


def test_recovery_id_outside_protocol_range():
    signature = unhexlify(VECTORS[0][1])[:-1]
    for recovery_id in (4, 255):
        with pytest.raises(MalformedSignature):
            recover_public_key(
                signature + int2byte(recovery_id),
                DIGEST,
                SECP256k1,
                sha256,
            )


@pytest.mark.parametrize("curve", (SECP256k1, NIST256p))
def test_signature_length_is_validated(curve):
    signature = unhexlify(VECTORS[0 if curve == SECP256k1 else 1][1])

    for invalid in (
        signature[:-1],
        signature + b"\x00",
        signature[:32] + signature[33:],
    ):
        with pytest.raises(MalformedSignature):
            recover_public_key(invalid, DIGEST, curve, sha256)


@pytest.mark.parametrize("curve", (SECP256k1, NIST256p))
@pytest.mark.parametrize(
    "r,s",
    [
        (0, 1),
        (None, 1),
        (1, 0),
        (None, None),
    ],
)
def test_r_and_s_ranges_are_validated(curve, r, s):
    if r is None:
        r = curve.order
    if s is None:
        s = curve.order
    signature = (
        number_to_string(r, curve.order)
        + number_to_string(s, curve.order)
        + b"\x00"
    )

    with pytest.raises(MalformedSignature):
        recover_public_key(signature, DIGEST, curve, sha256)


@pytest.mark.parametrize("curve", (SECP256k1, NIST256p))
def test_recovery_id_must_select_a_valid_point(curve):
    non_residue_x = 5 if curve == SECP256k1 else 1
    signature = (
        number_to_string(non_residue_x, curve.order)
        + number_to_string(1, curve.order)
        + b"\x00"
    )

    with pytest.raises(ecdsa.InvalidRecoveryIdError):
        recover_public_key(signature, DIGEST, curve, sha256)


def test_digest_truncation_matches_verify_digest():
    curve = NIST256p
    sk = signing_key(curve)
    signature = sk.sign_recoverable_digest(
        LONG_DIGEST, k=NONCE, allow_truncate=True
    )

    with pytest.raises(BadDigestError):
        recover_public_key(
            signature, LONG_DIGEST, curve, sha512
        )

    vk = recover_public_key(
        signature,
        LONG_DIGEST,
        curve,
        sha512,
        allow_truncate=True,
    )

    assert vk == sk.get_verifying_key()
    assert vk.verify_digest(
        signature[:-1], LONG_DIGEST, allow_truncate=True
    )


@pytest.mark.parametrize("curve", (SECP256k1, NIST256p))
def test_random_recoverable_signature_round_trip(curve):
    sk = SigningKey.generate(curve=curve, hashfunc=sha256)
    signature = sk.sign_recoverable_digest(
        DIGEST, low_s=False
    )

    assert len(signature) == 65
    vk = VerifyingKey.from_recoverable_signature_digest(
        signature, DIGEST, curve, sha256
    )

    assert vk == sk.get_verifying_key()


@pytest.mark.parametrize("curve", (SECP256k1, NIST256p))
def test_message_recoverable_signature_round_trip(curve):
    sk = SigningKey.generate(curve=curve, hashfunc=sha256)
    data = b"recoverable message"
    signature = sk.sign_recoverable(
        data, k=NONCE, hashfunc=sha256
    )

    vk = VerifyingKey.from_recoverable_signature(
        signature, data, curve, sha256
    )

    assert vk == sk.get_verifying_key()
    assert vk.verify(signature[:-1], data, hashfunc=sha256)


def test_only_prime_order_curves_supported_in_first_version():
    sk = SigningKey.generate(curve=BRAINPOOLP160r1)
    with pytest.raises(ValueError):
        sign_recoverable_digest(sk, DIGEST)
    with pytest.raises(ValueError):
        recover_public_key(
            b"\x00" * 41, DIGEST, BRAINPOOLP160r1
        )


def test_compact_codec_rejects_invalid_values():
    order = SECP256k1.order

    with pytest.raises(MalformedSignature):
        sigencode_string_recoverable(0, 1, 0, order)
    with pytest.raises(MalformedSignature):
        sigencode_string_recoverable(1, 0, 0, order)
    with pytest.raises(MalformedSignature):
        sigencode_string_recoverable(1, 1, 4, order)

    encoded = sigencode_string_recoverable(1, 1, 3, order)
    assert sigdecode_string_recoverable(encoded, order) == (1, 1, 3)
