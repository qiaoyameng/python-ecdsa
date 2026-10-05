"""
BIP 340 Schnorr signatures over the secp256k1 curve.

This module is a self-contained implementation of `BIP 340
<https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>`_.
It reuses the existing secp256k1 curve arithmetic from
:py:mod:`ecdsa.ecdsa` and :py:mod:`ecdsa.ellipticcurve`, but it is
intentionally a *separate* public entry point from the ECDSA API in
:py:mod:`ecdsa.keys`: a 64 byte BIP 340 signature (``R.x || s``) and a
64 byte raw ECDSA signature (``r || s``, see
:py:func:`ecdsa.util.sigencode_string`) are different formats and must
never be passed to each other's verification functions.

Message length
--------------
Per the current revision of BIP 340 (the original draft limited messages
to 32 bytes; that restriction was lifted in the 2020-08 revision), the
message is a byte string of *arbitrary* length. Messages are **not**
pre-hashed by this module, and callers must not pre-hash them either:
the message bytes are fed directly into the BIP 340 tagged hashes inside
the signing and verification algorithms. Hashing the message first would
produce a signature for a different protocol.

Scope
-----
Only single-signature verification is implemented, exactly as specified
in BIP 340. No batch verification algorithm is provided.
"""

import hashlib
import os

from . import ellipticcurve
from .ecdsa import curve_secp256k1, generator_secp256k1
from ._compat import (
    bytes_to_int,
    int_to_bytes,
    compat26_str,
)

__all__ = [
    "SchnorrError",
    "InvalidSecretKeyError",
    "InvalidPublicKeyError",
    "PrivateKey",
    "PublicKey",
    "pubkey_from_secret",
    "sign",
    "verify",
]


class SchnorrError(ValueError):
    """Base class for BIP 340 Schnorr signature errors."""

    pass


class InvalidSecretKeyError(SchnorrError):
    """Raised when a secret key is malformed or out of range."""

    pass


class InvalidPublicKeyError(SchnorrError):
    """Raised when a public key is malformed or not on the curve."""

    pass


_curve = curve_secp256k1
_G = generator_secp256k1
_p = _curve.p()
_n = _G.order()


def _sha256(data):
    return hashlib.sha256(compat26_str(data)).digest()


def _tagged_hash(tag, msg):
    """BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    tag_hash = _sha256(tag)
    return _sha256(tag_hash + tag_hash + msg)


def _bytes(num):
    """Encode an integer as a 32 byte big-endian string."""
    return bytes(int_to_bytes(num, 32, "big"))


def _lift_x(x_coord):
    """
    Return the point with the given x coordinate and even y, or None.

    Returns None when ``x_coord >= p`` or when no curve point with that
    x coordinate exists.
    """
    if x_coord >= _p:
        return None
    y_sq = (pow(x_coord, 3, _p) + 7) % _p
    y = pow(y_sq, (_p + 1) // 4, _p)
    if pow(y, 2, _p) != y_sq:
        return None
    if y % 2 != 0:
        y = _p - y
    return ellipticcurve.PointJacobi(_curve, x_coord, y, 1, _n)


def _secret_to_int(secret_key):
    """Validate a 32 byte secret key and return it as an integer."""
    secret_key = compat26_str(secret_key)
    if len(secret_key) != 32:
        raise InvalidSecretKeyError(
            "Secret key must be 32 bytes, got {0}".format(len(secret_key))
        )
    secret = bytes_to_int(secret_key, "big")
    if not 1 <= secret < _n:
        raise InvalidSecretKeyError(
            "Secret key must be an integer in the range 1..n-1"
        )
    return secret


def pubkey_from_secret(secret_key):
    """
    Compute the 32 byte x-only BIP 340 public key for a secret key.

    ``secret_key`` must be a 32 byte string encoding an integer in the
    range 1..n-1. Returns the 32 byte big-endian encoding of the x
    coordinate of the public key point.
    """
    secret = _secret_to_int(secret_key)
    public_point = secret * _G
    return _bytes(public_point.x())


def sign(message, secret_key, aux_rand=None):
    """
    Create a 64 byte BIP 340 Schnorr signature over ``message``.

    ``message`` is a byte string of arbitrary length (see the module
    docstring); it is hashed internally with the BIP 340 tagged hashes
    and must not be pre-hashed by the caller.

    ``secret_key`` must be a 32 byte string encoding an integer in the
    range 1..n-1.

    ``aux_rand`` must be a 32 byte string of auxiliary random data, as
    specified by BIP 340. When not provided, fresh randomness from
    :func:`os.urandom` is used. Providing a fixed ``aux_rand`` makes the
    signature reproducible.

    Returns the 64 byte signature ``R.x || s``.
    """
    message = compat26_str(message)
    secret = _secret_to_int(secret_key)
    if aux_rand is None:
        aux_rand = os.urandom(32)
    aux_rand = compat26_str(aux_rand)
    if len(aux_rand) != 32:
        raise ValueError(
            "aux_rand must be 32 bytes, got {0}".format(len(aux_rand))
        )

    public_point = secret * _G
    # parity normalisation: use the secret key of the even-y public key
    if public_point.y() % 2 == 0:
        secret_even = secret
    else:
        secret_even = _n - secret
    pubkey = _bytes(public_point.x())

    rand_hash = bytearray(_tagged_hash(b"BIP0340/aux", aux_rand))
    masked = bytearray(int_to_bytes(secret_even, 32, "big"))
    for i in range(32):
        masked[i] ^= rand_hash[i]

    nonce = bytes_to_int(
        _tagged_hash(b"BIP0340/nonce", bytes(masked) + pubkey + message),
        "big",
    ) % _n
    if nonce == 0:
        # negligible probability, but the BIP requires aborting
        raise SchnorrError(
            "Nonce generation failed, retry with different aux_rand"
        )

    nonce_point = nonce * _G
    # parity normalisation: commit to the even-y nonce point
    if nonce_point.y() % 2 == 0:
        nonce_even = nonce
    else:
        nonce_even = _n - nonce
    nonce_x = _bytes(nonce_point.x())

    challenge = bytes_to_int(
        _tagged_hash(b"BIP0340/challenge", nonce_x + pubkey + message),
        "big",
    ) % _n

    return nonce_x + _bytes((nonce_even + challenge * secret_even) % _n)


def verify(message, public_key, signature):
    """
    Verify a 64 byte BIP 340 Schnorr signature over ``message``.

    ``public_key`` must be a 32 byte x-only public key and ``signature``
    a 64 byte string ``R.x || s``. ``message`` is a byte string of
    arbitrary length (see the module docstring).

    Returns True when the signature is valid, False otherwise. All the
    BIP 340 checks are performed strictly: the public key x coordinate
    and ``R.x`` must be smaller than the field size, ``s`` must be
    smaller than the curve order, and the public key must lift to an
    actual curve point.
    """
    message = compat26_str(message)
    public_key = compat26_str(public_key)
    signature = compat26_str(signature)
    if len(public_key) != 32 or len(signature) != 64:
        return False

    pubkey_x = bytes_to_int(public_key, "big")
    r = bytes_to_int(signature[:32], "big")
    s = bytes_to_int(signature[32:], "big")
    if pubkey_x >= _p or r >= _p or s >= _n:
        return False

    public_point = _lift_x(pubkey_x)
    if public_point is None:
        return False

    challenge = bytes_to_int(
        _tagged_hash(
            b"BIP0340/challenge", signature[:32] + public_key + message
        ),
        "big",
    ) % _n

    # R = s*G - e*P
    nonce_point = s * _G + ((-challenge) % _n) * public_point
    if nonce_point == ellipticcurve.INFINITY:
        return False
    nonce_point = nonce_point.to_affine()
    if nonce_point.y() % 2 != 0:
        return False
    return nonce_point.x() == r


class PublicKey(object):
    """
    X-only BIP 340 Schnorr public key (32 byte encoding).

    The key is validated on construction: the encoding must be 32 bytes
    long, smaller than the field size, and correspond to an actual
    secp256k1 point.
    """

    def __init__(self, public_key):
        public_key = compat26_str(public_key)
        if len(public_key) != 32:
            raise InvalidPublicKeyError(
                "Public key must be 32 bytes, got {0}".format(
                    len(public_key)
                )
            )
        point = _lift_x(bytes_to_int(public_key, "big"))
        if point is None:
            raise InvalidPublicKeyError(
                "Public key does not correspond to a secp256k1 point"
            )
        self.__point = point
        self.__encoded = bytes(bytearray(public_key))

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return self.__encoded == other.__encoded
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return "schnorr.PublicKey({0!r})".format(self.__encoded)

    @property
    def point(self):
        """The curve point (with even y) of this public key."""
        return self.__point

    def to_bytes(self):
        """Return the 32 byte x-only encoding of the public key."""
        return self.__encoded

    def verify(self, signature, message):
        """
        Verify a 64 byte BIP 340 signature over ``message``.

        Returns True for a valid signature, False otherwise.
        """
        return verify(message, self.__encoded, signature)


class PrivateKey(object):
    """
    BIP 340 Schnorr private key.

    The secret scalar is never included in the string representation of
    this object or in the exceptions it raises.
    """

    def __init__(self, secret_key):
        secret_key = compat26_str(secret_key)
        # validates length and range, raises InvalidSecretKeyError
        _secret_to_int(secret_key)
        self.__secret = bytes(bytearray(secret_key))

    @classmethod
    def generate(cls):
        """Create a new private key from ``os.urandom`` randomness."""
        while True:
            try:
                return cls(os.urandom(32))
            except InvalidSecretKeyError:
                continue

    def __eq__(self, other):
        if isinstance(other, PrivateKey):
            return self.__secret == other.__secret
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        # never leak the secret scalar through the representation
        return "schnorr.PrivateKey(<hidden>)"

    def to_bytes(self):
        """Return the 32 byte encoding of the secret key."""
        return self.__secret

    def public_key(self):
        """Return the x-only :class:`PublicKey` for this private key."""
        return PublicKey(pubkey_from_secret(self.__secret))

    def sign(self, message, aux_rand=None):
        """
        Create a 64 byte BIP 340 signature over ``message``.

        ``aux_rand`` works as in :func:`sign`: 32 bytes of auxiliary
        random data, generated with :func:`os.urandom` when omitted.
        """
        return sign(message, self.__secret, aux_rand)
