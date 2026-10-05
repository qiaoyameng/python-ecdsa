"""
BIP 340 Schnorr signatures over secp256k1.

This module implements Schnorr signatures as specified in BIP 340
("Schnorr Signatures for secp256k1", version of 2021-01-20 with the
x-only public key lifting rules from the current specification) using the
pure-python curve arithmetic of this library.

The interface here is intentionally separate from
:class:`ecdsa.keys.SigningKey`/:class:`ecdsa.keys.VerifyingKey` and the
ECDSA signature encodings: a BIP 340 signature is always exactly 64 bytes
(``r`` x-coordinate followed by ``s``) and is never accepted by or
confused with the ECDSA interfaces.

Note that BIP 340 signs byte strings of exactly 32 octets; the message is
*not* hashed by this module. Callers that want to sign a longer message
must hash it themselves according to the application protocol (for example
BIP 341 uses the ``"BIP0340/challenge"``-style tagged hashes through
``H(m)``), before invoking :meth:`SchnorrSigningKey.sign`.
"""
from __future__ import division

import hashlib
import os

from . import ecdsa
from .ellipticcurve import PointJacobi
from .keys import BadSignatureError
from ._compat import int_to_bytes, bytes_to_int


p = ecdsa.curve_secp256k1.p()
n = ecdsa.generator_secp256k1.order()
G = ecdsa.generator_secp256k1


class SchnorrError(Exception):
    """Base class for all errors raised by the Schnorr module."""


class InvalidPrivateKeyError(SchnorrError, ValueError):
    """Raised when a scalar is not a valid BIP 340 private key."""


class InvalidPublicKeyError(SchnorrError, ValueError):
    """Raised when bytes do not encode a valid x-only public key."""


class InvalidSignatureError(SchnorrError, BadSignatureError):
    """Raised when bytes do not encode a valid BIP 340 signature.

    Subclasses :class:`ecdsa.keys.BadSignatureError` so that code
    uniformly catching signature verification failures works as expected.
    """


def _to_bytes32(value, name):
    """Return exactly 32 bytes from a bytes-like *value*."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(
            "{0} must be a bytes-like object of exactly 32 bytes".format(name)
        )
    if len(value) != 32:
        raise ValueError(
            "{0} must be exactly 32 bytes long, got {1}".format(
                name, len(value)
            )
        )
    return bytes(value)


def _i(b):
    """Interpret a 32-byte big-endian string as an integer."""
    return bytes_to_int(b, "big")


def _b(x):
    """Serialize an integer as a 32-byte big-endian string."""
    return bytes(int_to_bytes(x, 32))


def tagged_hash(tag, data):
    """Compute the BIP 340 tagged hash ``SHA256(SHA256(tag) || msg)``."""
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def lift_x(x):
    """Return the even-y point with x-coordinate *x*.

    :raises InvalidPublicKeyError: if *x* is out of range or no such point
        exists.
    """
    if isinstance(x, bool) or not isinstance(x, int) or not (0 <= x < p):
        raise InvalidPublicKeyError("x coordinate is out of range")
    c = (pow(x, 3, p) + 7) % p
    y = pow(c, (p + 1) // 4, p)
    if (y * y) % p != c:
        raise InvalidPublicKeyError(
            "x coordinate does not correspond to a point on the curve"
        )
    if y & 1:
        y = p - y
    return PointJacobi(ecdsa.curve_secp256k1, x, y, 1, n)


class SchnorrSigningKey(object):
    """A BIP 340 Schnorr private (signing) key for secp256k1.

    The private scalar is stored privately and never included in the
    object representation or in any exception message.
    """

    def __init__(self, secret):
        if isinstance(secret, bool) or not isinstance(secret, int):
            raise InvalidPrivateKeyError(
                "private scalar must be an integer"
            )
        if not (1 <= secret < n):
            raise InvalidPrivateKeyError(
                "private scalar must be in the range 1..n-1"
            )
        self.__secret = secret
        d = secret
        P = d * G
        if P.y() & 1:
            d = n - d
            P = -P
        self.__d = d
        self.__verifying_key = SchnorrPublicKey._from_point(P.x(), P)

    @classmethod
    def generate(cls, entropy=None):
        """Create a new random signing key.

        :param entropy: callable taking an integer byte count and returning
            that many random bytes; defaults to :func:`os.urandom`.
        """
        if entropy is None:
            entropy = os.urandom
        while True:
            candidate = _i(entropy(32))
            if 1 <= candidate < n:
                return cls(candidate)

    @classmethod
    def from_string(cls, string):
        """Decode a 32-byte big-endian scalar into a signing key."""
        return cls(_i(_to_bytes32(string, "private key")))

    def to_string(self):
        """Return the 32-byte big-endian encoding of the private scalar."""
        return _b(self.__secret)

    def get_verifying_key(self):
        """Return the associated :class:`SchnorrPublicKey`."""
        return self.__verifying_key

    def sign(self, msg, aux_rand=None):
        """Produce a BIP 340 Schnorr signature over a 32-byte message.

        :param bytes msg: the 32-byte message to sign (BIP 340 ``m``); it
            is hashed by the Schnorr construction, not by this method, so
            it must already be exactly 32 bytes.
        :param bytes aux_rand: optional 32 bytes of auxiliary randomness.
            When ``None`` (the default), fresh randomness is drawn with
            :func:`os.urandom`; pass an explicit value for reproducible
            signatures.

        :rtype: bytes
        """
        msg = _to_bytes32(msg, "message")
        if aux_rand is None:
            aux_rand = os.urandom(32)
        aux_rand = _to_bytes32(aux_rand, "aux_rand")

        d = self.__d
        px = self.__verifying_key.x_int()

        t = _b(d ^ _i(tagged_hash(b"BIP0340/aux", aux_rand)))
        k0 = _i(
            tagged_hash(
                b"BIP0340/nonce",
                t + _b(px) + msg,
            )
        ) % n
        if k0 == 0:
            raise SchnorrError(
                "nonce derivation produced zero; retry with fresh "
                "auxiliary randomness"
            )
        R = k0 * G
        if R.y() & 1:
            k = n - k0
        else:
            k = k0
        rx = R.x()
        e = _i(
            tagged_hash(
                b"BIP0340/challenge",
                _b(rx) + _b(px) + msg,
            )
        ) % n
        s = (k + e * d) % n
        if s == 0:
            raise SchnorrError(
                "signature generation produced s == 0; retry with fresh "
                "auxiliary randomness"
            )
        return _b(rx) + _b(s)

    def __eq__(self, other):
        if isinstance(other, SchnorrSigningKey):
            return self.__secret == other.__secret
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((SchnorrSigningKey, self.__secret))

    def __repr__(self):
        return "SchnorrSigningKey(verifying_key={0})".format(
            self.get_verifying_key().to_string().hex()
        )


class SchnorrPublicKey(object):
    """A BIP 340 x-only Schnorr public key for secp256k1."""

    def __init__(self, data):
        data = _to_bytes32(data, "public key")
        point = lift_x(_i(data))
        self.__x = point.x()
        self.__point = point

    @classmethod
    def _from_point(cls, x, point):
        obj = cls.__new__(cls)
        obj.__x = x
        obj.__point = point
        return obj

    def x_int(self):
        """Return the x coordinate as an integer."""
        return self.__x

    def to_string(self):
        """Return the 32-byte x-only encoding of the public key."""
        return _b(self.__x)

    @classmethod
    def from_string(cls, string):
        """Decode a 32-byte x-only public key."""
        return cls(string)

    def verify(self, signature, msg):
        """Verify a BIP 340 signature over a 32-byte message.

        :param bytes signature: the 64-byte BIP 340 signature.
        :param bytes msg: the 32-byte signed message.

        :raises InvalidSignatureError: if the signature is malformed, has
            out-of-range ``r``/``s``, encodes an invalid curve point, or
            does not verify.
        :rtype: bool
        """
        msg = _to_bytes32(msg, "message")
        if not isinstance(signature, (bytes, bytearray, memoryview)):
            raise InvalidSignatureError(
                "signature must be a bytes-like object of 64 bytes"
            )
        if len(signature) != 64:
            raise InvalidSignatureError(
                "signature must be exactly 64 bytes long, got {0}".format(
                    len(signature)
                )
            )
        signature = bytes(signature)
        r = _i(signature[:32])
        s = _i(signature[32:])
        if r >= p:
            raise InvalidSignatureError("r is out of range")
        if s >= n:
            raise InvalidSignatureError("s is out of range")
        try:
            R = lift_x(r)
        except InvalidPublicKeyError:
            raise InvalidSignatureError(
                "r does not correspond to a point on the curve"
            )
        e = _i(
            tagged_hash(
                b"BIP0340/challenge",
                _b(r) + _b(self.__x) + msg,
            )
        ) % n
        R_check = G.mul_add(s, self.__point, (n - e) % n)
        if R_check == R and (R_check.y() & 1) == 0:
            return True
        raise InvalidSignatureError("Schnorr signature does not verify")

    def __eq__(self, other):
        if isinstance(other, SchnorrPublicKey):
            return self.__x == other.__x
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((SchnorrPublicKey, self.__x))

    def __repr__(self):
        return "SchnorrPublicKey({0})".format(_b(self.__x).hex())


def sign(secret, msg, aux_rand=None):
    """Sign *msg* with the 32-byte scalar *secret* (BIP 340).

    This is a standalone convenience entry point that is independent of
    the ECDSA :meth:`ecdsa.keys.SigningKey.sign` interface.

    :rtype: bytes
    """
    return SchnorrSigningKey.from_string(secret).sign(msg, aux_rand)


def verify(public_key, signature, msg):
    """Verify a BIP 340 *signature* over *msg* against *public_key*.

    Standalone counterpart to :func:`sign`; it never interprets the
    signature as an ECDSA signature.

    :raises InvalidSignatureError: if verification fails.
    :rtype: bool
    """
    return SchnorrPublicKey(public_key).verify(signature, msg)
