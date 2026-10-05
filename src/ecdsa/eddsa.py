"""Implementation of Edwards Digital Signature Algorithm."""

import hashlib
from ._sha3 import shake_256
from . import ellipticcurve
from ._compat import (
    remove_whitespace,
    bit_length,
    bytes_to_int,
    int_to_bytes,
    compat26_str,
)

# edwards25519, defined in RFC7748
_p = 2**255 - 19
_a = -1
_d = int(
    remove_whitespace(
        "370957059346694393431380835087545651895421138798432190163887855330"
        "85940283555"
    )
)
_h = 8

_Gx = int(
    remove_whitespace(
        "151122213495354007725011514095885315114540126930418572060461132"
        "83949847762202"
    )
)
_Gy = int(
    remove_whitespace(
        "463168356949264781694283940034751631413079938662562256157830336"
        "03165251855960"
    )
)
_r = 2**252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED


def _sha512(data):
    return hashlib.new("sha512", compat26_str(data)).digest()


curve_ed25519 = ellipticcurve.CurveEdTw(_p, _a, _d, _h, _sha512)
generator_ed25519 = ellipticcurve.PointEdwards(
    curve_ed25519, _Gx, _Gy, 1, _Gx * _Gy % _p, _r, generator=True
)


# edwards448, defined in RFC7748
_p = 2**448 - 2**224 - 1
_a = 1
_d = -39081 % _p
_h = 4

_Gx = int(
    remove_whitespace(
        "224580040295924300187604334099896036246789641632564134246125461"
        "686950415467406032909029192869357953282578032075146446173674602635"
        "247710"
    )
)
_Gy = int(
    remove_whitespace(
        "298819210078481492676017930443930673437544040154080242095928241"
        "372331506189835876003536878655418784733982303233503462500531545062"
        "832660"
    )
)
_r = 2**446 - 0x8335DC163BB124B65129C96FDE933D8D723A70AADC873D6D54A7BB0D


def _shake256(data):
    return shake_256(data, 114)


curve_ed448 = ellipticcurve.CurveEdTw(_p, _a, _d, _h, _shake256)
generator_ed448 = ellipticcurve.PointEdwards(
    curve_ed448, _Gx, _Gy, 1, _Gx * _Gy % _p, _r, generator=True
)


# Maximum length (in bytes) of the context string allowed by RFC 8032 for
# Ed25519ctx and Ed25519ph.
MAX_CONTEXT_LENGTH_ED25519 = 255

# Recognised Ed25519 signature modes from RFC 8032.
ED25519_MODE_PURE = "pure"
ED25519_MODE_CONTEXT = "context"
ED25519_MODE_PREHASHED = "prehashed"

ED25519_MODES = (
    ED25519_MODE_PURE,
    ED25519_MODE_CONTEXT,
    ED25519_MODE_PREHASHED,
)

# Length of the SHA-512 output, the only message digest used by Ed25519ph.
_PREHASH_LENGTH_ED25519 = 64

# Prefix used by Ed25519ctx/Ed25519ph for domain separation, see RFC 8032.
_DOMAIN_PREFIX_ED25519 = b"SigEd25519 no Ed25519 collisions"


def prehash_ed25519(data):
    """Return the SHA-512 digest of `data`, the Ed25519ph prehash."""
    return _sha512(compat26_str(data))


def _ed25519_context(mode, context):
    """Validate the mode/context pair and return the domain separator.

    Implements the ``dom2(F, C)`` function from RFC 8032. PureEdDSA uses an
    empty domain separator while Ed25519ctx (F=0) and Ed25519ph (F=1) always
    use the collision-resistant prefix.
    """
    if mode not in ED25519_MODES:
        raise ValueError(
            "Unknown Ed25519 mode: {0!r}, expected one of {1}".format(
                mode, ", ".join(repr(m) for m in ED25519_MODES)
            )
        )

    if context is None:
        context = b""

    if not isinstance(context, (bytes, bytearray)):
        raise TypeError(
            "The context must be a byte string, not {0}".format(
                type(context).__name__
            )
        )

    if mode == ED25519_MODE_PURE:
        if context:
            raise ValueError(
                "A non-empty context is only allowed with the 'context' "
                "or 'prehashed' Ed25519 modes"
            )
        return b""

    if len(context) > MAX_CONTEXT_LENGTH_ED25519:
        raise ValueError(
            "The context must not be longer than {0} bytes, got {1}".format(
                MAX_CONTEXT_LENGTH_ED25519, len(context)
            )
        )

    flag = 1 if mode == ED25519_MODE_PREHASHED else 0
    suffix = bytearray(2)
    suffix[0] = flag
    suffix[1] = len(context)
    return bytearray(_DOMAIN_PREFIX_ED25519) + suffix + bytearray(context)


class PublicKey(object):
    """Public key for the Edwards Digital Signature Algorithm."""

    def __init__(self, generator, public_key, public_point=None):
        self.generator = generator
        self.curve = generator.curve()
        self.__encoded = public_key
        # plus one for the sign bit and round up
        self.baselen = (bit_length(self.curve.p()) + 1 + 7) // 8
        if len(public_key) != self.baselen:
            raise ValueError(
                "Incorrect size of the public key, expected: {0} bytes".format(
                    self.baselen
                )
            )
        if public_point:
            self.__point = public_point
        else:
            self.__point = ellipticcurve.PointEdwards.from_bytes(
                self.curve, public_key
            )

    def __eq__(self, other):
        if isinstance(other, PublicKey):
            return (
                self.curve == other.curve and self.__encoded == other.__encoded
            )
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    @property
    def point(self):
        return self.__point

    @point.setter
    def point(self, other):
        if self.__point != other:
            raise ValueError("Can't change the coordinates of the point")
        self.__point = other

    def public_point(self):
        return self.__point

    def public_key(self):
        return self.__encoded

    def verify(self, data, signature, mode=ED25519_MODE_PURE, context=None):
        """Verify an EdDSA signature over data.

        For Ed25519, `mode` selects one of the three schemes defined in
        RFC 8032: ``"pure"`` (PureEdDSA, the default), ``"context"``
        (Ed25519ctx) or ``"prehashed"`` (Ed25519ph). With the ``"prehashed"``
        mode, `data` must already be the 64 byte SHA-512 digest of the
        message; the caller is responsible for performing the prehashing so
        that the digest is not hashed a second time.

        `context` is the optional domain separation string used by the
        ``"context"`` and ``"prehashed"`` modes; it must be a byte string no
        longer than 255 bytes and must match the context used for signing.
        """
        data = compat26_str(data)

        if self.curve == curve_ed25519:
            dom = _ed25519_context(mode, context)
            if (
                mode == ED25519_MODE_PREHASHED
                and len(data) != _PREHASH_LENGTH_ED25519
            ):
                raise ValueError(
                    "Invalid prehashed message length, expected: {0} "
                    "bytes of SHA-512 output".format(
                        _PREHASH_LENGTH_ED25519
                    )
                )
        else:
            dom = bytearray(b"SigEd448" + b"\x00\x00")

        if len(signature) != 2 * self.baselen:
            raise ValueError(
                "Invalid signature length, expected: {0} bytes".format(
                    2 * self.baselen
                )
            )
        R = ellipticcurve.PointEdwards.from_bytes(
            self.curve, signature[: self.baselen]
        )
        S = bytes_to_int(signature[self.baselen :], "little")
        if S >= self.generator.order():
            raise ValueError("Invalid signature")

        k = bytes_to_int(
            self.curve.hash_func(dom + R.to_bytes() + self.__encoded + data),
            "little",
        )

        if self.generator * S != self.__point * k + R:
            raise ValueError("Invalid signature")

        return True


class PrivateKey(object):
    """Private key for the Edwards Digital Signature Algorithm."""

    def __init__(self, generator, private_key):
        self.generator = generator
        self.curve = generator.curve()
        # plus one for the sign bit and round up
        self.baselen = (bit_length(self.curve.p()) + 1 + 7) // 8
        if len(private_key) != self.baselen:
            raise ValueError(
                "Incorrect size of private key, expected: {0} bytes".format(
                    self.baselen
                )
            )
        self.__private_key = bytes(private_key)
        self.__h = bytearray(self.curve.hash_func(private_key))
        self.__public_key = None

        a = self.__h[: self.baselen]
        a = self._key_prune(a)
        scalar = bytes_to_int(a, "little")
        self.__s = scalar

    @property
    def private_key(self):
        return self.__private_key

    def __eq__(self, other):
        if isinstance(other, PrivateKey):
            return (
                self.curve == other.curve
                and self.__private_key == other.__private_key
            )
        return NotImplemented

    def __ne__(self, other):
        return not self == other

    def _key_prune(self, key):
        # make sure the key is not in a small subgroup
        h = self.curve.cofactor()
        if h == 4:
            h_log = 2
        elif h == 8:
            h_log = 3
        else:
            raise ValueError("Only cofactor 4 and 8 curves supported")
        key[0] &= ~((1 << h_log) - 1)

        # ensure the highest bit is set but no higher
        l = bit_length(self.curve.p())
        if l % 8 == 0:
            key[-1] = 0
            key[-2] |= 0x80
        else:
            key[-1] = key[-1] & (1 << (l % 8)) - 1 | 1 << (l % 8) - 1
        return key

    def public_key(self):
        """Generate the public key based on the included private key"""
        if self.__public_key:
            return self.__public_key

        public_point = self.generator * self.__s

        self.__public_key = PublicKey(
            self.generator, public_point.to_bytes(), public_point
        )

        return self.__public_key

    def sign(self, data, mode=ED25519_MODE_PURE, context=None):
        """Perform an EdDSA signature over data.

        For Ed25519, `mode` selects the scheme from RFC 8032: ``"pure"``
        (PureEdDSA, the default), ``"context"`` (Ed25519ctx) or
        ``"prehashed"`` (Ed25519ph). In the ``"prehashed"`` mode `data` must
        already be the 64 byte SHA-512 digest of the message; use
        :meth:`sign_prehashed` to sign the original message without having to
        perform the prehashing manually.

        `context` is the optional domain separation string (a byte string of
        at most 255 bytes) used by the ``"context"`` and ``"prehashed"``
        modes.

        Invalid modes or contexts raise a ValueError/TypeError before any
        signing operation is attempted.
        """
        data = compat26_str(data)
        A = self.public_key().public_key()

        prefix = self.__h[self.baselen :]

        if self.curve == curve_ed25519:
            dom = _ed25519_context(mode, context)
            if (
                mode == ED25519_MODE_PREHASHED
                and len(data) != _PREHASH_LENGTH_ED25519
            ):
                raise ValueError(
                    "Invalid prehashed message length, expected: {0} "
                    "bytes of SHA-512 output".format(
                        _PREHASH_LENGTH_ED25519
                    )
                )
        else:
            dom = bytearray(b"SigEd448" + b"\x00\x00")

        r = bytes_to_int(self.curve.hash_func(dom + prefix + data), "little")
        R = (self.generator * r).to_bytes()

        k = bytes_to_int(self.curve.hash_func(dom + R + A + data), "little")
        k %= self.generator.order()

        S = (r + k * self.__s) % self.generator.order()

        return R + int_to_bytes(S, self.baselen, "little")

    def sign_prehashed(self, data, context=None):
        """Perform an Ed25519ph signature over the original message `data`.

        The message is prehashed with SHA-512 once, as required by
        Ed25519ph in RFC 8032, and then signed in the ``"prehashed"`` mode.
        `context` is an optional domain separation string of at most 255
        bytes.
        """
        data = compat26_str(data)
        digest = prehash_ed25519(data)
        return self.sign(
            digest, mode=ED25519_MODE_PREHASHED, context=context
        )
