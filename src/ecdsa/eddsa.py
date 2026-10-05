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


def _normalise_context(context):
    """Return the context as bytes, verifying it's of valid length."""
    if context is None:
        return b""
    if not isinstance(context, (bytes, bytearray)):
        raise TypeError("context must be a bytes-like object")
    context = bytes(context)
    if len(context) > 255:
        raise ValueError(
            "context too long, maximum length is 255 bytes, got {0}".format(
                len(context)
            )
        )
    return context


def _check_mode(mode, context, prehashed):
    """Verify that the combination of mode, context and prehashed is valid."""
    if mode not in ("pure", "ctx", "ph"):
        raise ValueError(
            "Unknown mode: {0!r}, must be 'pure', 'ctx' or 'ph'".format(mode)
        )
    if mode == "pure" and context:
        raise ValueError(
            "context is not supported in 'pure' mode, use 'ctx' mode"
        )
    if prehashed and mode != "ph":
        raise ValueError("prehashed input is only supported in 'ph' mode")


def _prehash_message(curve, data):
    """Hash the message as specified for the ph mode in RFC 8032."""
    if curve == curve_ed448:
        # Ed448ph uses SHAKE256 with a 64 byte output for the prehash,
        # not the 114 byte output used internally by the curve
        return shake_256(data, 64)
    return curve.hash_func(data)


def _prehash_len(curve):
    """Return the length of the prehash for the ph mode."""
    if curve == curve_ed448:
        return 64
    return len(curve.hash_func(b""))


def _dom2(curve, mode, context):
    """Compute the dom2 (Ed25519) or dom4 (Ed448) prefix from RFC 8032."""
    if curve == curve_ed448:
        dom = bytearray(b"SigEd448")
    elif mode == "pure":
        # for PureEdDSA the dom2 is the empty string
        return bytearray()
    else:
        dom = bytearray(b"SigEd25519 no Ed25519 collisions")
    dom.append(1 if mode == "ph" else 0)
    dom.append(len(context))
    dom += context
    return dom


def _validate_parameters(curve, data, context, mode, prehashed):
    """Verify that the combination of parameters is valid, return context."""
    context = _normalise_context(context)
    _check_mode(mode, context, prehashed)
    if mode == "ph" and prehashed:
        hash_len = _prehash_len(curve)
        if len(data) != hash_len:
            raise ValueError(
                "Invalid length of the prehashed message, expected "
                "{0} bytes, got {1}".format(hash_len, len(data))
            )
    return context


def _process_message(curve, data, context, mode, prehashed):
    """
    Validate parameters and return the (dom, message) pair to sign/verify.
    """
    context = _validate_parameters(curve, data, context, mode, prehashed)
    dom = _dom2(curve, mode, context)
    if mode != "ph":
        return dom, data
    if prehashed:
        return dom, data
    return dom, _prehash_message(curve, data)


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

    def verify(
        self, data, signature, context=None, mode="pure", prehashed=False
    ):
        """
        Verify an EdDSA signature over data.

        :param data: the message the signature is over; in ``ph`` mode with
            ``prehashed`` set to True it must be the output of the curve hash
            function over the message
        :type data: :term:`bytes-like object`
        :param signature: the signature to verify
        :type signature: :term:`bytes-like object`
        :param context: the protocol specific context string, at most 255
            bytes long; used only in ``ctx`` and ``ph`` modes
        :type context: :term:`bytes-like object` or None
        :param str mode: the EdDSA mode to use: "pure" for PureEdDSA
            (Ed25519, Ed448), "ctx" for the contextualised variant
            (Ed25519ctx) or "ph" for the prehashed variant (Ed25519ph,
            Ed448ph)
        :param bool prehashed: in ``ph`` mode, specifies that `data` is
            already the hash of the message and must not be hashed again
        """
        data = compat26_str(data)
        dom, message = _process_message(
            self.curve, data, context, mode, prehashed
        )
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
            self.curve.hash_func(
                dom + R.to_bytes() + self.__encoded + message
            ),
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

    def sign(self, data, context=None, mode="pure", prehashed=False):
        """
        Perform an EdDSA signature over data.

        :param data: the message to sign; in ``ph`` mode with ``prehashed``
            set to True it must be the output of the curve hash function
            over the message
        :type data: :term:`bytes-like object`
        :param context: the protocol specific context string, at most 255
            bytes long; used only in ``ctx`` and ``ph`` modes
        :type context: :term:`bytes-like object` or None
        :param str mode: the EdDSA mode to use: "pure" for PureEdDSA
            (Ed25519, Ed448), "ctx" for the contextualised variant
            (Ed25519ctx) or "ph" for the prehashed variant (Ed25519ph,
            Ed448ph)
        :param bool prehashed: in ``ph`` mode, specifies that `data` is
            already the hash of the message and must not be hashed again
        """
        data = compat26_str(data)
        dom, message = _process_message(
            self.curve, data, context, mode, prehashed
        )
        A = self.public_key().public_key()

        prefix = self.__h[self.baselen :]

        r = bytes_to_int(
            self.curve.hash_func(dom + prefix + message), "little"
        )
        R = (self.generator * r).to_bytes()

        k = bytes_to_int(
            self.curve.hash_func(dom + R + A + message), "little"
        )
        k %= self.generator.order()

        S = (r + k * self.__s) % self.generator.order()

        return R + int_to_bytes(S, self.baselen, "little")
