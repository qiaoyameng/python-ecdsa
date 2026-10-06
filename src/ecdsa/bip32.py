#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""
BIP 32 hierarchical deterministic key derivation for secp256k1.

This is an independent module built on top of the elliptic curve
arithmetic provided by the library; the original ECDSA signing API
(:class:`~ecdsa.keys.SigningKey`/:class:`~ecdsa.keys.VerifyingKey`)
is not modified.

It implements:

* master key generation from a seed
  (:func:`master_key_from_seed`),
* hardened (``n'``/``nH``) and normal (``n``) child derivation,
* public-only ("neutered") keys and public-only derivation of
  non-hardened paths,
* serialisation and parsing of the 78-byte Base58Check encoded
  extended keys (xprv/xpub and tprv/tpub) described in BIP 32.

Path strings are parsed with a small dedicated parser; no Python
expression evaluation is ever performed on them.

Written as part of python-ecdsa and placed in the public domain.
"""

from __future__ import division

import hashlib
import hmac
import struct

from six import integer_types

from ._compat import int_to_bytes, normalise_bytes, str_idx_as_int
from .curves import SECP256k1
from .ellipticcurve import INFINITY, PointJacobi
from .keys import SigningKey, VerifyingKey
from .util import number_to_string, string_to_number


#: Indices from this value up are hardened.
HARDENED_INDEX = 0x80000000

#: Highest valid child index.
MAX_INDEX = 0xFFFFFFFF

_KEY_LEN = 32
_CHAIN_CODE_LEN = 32
_SERIALISED_LEN = 78
_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_BASE58_ALPHABET += b"abcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: i for i, char in enumerate(_BASE58_ALPHABET)}

#: Order of the secp256k1 group.
SECP256K1_ORDER = SECP256k1.order

#: Version bytes of the four supported extended key types.
MAINNET_PRIVATE = 0x0488ADE4  # xprv
MAINNET_PUBLIC = 0x0488B21E  # xpub
TESTNET_PRIVATE = 0x04358394  # tprv
TESTNET_PUBLIC = 0x043587CF  # tpub

_PRIVATE_VERSIONS = frozenset((MAINNET_PRIVATE, TESTNET_PRIVATE))
_PUBLIC_VERSIONS = frozenset((MAINNET_PUBLIC, TESTNET_PUBLIC))
_VERSIONS = _PRIVATE_VERSIONS | _PUBLIC_VERSIONS

#: Map a private version byte to the matching public version byte.
PUBLIC_VERSION_OF = {
    MAINNET_PRIVATE: MAINNET_PUBLIC,
    TESTNET_PRIVATE: TESTNET_PUBLIC,
}


class BIP32Error(ValueError):
    """Base class for all BIP 32 related errors."""

    pass


class InvalidSeedError(BIP32Error):
    """Raised when a seed cannot produce a valid master key."""

    pass


class InvalidPathError(BIP32Error):
    """Raised when a derivation path is malformed."""

    pass


class InvalidExtendedKeyError(BIP32Error):
    """Raised when a serialised extended key is invalid."""

    pass


class HardPublicDerivationError(BIP32Error):
    """Raised when attempting hardened derivation from a public key."""

    pass


def _i2o32(value):
    """Convert an unsigned 32 bit integer to 4 big-endian bytes."""
    return bytes(int_to_bytes(value, 4, "big"))


def _i2o256(value):
    """Convert an unsigned 256 bit integer to exactly 32 big-endian bytes."""
    return bytes(int_to_bytes(value, _KEY_LEN, "big"))


# ---------------------------------------------------------------------------
# Base58Check encoding
# ---------------------------------------------------------------------------

def base58_encode(data):
    """Encode a byte string with the Bitcoin Base58 alphabet."""
    data = bytes(bytearray(normalise_bytes(data)))
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = string_to_number(data) if data.strip(b"\x00") else 0
    result = b""
    while number > 0:
        number, remainder = divmod(number, 58)
        result = (
            _BASE58_ALPHABET[remainder:remainder + 1] + result
        )
    return b"1" * leading_zeroes + result


def base58_decode(data):
    """Decode a Base58 string back to a byte string.

    :raises InvalidExtendedKeyError: if the input contains characters
        outside the Base58 alphabet.
    """
    if isinstance(data, str):
        data = data.encode("ascii")
    number = 0
    for char in data:
        index = _BASE58_INDEX.get(char)
        if index is None:
            raise InvalidExtendedKeyError(
                "Invalid Base58 character in extended key"
            )
        number = number * 58 + index
    decoded = b""
    while number > 0:
        number, remainder = divmod(number, 256)
        decoded = int_to_bytes(remainder, 1, "big") + decoded
    decoded = bytes(bytearray(decoded))
    leading_ones = len(data) - len(data.lstrip(b"1"))
    return b"\x00" * leading_ones + decoded


def base58check_encode(data):
    """Encode data with a SHA-256-double checksum appended."""
    checksum = hashlib.sha256(
        hashlib.sha256(normalise_bytes(data)).digest()
    ).digest()[:4]
    return base58_encode(bytes(bytearray(data)) + checksum)


def base58check_decode(data):
    """Decode Base58Check data, verifying the trailing checksum.

    :raises InvalidExtendedKeyError: on bad alphabet or checksum.
    """
    raw = base58_decode(data)
    if len(raw) < 4:
        raise InvalidExtendedKeyError(
            "Extended key too short for a checksum"
        )
    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(
        hashlib.sha256(payload).digest()
    ).digest()[:4]
    if checksum != expected:
        raise InvalidExtendedKeyError(
            "Invalid Base58Check checksum"
        )
    return payload


# ---------------------------------------------------------------------------
# Hash160 (RIPEMD-160 of SHA-256), used for key fingerprints.
# ---------------------------------------------------------------------------

def hash160(data):
    """Compute RIPEMD-160(SHA-256(data))."""
    digest = hashlib.sha256(normalise_bytes(data)).digest()
    try:
        return hashlib.new("ripemd160", digest).digest()
    except ValueError:
        # RIPEMD-160 is not provided by this hashlib build.
        return _ripemd160(digest)


def _ripemd160(data):
    """Pure-Python RIPEMD-160, used only if hashlib lacks the algorithm."""
    r_left = (
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    )
    r_right = (
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    )
    s_left = (
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    )
    s_right = (
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 7, 5, 15, 13, 11,
    )
    constants_left = (
        0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
    )
    constants_right = (
        0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000,
    )

    def rol(value, bits):
        return (
            (value << bits) | (value >> (32 - bits))
        ) & 0xFFFFFFFF

    def function(group, x, y, z):
        if group == 0:
            return (x ^ y ^ z) & 0xFFFFFFFF
        if group == 1:
            return ((x & y) | (~x & z)) & 0xFFFFFFFF
        if group == 2:
            return ((x | ~y) ^ z) & 0xFFFFFFFF
        if group == 3:
            return ((x & z) | (y & ~z)) & 0xFFFFFFFF
        return (x ^ (y | ~z)) & 0xFFFFFFFF

    message = bytearray(data)
    bit_length = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += struct.pack("<Q", bit_length)

    h0, h1, h2, h3, h4 = (
        0x67452301, 0xEFCDAB89, 0x98BADCFE,
        0x10325476, 0xC3D2E1F0,
    )

    for block_start in range(0, len(message), 64):
        words = struct.unpack_from("<16I", bytes(message), block_start)
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for round_index in range(80):
            group = round_index // 16

            temp_left = (
                rol(
                    al
                    + function(group, bl, cl, dl)
                    + words[r_left[round_index]]
                    + constants_left[group],
                    s_left[round_index],
                )
                + el
            ) & 0xFFFFFFFF
            al, bl, cl, dl, el = (
                el,
                temp_left,
                bl,
                rol(cl, 10),
                dl,
            )

            temp_right = (
                rol(
                    ar
                    + function(4 - group, br, cr, dr)
                    + words[r_right[round_index]]
                    + constants_right[group],
                    s_right[round_index],
                )
                + er
            ) & 0xFFFFFFFF
            ar, br, cr, dr, er = (
                er,
                temp_right,
                br,
                rol(cr, 10),
                dr,
            )

        temp = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = temp

    return struct.pack("<5I", h0, h1, h2, h3, h4)


# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------

def parse_path(path):
    """Parse a BIP 32 derivation path into a tuple of 32 bit indices.

    Absolute paths start with ``m``/``M``/``"m/"``; relative paths start
    directly with the first component. Hardened components are marked with
    a trailing ``'`` or ``"h"``/``"H"``.

    Only the small parser below is used; Python expressions are never
    evaluated, so a component such as ``0 + 1`` raises.

    :raises InvalidPathError: if the path is malformed.
    """
    if isinstance(path, (list, tuple)):
        components = tuple(path)
        for component in components:
            if (
                not isinstance(component, integer_types)
                or not 0 <= component <= MAX_INDEX
            ):
                raise InvalidPathError(
                    "Path component {0!r} is not a valid index".format(
                        component
                    )
                )
        return components

    if isinstance(path, bytes):
        try:
            path = path.decode("ascii")
        except UnicodeDecodeError:
            raise InvalidPathError("Path is not valid ASCII")
    if not isinstance(path, str):
        raise InvalidPathError("Path must be a string or a sequence")

    text = path.strip()
    if text == "" or text in ("m", "M"):
        return ()

    # Absolute path prefix.
    if text[0] in ("m", "M"):
        if len(text) < 2 or text[1] != "/":
            raise InvalidPathError(
                "Expected '/' after the master marker in path"
            )
        text = text[2:]
    elif text[0] == "/":
        raise InvalidPathError("Path must not start with a bare '/'")

    indices = []
    for raw_component in text.split("/"):
        component = raw_component.strip()
        if component == "":
            raise InvalidPathError("Empty component in derivation path")
        hardened = False
        if component[-1] in ("'", "h", "H", "p", "P"):
            hardened = True
            component = component[:-1]
        if component == "" or not component.isdigit():
            raise InvalidPathError(
                "Invalid path component {0!r}".format(raw_component)
            )
        value = int(component, 10)
        if not 0 <= value <= MAX_INDEX:
            raise InvalidPathError(
                "Child index {0} is out of range".format(value)
            )
        if hardened:
            value += HARDENED_INDEX
        elif value >= HARDENED_INDEX:
            raise InvalidPathError(
                "Index {0} requires a hardened marker".format(value)
            )
        if not 0 <= value <= MAX_INDEX:
            raise InvalidPathError(
                "Child index {0} is out of range".format(value)
            )
        indices.append(value)
    return tuple(indices)


def _is_hardened(index):
    return index >= HARDENED_INDEX


# ---------------------------------------------------------------------------
# Extended key
# ---------------------------------------------------------------------------

class ExtendedKey(object):
    """A BIP 32 extended (public or private) key.

    The key keeps a private scalar (``None`` for a neutered key), the
    chain code, depth, parent fingerprint and child number.
    """

    def __init__(
        self,
        chain_code,
        depth=0,
        parent_fingerprint=b"\x00\x00\x00\x00",
        child_number=0,
        private_exponent=None,
        public_point=None,
        version=MAINNET_PRIVATE,
    ):
        self.depth = depth
        self.parent_fingerprint = bytes(parent_fingerprint)
        self.child_number = child_number
        self.chain_code = bytes(chain_code)
        self.version = version

        if len(self.chain_code) != _CHAIN_CODE_LEN:
            raise InvalidExtendedKeyError(
                "Chain code must be 32 bytes long"
            )
        if len(self.parent_fingerprint) != 4:
            raise InvalidExtendedKeyError(
                "Parent fingerprint must be 4 bytes long"
            )
        if not 0 <= self.depth <= 255:
            raise InvalidExtendedKeyError("Depth must be between 0 and 255")
        if not 0 <= self.child_number <= MAX_INDEX:
            raise InvalidExtendedKeyError("Child number out of range")
        if self.version not in _VERSIONS:
            raise InvalidExtendedKeyError("Unknown extended key version")

        self.private_exponent = private_exponent
        if public_point is None and private_exponent is not None:
            public_point = (
                SECP256k1.generator * private_exponent
            )
        if public_point is None:
            raise InvalidExtendedKeyError(
                "An extended key must have a public point"
            )
        self._public_point = public_point

        if self.is_private():
            if private_exponent is None or not (
                1 <= private_exponent < SECP256K1_ORDER
            ):
                raise InvalidSeedError(
                    "Private scalar must be in [1, n-1]"
                )
        else:
            self.private_exponent = None

    # -- metadata -------------------------------------------------------

    def is_private(self):
        """Return True for an extended private key."""
        return self.version in _PRIVATE_VERSIONS

    def is_testnet(self):
        """Return True for the test net (tprv/tpub) version bytes."""
        return self.version in (
            TESTNET_PRIVATE,
            TESTNET_PUBLIC,
        )

    @property
    def public_key(self):
        """The uncompressed 64 byte SEC1 public key (X||Y)."""
        point = self._public_point
        raw = point.to_bytes("raw")
        if len(raw) == 64:
            return raw
        # PointJacobi raw encoding is X||Y; normalise defensively.
        return (
            number_to_string(point.x(), SECP256K1_ORDER)
            + number_to_string(point.y(), SECP256K1_ORDER)
        )

    @property
    def compressed_public_key(self):
        """The 33 byte compressed SEC1 public key."""
        return self._public_point.to_bytes("compressed")

    @property
    def identifier(self):
        """RIPEMD160(SHA256(compressed public key))."""
        return hash160(self.compressed_public_key)

    @property
    def fingerprint(self):
        """The first 4 bytes of :attr:`identifier`."""
        return self.identifier[:4]

    def to_signing_key(self):
        """Return a :class:`SigningKey` for this extended private key."""
        if not self.is_private():
            raise HardPublicDerivationError(
                "A neutered extended key has no signing key"
            )
        return SigningKey.from_secret_exponent(
            self.private_exponent, curve=SECP256k1
        )

    def to_verifying_key(self):
        """Return a :class:`VerifyingKey` for the public point."""
        return VerifyingKey.from_public_point(
            self._public_point, curve=SECP256k1
        )

    # -- serialisation --------------------------------------------------

    def serialize(self):
        """Return the 78 byte binary extended key representation."""
        version = _i2o32(self.version)
        depth = bytes(bytearray((self.depth,)))
        data = bytearray()
        data += version
        data += depth
        data += self.parent_fingerprint
        data += _i2o32(self.child_number)
        data += self.chain_code
        if self.is_private():
            data += b"\x00" + _i2o256(self.private_exponent)
        else:
            data += self.compressed_public_key
        if len(data) != _SERIALISED_LEN:
            raise InvalidExtendedKeyError(
                "Serialized extended key has wrong length"
            )
        return bytes(data)

    def export_key(self):
        """Return the Base58Check encoded extended key (bytes)."""
        return base58check_encode(self.serialize())

    # aliases commonly used by BIP 32 libraries
    to_base58 = export_key
    to_extended_key = export_key

    @classmethod
    def deserialize(cls, data):
        """Parse the 78 byte binary extended key representation."""
        data = bytes(bytearray(normalise_bytes(data)))
        if len(data) != _SERIALISED_LEN:
            raise InvalidExtendedKeyError(
                "Serialized extended key must be 78 bytes long"
            )
        version = struct.unpack(">I", data[0:4])[0]
        depth = str_idx_as_int(data, 4)
        parent_fingerprint = data[5:9]
        child_number = struct.unpack(">I", data[9:13])[0]
        chain_code = data[13:45]
        key_data = data[45:78]

        if version not in _VERSIONS:
            raise InvalidExtendedKeyError(
                "Unknown extended key version 0x{0:08x}".format(version)
            )
        if version in _PRIVATE_VERSIONS:
            if key_data[0] != 0:
                raise InvalidExtendedKeyError(
                    "Private key data must have a leading zero pad"
                )
            private_exponent = string_to_number(key_data[1:33])
            if not 1 <= private_exponent < SECP256K1_ORDER:
                raise InvalidSeedError(
                    "Private scalar out of range in extended key"
                )
            public_point = (
                SECP256k1.generator * private_exponent
            )
        else:
            if key_data[0] not in (0x02, 0x03):
                raise InvalidExtendedKeyError(
                    "Public key data must be a compressed SEC1 point"
                )
            public_point = PointJacobi.from_bytes(
                SECP256k1.curve, key_data
            )
            private_exponent = None

        if depth == 0:
            if child_number != 0 or parent_fingerprint != b"\x00" * 4:
                raise InvalidExtendedKeyError(
                    "Master key must have zero depth metadata"
                )

        return cls(
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            private_exponent=private_exponent,
            public_point=public_point,
            version=version,
        )

    @classmethod
    def from_key(cls, data):
        """Parse a Base58Check encoded extended key (xprv/xpub/...)."""
        return cls.deserialize(base58check_decode(data))

    # -- neutering / version handling ----------------------------------

    def neuter(self, public_version=None):
        """Return the extended public (neutered) key.

        :param public_version: optional explicit public version byte;
            defaults to the public version matching this key.
        """
        if public_version is None:
            if self.is_private():
                public_version = PUBLIC_VERSION_OF[self.version]
            else:
                public_version = self.version
        if public_version not in _PUBLIC_VERSIONS:
            raise InvalidExtendedKeyError(
                "Not a public extended key version"
            )
        return ExtendedKey(
            chain_code=self.chain_code,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            private_exponent=None,
            public_point=self._public_point,
            version=public_version,
        )

    def to_public(self, public_version=None):
        """Alias for :meth:`neuter`."""
        return self.neuter(public_version)

    # -- derivation -----------------------------------------------------

    def _child_data(self, index):
        if _is_hardened(index):
            if not self.is_private():
                raise HardPublicDerivationError(
                    "Cannot derive hardened child index {0} from a "
                    "public-only extended key".format(index)
                )
            data = b"\x00" + _i2o256(self.private_exponent)
        else:
            data = self.compressed_public_key
        return data + _i2o32(index)

    def child(self, index):
        """Derive the child extended key at ``index`` (an int)."""
        if not isinstance(index, integer_types) or not (
            0 <= index <= MAX_INDEX
        ):
            raise InvalidPathError("Invalid child index {0!r}".format(index))

        data = self._child_data(index)
        derived = hmac.new(
            self.chain_code, data, hashlib.sha512
        ).digest()
        il, chain_code = derived[:_KEY_LEN], derived[_KEY_LEN:]
        il_int = string_to_number(il)
        if il_int >= SECP256K1_ORDER:
            raise InvalidExtendedKeyError(
                "Derived scalar is out of range at index {0}".format(index)
            )

        parent_fingerprint = self.fingerprint
        depth = (self.depth + 1) & 0xFF

        if self.is_private():
            child_exponent = (
                il_int + self.private_exponent
            ) % SECP256K1_ORDER
            if child_exponent == 0:
                raise InvalidExtendedKeyError(
                    "Resulting private scalar is zero at index {0}".format(
                        index
                    )
                )
            child_point = SECP256k1.generator * child_exponent
            return ExtendedKey(
                chain_code=chain_code,
                depth=depth,
                parent_fingerprint=parent_fingerprint,
                child_number=index,
                private_exponent=child_exponent,
                public_point=child_point,
                version=self.version,
            )

        # Public-only, non-hardened derivation.
        il_point = SECP256k1.generator * il_int
        child_point = il_point + self._public_point
        if child_point == INFINITY:
            raise InvalidExtendedKeyError(
                "Resulting public point is the point at infinity"
            )
        return ExtendedKey(
            chain_code=chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=index,
            private_exponent=None,
            public_point=child_point,
            version=self.version,
        )

    def derive(self, path):
        """Derive the extended key at a parsed ``path``.

        ``path`` may be a string (``"m/0/1'"``) or an iterable of ints.
        """
        key = self
        for index in parse_path(path):
            key = key.child(index)
        return key

    def __getitem__(self, index):
        hardened = False
        if isinstance(index, str):
            indices = parse_path(index)
            if len(indices) != 1:
                raise InvalidPathError(
                    "Use derive() for multi-component paths"
                )
            index = indices[0]
        return self.child(index)


# ---------------------------------------------------------------------------
# Master key generation
# ---------------------------------------------------------------------------

def master_key_from_seed(seed, testnet=False):
    """Build the BIP 32 master extended private key from ``seed``.

    :param seed: the 16-64 byte BIP 32 seed.
    :param testnet: use the tprv version bytes when True.
    :raises InvalidSeedError: if the seed length is invalid or the
        derived master scalar is out of range.
    """
    seed = bytes(bytearray(normalise_bytes(seed)))
    if not 16 <= len(seed) <= 64:
        raise InvalidSeedError(
            "BIP 32 seeds must be between 16 and 64 bytes long"
        )
    derived = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_secret, chain_code = derived[:_KEY_LEN], derived[_KEY_LEN:]
    master_exponent = string_to_number(master_secret)
    if not 1 <= master_exponent < SECP256K1_ORDER:
        raise InvalidSeedError(
            "Master key derived from the seed is out of range"
        )
    version = TESTNET_PRIVATE if testnet else MAINNET_PRIVATE
    return ExtendedKey(
        chain_code=chain_code,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        child_number=0,
        private_exponent=master_exponent,
        public_point=SECP256k1.generator * master_exponent,
        version=version,
    )
