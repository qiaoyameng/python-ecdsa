"""
BIP 32 hierarchical deterministic key derivation for secp256k1.

This module is an independent layer built on top of the elliptic-curve
arithmetic in :mod:`ecdsa.ellipticcurve` and :mod:`ecdsa.curves`.  It
implements the "Hierarchical Deterministic Wallets" scheme described in
BIP 32: master key generation from a seed, hardened and non-hardened
derivation of extended private/public keys, and Base58Check
serialisation/deserialisation.

The existing ECDSA signing interface in :mod:`ecdsa.keys` is untouched;
use :meth:`HDPrivateKey.to_signing_key` if a classic :class:`SigningKey`
is needed.
"""

from __future__ import absolute_import
from __future__ import division

import binascii
import hashlib
import hmac
import struct

from six import integer_types

from ._compat import int_to_bytes, bytes_to_int, normalise_bytes
from .curves import SECP256k1
from .ellipticcurve import INFINITY, PointJacobi
from .keys import SigningKey
from .util import number_to_string, string_to_number


__all__ = [
    "HARDENED",
    "BIP32Error",
    "InvalidPathError",
    "InvalidExtendedKeyError",
    "HardenedDerivationError",
    "DerivationError",
    "parse_path",
    "b58encode",
    "b58decode",
    "b58encode_check",
    "b58decode_check",
    "HDPrivateKey",
    "HDPublicKey",
    "deserialize",
]


#: Offset added to an index to mark it as hardened.
HARDENED = 0x80000000

#: Highest allowed child index.
MAX_INDEX = 0xFFFFFFFF

#: Order of the secp256k1 base point (scalars must be in the range
#: ``[1, ORDER - 1]``).
ORDER = SECP256k1.order

_KEY_LEN = 32

# Base58 alphabet as defined for Bitcoin addresses/keys.
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = dict(
    (byte, index) for index, byte in enumerate(_B58_ALPHABET)
)


class BIP32Error(Exception):
    """Base class for all BIP 32 related errors."""

    pass


class InvalidPathError(BIP32Error, ValueError):
    """Raised when a derivation path cannot be parsed."""

    pass


class InvalidExtendedKeyError(BIP32Error, ValueError):
    """Raised when an extended key serialisation is malformed."""

    pass


class HardenedDerivationError(BIP32Error):
    """Raised when hardened derivation is attempted from a public key."""

    pass


class DerivationError(BIP32Error):
    """Raised when no valid child can be derived (index space exhausted)."""

    pass


def _b58encode_int(value):
    """Encode a non-negative integer as Base58 (no leading zero handling)."""
    result = bytearray()
    while value:
        value, remainder = divmod(value, 58)
        result.append(_B58_ALPHABET[remainder])
    return bytes(reversed(result))


def b58encode(data):
    """
    Encode a byte string with Base58.

    Leading zero bytes are preserved as leading ``'1'`` characters,
    matching the Base58 convention used by Base58Check.

    :param bytes data: data to encode
    :rtype: bytes
    """
    data = bytes(normalise_bytes(data))
    pad = 0
    while pad < len(data) and data[pad] == 0:
        pad += 1
    number = bytes_to_int(data, "big")
    encoded = _b58encode_int(number) if number else b""
    return b"1" * pad + encoded


def b58decode(data):
    """
    Decode a Base58 encoded byte string.

    :param data: Base58 encoded data (``bytes`` or ASCII ``str``)
    :raises InvalidExtendedKeyError: if the input contains a character
        outside of the Base58 alphabet
    :rtype: bytes
    """
    if isinstance(data, str):
        data = data.encode("ascii")
    data = bytes(normalise_bytes(data))
    number = 0
    for char in data:
        if char not in _B58_INDEX:
            raise InvalidExtendedKeyError(
                "Invalid character in Base58 encoded data: {0!r}".format(
                    chr(char)
                )
            )
        number = number * 58 + _B58_INDEX[char]

    pad = 0
    while pad < len(data) and data[pad] == _B58_ALPHABET[0]:
        pad += 1

    if number:
        body = bytes(int_to_bytes(number))
    else:
        body = b""
    return b"\x00" * pad + body


def b58encode_check(data):
    """
    Encode *data* with Base58Check.

    The checksum is the first four bytes of the double SHA-256 hash of
    the payload.

    :param bytes data: payload to encode
    :rtype: bytes
    """
    data = bytes(normalise_bytes(data))
    checksum = hashlib.sha256(
        hashlib.sha256(data).digest()
    ).digest()[:4]
    return b58encode(data + checksum)


def b58decode_check(data):
    """
    Decode a Base58Check encoded value, verifying its checksum.

    :param data: Base58Check encoded data (``bytes`` or ASCII ``str``)
    :raises InvalidExtendedKeyError: if the encoding or the checksum is
        incorrect
    :rtype: bytes
    """
    raw = b58decode(data)
    if len(raw) < 4:
        raise InvalidExtendedKeyError(
            "Base58Check payload too short for a checksum"
        )
    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(
        hashlib.sha256(payload).digest()
    ).digest()[:4]
    if checksum != expected:
        raise InvalidExtendedKeyError("Invalid Base58Check checksum")
    return payload


# -- RIPEMD-160 -------------------------------------------------------------
# RIPEMD-160 is required for the HASH160 fingerprint, but OpenSSL 3 builds
# often do not provide it through hashlib.  Keep a small pure-python
# implementation as a fallback.


def _ripemd160_rol(value, bits):
    """Rotate a 32-bit integer *value* left by *bits* positions."""
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def _ripemd160(data):
    """Compute the RIPEMD-160 digest of *data* (bytes)."""
    data = bytes(normalise_bytes(data))

    def fun(kind, x, y, z):
        if kind == 0:
            return x ^ y ^ z
        if kind == 1:
            return (x & y) | (~x & z)
        if kind == 2:
            return (x | ~y) ^ z
        if kind == 3:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

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
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    )
    k_left = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
    k_right = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)

    # MD4-style padding.
    bit_len = len(data) * 8
    padded = data + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += struct.pack("<Q", bit_len & 0xFFFFFFFFFFFFFFFF)

    h0, h1, h2, h3, h4 = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

    for offset in range(0, len(padded), 64):
        words = struct.unpack("<16I", padded[offset:offset + 64])
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for round_index in range(80):
            kind = round_index // 16
            word = words[r_left[round_index]]
            t = (
                al
                + fun(kind, bl, cl, dl)
                + word
                + k_left[kind]
            ) & 0xFFFFFFFF
            t = (_ripemd160_rol(t, s_left[round_index]) + el) & 0xFFFFFFFF
            al, el, dl = el, dl, _ripemd160_rol(cl, 10)
            cl, bl = bl, t

            kind_r = 4 - round_index // 16
            word = words[r_right[round_index]]
            t = (
                ar
                + fun(kind_r, br, cr, dr)
                + word
                + k_right[round_index // 16]
            ) & 0xFFFFFFFF
            t = (
                _ripemd160_rol(t, s_right[round_index]) + er
            ) & 0xFFFFFFFF
            ar, er, dr = er, dr, _ripemd160_rol(cr, 10)
            cr, br = br, t

        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t

    return struct.pack("<5I", h0, h1, h2, h3, h4)


def _hash160(data):
    """Compute RIPEMD-160(SHA-256(*data*))."""
    sha = hashlib.sha256(bytes(normalise_bytes(data))).digest()
    try:
        ripe = hashlib.new("ripemd160", sha).digest()
    except (ValueError, TypeError):
        ripe = _ripemd160(sha)
    return ripe


def _hmac_sha512(key, data):
    """Return the 64 byte HMAC-SHA512 of *data* keyed by *key*."""
    return hmac.new(
        bytes(normalise_bytes(key)),
        bytes(normalise_bytes(data)),
        hashlib.sha512,
    ).digest()


def parse_path(path):
    """
    Parse a textual BIP 32 derivation path into a list of child indexes.

    Recognised forms include ``"m"`` (the master, an empty list),
    ``"m/0"``, ``"m/0'/1/2h"``, and relative paths such as ``"0/1"``.
    Both ``'``/``h``/``H`` mark a hardened index.  The parsing is purely
    syntactic -- it never evaluates Python expressions.

    :param path: slash separated derivation path
    :type path: str
    :raises InvalidPathError: if the path is syntactically invalid or
        references an index outside of the allowed range
    :rtype: list(int)
    """
    if isinstance(path, bytes):
        try:
            path = path.decode("ascii")
        except UnicodeDecodeError:
            raise InvalidPathError("Non-ASCII derivation path")
    if not isinstance(path, str):
        raise InvalidPathError(
            "Derivation path must be a string, not {0}".format(type(path))
        )

    text = path.strip()
    if not text:
        raise InvalidPathError("Empty derivation path")

    if text[0] in "mM":
        text = text[1:]
        if text:
            if text[0] != "/":
                raise InvalidPathError(
                    "Invalid derivation path: {0!r}".format(path)
                )
            text = text[1:]
            if not text:
                raise InvalidPathError(
                    "Trailing slash in derivation path: {0!r}".format(path)
                )
    elif text[0] == "/":
        raise InvalidPathError(
            "Absolute derivation path must start with 'm': {0!r}".format(path)
        )

    if not text:
        return []

    indexes = []
    for component in text.split("/"):
        if not component:
            raise InvalidPathError(
                "Empty path component in: {0!r}".format(path)
            )
        hardened = False
        if component[-1] in "'hH":
            hardened = True
            component = component[:-1]
        if not component or not component.isdigit():
            raise InvalidPathError(
                "Invalid path component {0!r} in: {1!r}".format(
                    component, path
                )
            )
        index = int(component)
        if index >= HARDENED:
            raise InvalidPathError(
                "Child index {0} out of range".format(index)
            )
        if hardened:
            index += HARDENED
        indexes.append(index)
    return indexes


def _check_index(index):
    """Validate a single child index."""
    if isinstance(index, bool) or not isinstance(index, integer_types):
        raise InvalidPathError(
            "Child index must be an integer, not {0}".format(type(index))
        )
    if not 0 <= index <= MAX_INDEX:
        raise InvalidPathError(
            "Child index {0} out of range".format(index)
        )
    return index


# -- Extended keys ----------------------------------------------------------


#: 4 byte version bytes for the four kinds of serialised keys.
#:
#: Mapping: (network, key kind) -> version bytes.
VERSIONS = {
    ("mainnet", "private"): b"\x04\x88\xad\xe4",
    ("mainnet", "public"): b"\x04\x88\xb2\x1e",
    ("testnet", "private"): b"\x04\x35\x83\x94",
    ("testnet", "public"): b"\x04\x35\x87\xcf",
}

_VERSION_LOOKUP = dict(
    (version, network_kind) for network_kind, version in VERSIONS.items()
)


class _ExtendedKey(object):
    """
    Common base for BIP 32 extended keys.

    :ivar int depth: distance from the master key, ``0`` for the master.
    :ivar bytes parent_fingerprint: four byte fingerprint of the parent
        public key; all zeroes for a master key.
    :ivar int child_number: index used to derive this key (hardened
        indexes have :data:`HARDENED` added); zero for a master key.
    :ivar bytes chain_code: 32 byte chain code.
    :ivar str network: ``"mainnet"`` or ``"testnet"``.
    """

    def __init__(self, depth, parent_fingerprint, child_number, chain_code,
                 network="mainnet"):
        if not isinstance(depth, int) or not 0 <= depth <= 255:
            raise ValueError("depth must be an integer in the range 0..255")
        parent_fingerprint = bytes(normalise_bytes(parent_fingerprint))
        chain_code = bytes(normalise_bytes(chain_code))
        if len(parent_fingerprint) != 4:
            raise ValueError("parent_fingerprint must be exactly 4 bytes")
        if len(chain_code) != 32:
            raise ValueError("chain_code must be exactly 32 bytes")
        if not 0 <= child_number <= MAX_INDEX:
            raise ValueError("child_number out of range")
        if depth == 0 and (
            child_number != 0 or parent_fingerprint != b"\x00" * 4
        ):
            raise ValueError(
                "A master key (depth 0) must have child number and "
                "parent fingerprint set to zero"
            )
        if network not in ("mainnet", "testnet"):
            raise ValueError("network must be 'mainnet' or 'testnet'")

        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.chain_code = chain_code
        self.network = network

    @property
    def is_private(self):
        """True for extended private keys, False for public ones."""
        raise NotImplementedError

    @property
    def is_hardened(self):
        """True if this key was derived with a hardened index."""
        return self.child_number >= HARDENED

    @property
    def index(self):
        """Index without the hardened bit (its position in the path)."""
        return self.child_number & (HARDENED - 1)

    def fingerprint(self):
        """
        Return the 4 byte BIP 32 fingerprint of this key.

        The fingerprint is the first four bytes of
        RIPEMD-160(SHA-256(compressed public key)).
        """
        return _hash160(self.compressed_public_key())[:4]

    def identifier(self):
        """Return the 20 byte HASH160 identifier of the public key."""
        return _hash160(self.compressed_public_key())

    def compressed_public_key(self):
        """Return the 33 byte compressed encoding of the public point."""
        raise NotImplementedError

    def neuter(self):
        """Return the extended public key corresponding to this key."""
        raise NotImplementedError

    def derive(self, index):
        """
        Derive a child key, skipping indexes rejected by BIP 32.

        Per BIP 32, an index must be retried (incremented) when the
        derived scalar is outside of ``[1, n-1]`` or when the derived
        public point is the point at infinity.  Because the index
        actually used may differ from *index*, the returned value is a
        ``(child, used_index)`` tuple.

        :param int index: requested child index
        :return: the derived child key and the index that produced it
        :rtype: tuple(_ExtendedKey, int)
        """
        raise NotImplementedError

    def derive_path(self, path):
        """
        Derive a key along a slash separated path.

        See :func:`parse_path` for the accepted path syntax.  Returns a
        ``(key, used_indexes)`` tuple so retried indexes are visible to
        the caller.
        """
        indexes = parse_path(path)
        node = self
        used = []
        for index in indexes:
            node, actual = node.derive(index)
            used.append(actual)
        return node, used

    def serialize(self):
        """
        Serialise the key to a Base58Check encoded ``bytes`` value.

        :rtype: bytes
        """
        if self.is_private:
            version = VERSIONS[(self.network, "private")]
            key_data = b"\x00" + number_to_string(self.private_key, ORDER)
        else:
            version = VERSIONS[(self.network, "public")]
            key_data = self.compressed_public_key()

        payload = (
            version
            + struct.pack("B", self.depth)
            + self.parent_fingerprint
            + struct.pack(">I", self.child_number)
            + self.chain_code
            + key_data
        )
        return b58encode_check(payload)

    def __str__(self):
        return self.serialize().decode("ascii")

    def __repr__(self):
        return "{0}({1!r})".format(type(self).__name__, str(self))

    def __eq__(self, other):
        if type(self) != type(other):
            return NotImplemented
        return self.serialize() == other.serialize()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((type(self), self.serialize()))


class HDPrivateKey(_ExtendedKey):
    """An extended BIP 32 private key."""

    def __init__(
        self,
        private_key,
        chain_code,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        child_number=0,
        network="mainnet",
    ):
        """
        :param int private_key: ECDSA scalar in the range ``[1, n-1]``.
        :param bytes chain_code: 32 byte chain code.
        :param int depth: depth of the key, zero for a master.
        :param bytes parent_fingerprint: four byte parent fingerprint.
        :param int child_number: child index (with hardened bit set if
            applicable), zero for a master.
        :param str network: ``"mainnet"`` or ``"testnet"``.
        """
        super(HDPrivateKey, self).__init__(
            depth, parent_fingerprint, child_number, chain_code, network
        )
        if isinstance(private_key, bool) or not isinstance(
            private_key, integer_types
        ):
            raise ValueError("private_key must be an integer")
        if not 1 <= private_key < ORDER:
            raise ValueError(
                "private_key must be in the range [1, order - 1]"
            )
        self.private_key = int(private_key)
        self._public_point = None

    @classmethod
    def from_seed(cls, seed, network="mainnet"):
        """
        Generate a master extended private key from a binary seed.

        BIP 32 seeds must be between 16 and 64 bytes long.

        :param bytes seed: binary seed (typically the output of a
            BIP 39 mnemonic decode)
        :param str network: ``"mainnet"`` or ``"testnet"``
        :rtype: HDPrivateKey
        """
        seed = bytes(normalise_bytes(seed))
        if not 16 <= len(seed) <= 64:
            raise ValueError(
                "Seed must be between 16 and 64 bytes long, got {0}".format(
                    len(seed)
                )
            )
        derived = _hmac_sha512(b"Bitcoin seed", seed)
        private_scalar = string_to_number(derived[:_KEY_LEN])
        chain_code = derived[_KEY_LEN:]
        if private_scalar == 0 or private_scalar >= ORDER:
            raise BIP32Error("Seed produced an invalid master key")
        return cls(private_scalar, chain_code, network=network)

    @property
    def is_private(self):
        return True

    def public_point(self):
        """Return the :class:`~ecdsa.ellipticcurve.PointJacobi` public key."""
        if self._public_point is None:
            self._public_point = SECP256k1.generator * self.private_key
        return self._public_point

    def compressed_public_key(self):
        return bytes(
            self.public_point().to_affine().to_bytes("compressed")
        )

    def neuter(self):
        """
        Return the matching :class:`HDPublicKey`.

        Derivation and chain code are preserved, only the private scalar
        is stripped.
        """
        return HDPublicKey(
            self.public_point(),
            self.chain_code,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            network=self.network,
        )

    def public_key(self):
        """Return the extended public key (alias of :meth:`neuter`)."""
        return self.neuter()

    def to_signing_key(self, hashfunc=hashlib.sha256):
        """
        Convert this node to a regular :class:`ecdsa.keys.SigningKey`.

        The ECDSA signing interface is otherwise unchanged.

        :param hashfunc: default hash function for the returned key
        :rtype: ecdsa.keys.SigningKey
        """
        return SigningKey.from_secret_exponent(
            self.private_key, curve=SECP256k1, hashfunc=hashfunc
        )

    def _derive_private(self, index):
        if index >= HARDENED:
            data = b"\x00" + number_to_string(self.private_key, ORDER)
        else:
            data = self.compressed_public_key()
        data += struct.pack(">I", index)
        derived = _hmac_sha512(self.chain_code, data)
        scalar = string_to_number(derived[:_KEY_LEN])
        child_scalar = (scalar + self.private_key) % ORDER
        chain_code = derived[_KEY_LEN:]
        if scalar >= ORDER or child_scalar == 0:
            return None
        return HDPrivateKey(
            child_scalar,
            chain_code,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint(),
            child_number=index,
            network=self.network,
        )

    def derive(self, index):
        index = _check_index(index)
        if self.depth >= 255:
            raise DerivationError("Maximum key depth (255) reached")
        candidate = index
        while True:
            child = self._derive_private(candidate)
            if child is not None:
                return child, candidate
            if candidate == MAX_INDEX:
                raise DerivationError(
                    "No valid child index starting from {0}".format(index)
                )
            candidate += 1

    @classmethod
    def deserialize(cls, data):
        """
        Decode a Base58Check encoded extended private key.

        :param data: Base58Check encoded ``str``/``bytes`` (a raw 78 byte
            payload without checksum is accepted too)
        :rtype: HDPrivateKey
        """
        key = _deserialize(data)
        if not isinstance(key, HDPrivateKey):
            raise InvalidExtendedKeyError(
                "Serialized extended key is not a private key"
            )
        return key


class HDPublicKey(_ExtendedKey):
    """An extended BIP 32 public key (an xpub)."""

    def __init__(
        self,
        public_key,
        chain_code,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        child_number=0,
        network="mainnet",
    ):
        """
        :param public_key: the public point (any
            :class:`~ecdsa.ellipticcurve.AbstractPoint` on secp256k1)
        :param bytes chain_code: 32 byte chain code.
        :param int depth: depth of the key, zero for a master.
        :param bytes parent_fingerprint: four byte parent fingerprint.
        :param int child_number: child index, zero for a master.
        :param str network: ``"mainnet"`` or ``"testnet"``.
        """
        super(HDPublicKey, self).__init__(
            depth, parent_fingerprint, child_number, chain_code, network
        )
        if public_key is INFINITY or public_key == INFINITY:
            raise ValueError("Public key must not be the point at infinity")
        if public_key.curve() != SECP256k1.curve:
            raise ValueError("Public key must be a point on secp256k1")
        point = public_key
        if hasattr(point, "scale"):
            point = point.scale()
        x_coord = point.x()
        y_coord = point.y()
        prime = SECP256k1.curve.p()
        if not (0 <= x_coord < prime and 0 <= y_coord < prime):
            raise ValueError("Public key coordinates are out of range")
        if not SECP256k1.curve.contains_point(x_coord, y_coord):
            raise ValueError("Public key is not on the secp256k1 curve")
        self._point = point

    @property
    def is_private(self):
        return False

    def public_point(self):
        return self._point

    def compressed_public_key(self):
        return bytes(self._point.to_affine().to_bytes("compressed"))

    def neuter(self):
        return self

    def derive(self, index):
        index = _check_index(index)
        if index >= HARDENED:
            raise HardenedDerivationError(
                "Hardened child {0} cannot be derived from a public "
                "key".format(index & (HARDENED - 1))
            )
        if self.depth >= 255:
            raise DerivationError("Maximum key depth (255) reached")

        candidate = index
        while True:
            data = self.compressed_public_key() + struct.pack(">I", candidate)
            derived = _hmac_sha512(self.chain_code, data)
            scalar = string_to_number(derived[:_KEY_LEN])
            chain_code = derived[_KEY_LEN:]
            if scalar >= ORDER:
                child = None
            else:
                # K_i = IL*G + K_par (single multi-scalar multiplication).
                child_point = SECP256k1.generator.mul_add(
                    scalar, self._point, 1
                )
                if child_point == INFINITY:
                    child = None
                else:
                    child = HDPublicKey(
                        child_point,
                        chain_code,
                        depth=self.depth + 1,
                        parent_fingerprint=self.fingerprint(),
                        child_number=candidate,
                        network=self.network,
                    )
            if child is not None:
                return child, candidate
            if candidate >= HARDENED - 1:
                # Retries must not cross into the hardened range, which
                # cannot be derived from a public key.
                raise DerivationError(
                    "No valid non-hardened child index starting from "
                    "{0}".format(index)
                )
            if candidate == MAX_INDEX:
                raise DerivationError(
                    "No valid child index starting from {0}".format(index)
                )
            candidate += 1

    @classmethod
    def deserialize(cls, data):
        """
        Decode a Base58Check encoded extended public key.

        :param data: Base58Check encoded ``str``/``bytes`` (a raw 78 byte
            payload without checksum is accepted too)
        :rtype: HDPublicKey
        """
        key = _deserialize(data)
        if not isinstance(key, HDPublicKey):
            raise InvalidExtendedKeyError(
                "Serialized extended key is not a public key"
            )
        return key


def _deserialize(data):
    """
    Decode a serialised extended key (private or public).

    Version bytes, depth/fingerprint/child-number relationship and the
    private/public marker byte are all validated.
    """
    if isinstance(data, str):
        data = data.encode("ascii")
    data = bytes(normalise_bytes(data))
    # A raw 78 byte payload carries no checksum; anything else is treated
    # as Base58Check.
    if len(data) == 78:
        payload = data
    else:
        payload = b58decode_check(data)
        if len(payload) != 78:
            raise InvalidExtendedKeyError(
                "Decoded extended key must be 78 bytes long, got {0}".format(
                    len(payload)
                )
            )

    version = payload[:4]
    if version not in _VERSION_LOOKUP:
        raise InvalidExtendedKeyError(
            "Unknown extended key version bytes: {0}".format(
                binascii.hexlify(payload[:4]).decode("ascii")
            )
        )
    network, kind = _VERSION_LOOKUP[version]
    depth = payload[4]
    parent_fingerprint = payload[5:9]
    child_number = bytes_to_int(payload[9:13], "big")
    chain_code = payload[13:45]
    key_data = payload[45:]

    if depth == 0:
        if child_number != 0 or parent_fingerprint != b"\x00" * 4:
            raise InvalidExtendedKeyError(
                "Master key must have zero depth metadata"
            )
    elif child_number == 0 and parent_fingerprint == b"\x00" * 4:
        # A non-master key was derived at index 0, but then its parent
        # fingerprint is the fingerprint of its (non-master) parent, not
        # zero.  Zeroes in both fields with depth > 0 are inconsistent.
        raise InvalidExtendedKeyError(
            "Non-master key must reference its parent fingerprint"
        )

    if kind == "private":
        if len(key_data) != 33 or key_data[0] != 0:
            raise InvalidExtendedKeyError(
                "Private key data must be 33 bytes prefixed with 0x00"
            )
        scalar = string_to_number(key_data[1:])
        if not 1 <= scalar < ORDER:
            raise InvalidExtendedKeyError(
                "Private scalar outside of the valid range"
            )
        return HDPrivateKey(
            scalar,
            chain_code,
            depth=depth,
            parent_fingerprint=parent_fingerprint,
            child_number=child_number,
            network=network,
        )

    if len(key_data) != 33 or key_data[0] not in (0x02, 0x03):
        raise InvalidExtendedKeyError(
            "Public key data must be 33 bytes in compressed form"
        )
    try:
        public_point = PointJacobi.from_bytes(SECP256k1.curve, key_data)
    except Exception as exc:
        raise InvalidExtendedKeyError(
            "Invalid public key point: {0}".format(exc)
        )
    return HDPublicKey(
        public_point,
        chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        network=network,
    )


def deserialize(data):
    """
    Decode any extended key (private or public) from Base58Check.

    :rtype: HDPrivateKey or HDPublicKey
    """
    return _deserialize(data)
