"""
Class for performing Elliptic-curve Diffie-Hellman (ECDH) operations.
"""

import struct

from .util import number_to_string, orderlen
from .ellipticcurve import INFINITY
from .keys import SigningKey, VerifyingKey
from .hkdf import hkdf, HKDFError


__all__ = [
    "ECDH",
    "HKDFContext",
    "INITIATOR",
    "RESPONDER",
    "NoKeyError",
    "NoCurveError",
    "InvalidCurveError",
    "InvalidSharedSecretError",
]


#: Role of the party that starts the protocol.
INITIATOR = b"initiator"

#: Role of the party that answers the protocol initiation.
RESPONDER = b"responder"


# Fixed prefix of the serialised key agreement context, it makes sure that
# HKDF input derived through this library can't be confused with an
# application provided ``info`` or with a different version of this format.
_CONTEXT_LABEL = b"python-ecdsa-ecdh-hkdf-v1"


def _encode_field(field):
    """Encode a single context field with an unambiguous 2-octet length."""
    if len(field) > 0xFFFF:
        raise HKDFError("Context field is too long to be encoded.")
    return struct.pack(">H", len(field)) + field


def _as_bytes(value):
    """Normalise a text/bytes value into bytes."""
    try:
        text_type = unicode  # noqa: F821
    except NameError:
        text_type = str
    if isinstance(value, text_type):
        return value.encode("utf-8")
    return bytes(value)


class HKDFContext(object):
    """
    Structured HKDF context (``info`` parameter of HKDF-Expand).

    Binds the derived session key to a protocol name, the order of the
    roles in the handshake (initiator first, responder second) and to the
    canonical (uncompressed SEC1) encodings of both public keys.

    The context is serialised with length prefixed fields, so it can be
    parsed without ambiguity and it never relies on a simple concatenation
    of variable length strings. Public keys are never sorted: the
    initiator key is always placed before the responder key, independent
    of their numeric values, so the two parties can't be confused.

    Both parties of the key agreement must build the context with the
    same protocol name and pass their own role as ``local_role``; the
    serialised context (and thus the derived key) is identical on both
    sides.
    """

    def __init__(
        self,
        protocol,
        local_role,
        initiator_public_key=None,
        responder_public_key=None,
    ):
        """
        :param protocol: name of the application protocol, like
            ``"my-protocol-v1"``
        :type protocol: str or bytes
        :param local_role: role of the local party, either
            :data:`INITIATOR` or :data:`RESPONDER`
        :type local_role: bytes
        :param initiator_public_key: public key of the initiator. It can be
            provided later in :meth:`to_info`.
        :type initiator_public_key: VerifyingKey or :term:`bytes-like object`
        :param responder_public_key: public key of the responder. It can be
            provided later in :meth:`to_info`.
        :type responder_public_key: VerifyingKey or :term:`bytes-like object`

        :raises HKDFError: the role or the protocol name is invalid
        """
        if local_role not in (INITIATOR, RESPONDER):
            raise HKDFError(
                "local_role must be either INITIATOR or RESPONDER."
            )

        protocol = _as_bytes(protocol)
        if not protocol:
            raise HKDFError("Protocol name can't be empty.")

        self.protocol = protocol
        self.local_role = local_role
        self.initiator_public_key = initiator_public_key
        self.responder_public_key = responder_public_key

    @staticmethod
    def _canonical_public_key(public_key, curve):
        """
        Return the canonical encoding of a public key.

        :param public_key: :class:`~ecdsa.keys.VerifyingKey` object or the
            uncompressed SEC1 encoding of a public key
        :type public_key: VerifyingKey or :term:`bytes-like object`
        :param curve: curve the public key is supposed to belong to, used
            to check the length of a raw encoding. It can be ``None`` when
            the key is provided as a :class:`~ecdsa.keys.VerifyingKey`.
        :type curve: Curve

        :raises InvalidCurveError: a VerifyingKey belongs to a different
            curve
        :raises HKDFError: the raw encoding has an illegal length or does
            not use the uncompressed point format

        :return: uncompressed SEC1 encoding of the public point
        :rtype: bytes
        """
        if isinstance(public_key, VerifyingKey):
            if curve is not None and public_key.curve != curve:
                raise InvalidCurveError(
                    "Public key curve does not match the context curve."
                )
            curve = public_key.curve
            return bytes(public_key.to_string("uncompressed"))

        encoded = bytes(public_key)
        if curve is None:
            raise HKDFError(
                "Curve is required to validate a raw public key encoding."
            )
        expected_length = 2 * orderlen(curve.curve.p()) + 1
        if len(encoded) != expected_length:
            raise HKDFError(
                "Public key has an invalid length for the selected "
                "curve: expected {0} bytes, got {1}.".format(
                    expected_length, len(encoded)
                )
            )
        if encoded[0:1] != b"\x04":
            raise HKDFError(
                "Only uncompressed (0x04) public key encoding is "
                "unambiguous, provide a VerifyingKey or an uncompressed "
                "encoding."
            )
        return encoded

    def to_info(
        self,
        curve=None,
        initiator_public_key=None,
        responder_public_key=None,
    ):
        """
        Serialise the context to the HKDF ``info`` byte string.

        Every field is prefixed with its length (a 2 octet, big endian
        number), fields are emitted in a fixed order:

        1. fixed format label
        2. protocol name
        3. curve name
        4. ``"initiator"`` role label
        5. initiator canonical public key
        6. ``"responder"`` role label
        7. responder canonical public key

        :param curve: curve used for the key agreement
        :type curve: Curve
        :param initiator_public_key: public key of the initiator, overrides
            a key provided to the constructor
        :type initiator_public_key: VerifyingKey or :term:`bytes-like object`
        :param responder_public_key: public key of the responder, overrides
            a key provided to the constructor
        :type responder_public_key: VerifyingKey or :term:`bytes-like object`

        :return: serialised context suitable for HKDF-Expand
        :rtype: bytes
        """
        if initiator_public_key is None:
            initiator_public_key = self.initiator_public_key
        if responder_public_key is None:
            responder_public_key = self.responder_public_key
        if initiator_public_key is None or responder_public_key is None:
            raise HKDFError(
                "Both initiator and responder public keys are required."
            )

        initiator_encoding = self._canonical_public_key(
            initiator_public_key, curve
        )
        responder_encoding = self._canonical_public_key(
            responder_public_key, curve
        )
        if len(initiator_encoding) != len(responder_encoding):
            raise InvalidCurveError(
                "Initiator and responder public keys use different "
                "curves (encoded lengths differ)."
            )

        if curve is None and isinstance(initiator_public_key, VerifyingKey):
            curve = initiator_public_key.curve
        curve_name = curve.name.encode("utf-8") if curve is not None else b""

        info = b"".join(
            [
                _encode_field(_CONTEXT_LABEL),
                _encode_field(self.protocol),
                _encode_field(curve_name),
                _encode_field(INITIATOR),
                _encode_field(initiator_encoding),
                _encode_field(RESPONDER),
                _encode_field(responder_encoding),
            ]
        )
        return info


class NoKeyError(Exception):
    """ECDH. Key not found but it is needed for operation."""

    pass


class NoCurveError(Exception):
    """ECDH. Curve not set but it is needed for operation."""

    pass


class InvalidCurveError(Exception):
    """
    ECDH. Raised in case the public and private keys use different curves.
    """

    pass


class InvalidSharedSecretError(Exception):
    """ECDH. Raised in case the shared secret we obtained is an INFINITY."""

    pass


class ECDH(object):
    """
    Elliptic-curve Diffie-Hellman (ECDH). A key agreement protocol.

    Allows two parties, each having an elliptic-curve public-private key
    pair, to establish a shared secret over an insecure channel
    """

    def __init__(self, curve=None, private_key=None, public_key=None):
        """
        ECDH init.

        Call can be initialised without parameters, then the first operation
        (loading either key) will set the used curve.
        All parameters must be ultimately set before shared secret
        calculation will be allowed.

        :param curve: curve for operations
        :type curve: Curve
        :param private_key: `my` private key for ECDH
        :type private_key: SigningKey
        :param public_key:  `their` public key for ECDH
        :type public_key: VerifyingKey
        """
        self.curve = curve
        self.private_key = None
        self.public_key = None
        if private_key:
            self.load_private_key(private_key)
        if public_key:
            self.load_received_public_key(public_key)

    def _get_shared_secret(self, remote_public_key):
        if not self.private_key:
            raise NoKeyError(
                "Private key needs to be set to create shared secret"
            )
        if not self.public_key:
            raise NoKeyError(
                "Public key needs to be set to create shared secret"
            )
        if not (
            self.private_key.curve == self.curve == remote_public_key.curve
        ):
            raise InvalidCurveError(
                "Curves for public key and private key is not equal."
            )

        # shared secret = PUBKEYtheirs * PRIVATEKEYours
        result = (
            remote_public_key.pubkey.point
            * self.private_key.privkey.secret_multiplier
        )
        if result == INFINITY:
            raise InvalidSharedSecretError("Invalid shared secret (INFINITY).")

        return result.x()

    def set_curve(self, key_curve):
        """
        Set the working curve for ecdh operations.

        :param key_curve: curve from `curves` module
        :type key_curve: Curve
        """
        self.curve = key_curve

    def generate_private_key(self):
        """
        Generate local private key for ecdh operation with curve that was set.

        :raises NoCurveError: Curve must be set before key generation.

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        if not self.curve:
            raise NoCurveError("Curve must be set prior to key generation.")
        return self.load_private_key(SigningKey.generate(curve=self.curve))

    def load_private_key(self, private_key):
        """
        Load private key from SigningKey (keys.py) object.

        Needs to have the same curve as was set with set_curve method.
        If curve is not set - it sets from this SigningKey

        :param private_key: Initialised SigningKey class
        :type private_key: SigningKey

        :raises InvalidCurveError: private_key curve not the same as self.curve

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        if not self.curve:
            self.curve = private_key.curve
        if self.curve != private_key.curve:
            raise InvalidCurveError("Curve mismatch.")
        self.private_key = private_key
        return self.private_key.get_verifying_key()

    def load_private_key_bytes(self, private_key):
        """
        Load private key from byte string.

        Uses current curve and checks if the provided key matches
        the curve of ECDH key agreement.
        Key loads via from_string method of SigningKey class

        :param private_key: private key in bytes string format
        :type private_key: :term:`bytes-like object`

        :raises NoCurveError: Curve must be set before loading.

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        if not self.curve:
            raise NoCurveError("Curve must be set prior to key load.")
        return self.load_private_key(
            SigningKey.from_string(private_key, curve=self.curve)
        )

    def load_private_key_der(self, private_key_der):
        """
        Load private key from DER byte string.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only DER format supported is the RFC5915
        Look at keys.py:SigningKey.from_der()

        :param private_key_der: string with the DER encoding of private ECDSA
            key
        :type private_key_der: string

        :raises InvalidCurveError: private_key curve not the same as self.curve

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        return self.load_private_key(SigningKey.from_der(private_key_der))

    def load_private_key_pem(self, private_key_pem):
        """
        Load private key from PEM string.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only PEM format supported is the RFC5915
        Look at keys.py:SigningKey.from_pem()
        it needs to have `EC PRIVATE KEY` section

        :param private_key_pem: string with PEM-encoded private ECDSA key
        :type private_key_pem: string

        :raises InvalidCurveError: private_key curve not the same as self.curve

        :return: public (verifying) key from this private key.
        :rtype: VerifyingKey
        """
        return self.load_private_key(SigningKey.from_pem(private_key_pem))

    def get_public_key(self):
        """
        Provides a public key that matches the local private key.

        Needs to be sent to the remote party.

        :return: public (verifying) key from local private key.
        :rtype: VerifyingKey
        """
        return self.private_key.get_verifying_key()

    def load_received_public_key(self, public_key):
        """
        Load public key from VerifyingKey (keys.py) object.

        Needs to have the same curve as set as current for ecdh operation.
        If curve is not set - it sets it from VerifyingKey.

        :param public_key: Initialised VerifyingKey class
        :type public_key: VerifyingKey

        :raises InvalidCurveError: public_key curve not the same as self.curve
        """
        if not self.curve:
            self.curve = public_key.curve
        if self.curve != public_key.curve:
            raise InvalidCurveError("Curve mismatch.")
        self.public_key = public_key

    def load_received_public_key_bytes(
        self, public_key_str, valid_encodings=None
    ):
        """
        Load public key from byte string.

        Uses current curve and checks if key length corresponds to
        the current curve.
        Key loads via from_string method of VerifyingKey class

        :param public_key_str: public key in bytes string format
        :type public_key_str: :term:`bytes-like object`
        :param valid_encodings: list of acceptable point encoding formats,
            supported ones are: :term:`uncompressed`, :term:`compressed`,
            :term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
            name). All formats by default (specified with ``None``).
        :type valid_encodings: :term:`set-like object`
        """
        return self.load_received_public_key(
            VerifyingKey.from_string(
                public_key_str, self.curve, valid_encodings
            )
        )

    def load_received_public_key_der(self, public_key_der):
        """
        Load public key from DER byte string.

        Compares the curve of the DER-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only DER format supported is the RFC5912
        Look at keys.py:VerifyingKey.from_der()

        :param public_key_der: string with the DER encoding of public ECDSA key
        :type public_key_der: string

        :raises InvalidCurveError: public_key curve not the same as self.curve
        """
        return self.load_received_public_key(
            VerifyingKey.from_der(public_key_der)
        )

    def load_received_public_key_pem(self, public_key_pem):
        """
        Load public key from PEM string.

        Compares the curve of the PEM-encoded key with the ECDH set curve,
        uses the former if unset.

        Note, the only PEM format supported is the RFC5912
        Look at keys.py:VerifyingKey.from_pem()

        :param public_key_pem: string with PEM-encoded public ECDSA key
        :type public_key_pem: string

        :raises InvalidCurveError: public_key curve not the same as self.curve
        """
        return self.load_received_public_key(
            VerifyingKey.from_pem(public_key_pem)
        )

    def generate_sharedsecret_bytes(self):
        """
        Generate shared secret from local private key and remote public key.

        The objects needs to have both private key and received public key
        before generation is allowed.

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises NoKeyError: public_key or private_key is not set

        :return: shared secret
        :rtype: bytes
        """
        return number_to_string(
            self.generate_sharedsecret(), self.private_key.curve.curve.p()
        )

    def generate_session_key(
        self,
        length,
        hash_name="sha256",
        salt=None,
        info=None,
        context=None,
    ):
        """
        Derive a session key from the ECDH shared secret using HKDF.

        HKDF follows RFC 5869, it takes the fixed width shared secret
        (encoded to the byte size of the curve prime, so leading zero
        octets of the shared x coordinate are preserved) as input keying
        material.

        Exactly one of ``info`` and ``context`` must be provided. Use
        ``info`` for an application defined raw HKDF info or ``context``
        with an :class:`HKDFContext` to bind the key to a protocol name,
        role order and the canonical encodings of both public keys.

        :param int length: length of the derived key in octets, at most
            ``255 * HashLen``
        :param hash_name: hash name accepted by :func:`hashlib.new` (like
            ``"sha256"``) or a callable returning a fresh hash object
        :type hash_name: str or callable
        :param salt: optional HKDF salt
        :type salt: :term:`bytes-like object`
        :param info: raw HKDF info
        :type info: :term:`bytes-like object`
        :param context: structured HKDF context, the public keys used for
            the key agreement are filled in automatically
        :type context: HKDFContext

        :raises NoKeyError: public key or private key is not set
        :raises InvalidCurveError: the public and private keys use
            different curves
        :raises InvalidSharedSecretError: the shared point is at infinity
        :raises HKDFError: both ``info`` and ``context`` (or neither) are
            provided, or the context/length is invalid

        :return: derived session key
        :rtype: bytes
        """
        if info is not None and context is not None:
            raise HKDFError(
                "Only one of 'info' and 'context' can be provided."
            )
        if info is None and context is None:
            raise HKDFError(
                "Either 'info' or 'context' needs to be provided."
            )

        shared_secret = self.generate_sharedsecret_bytes()

        if context is not None:
            if not isinstance(context, HKDFContext):
                raise HKDFError(
                    "'context' must be an HKDFContext instance."
                )
            local_public_key = self.private_key.get_verifying_key()
            if context.local_role == INITIATOR:
                initiator_public_key = local_public_key
                responder_public_key = self.public_key
            else:
                initiator_public_key = self.public_key
                responder_public_key = local_public_key
            info = context.to_info(
                curve=self.curve,
                initiator_public_key=initiator_public_key,
                responder_public_key=responder_public_key,
            )

        return hkdf(
            shared_secret,
            length,
            salt=salt,
            info=info,
            hash_name=hash_name,
        )

    def generate_sharedsecret(self):
        """
        Generate shared secret from local private key and remote public key.

        The objects needs to have both private key and received public key
        before generation is allowed.

        It's the same for local and remote party,
        shared secret(local private key, remote public key) ==
        shared secret(local public key, remote private key)

        :raises InvalidCurveError: public_key curve not the same as self.curve
        :raises NoKeyError: public_key or private_key is not set

        :return: shared secret
        :rtype: int
        """
        return self._get_shared_secret(self.public_key)
