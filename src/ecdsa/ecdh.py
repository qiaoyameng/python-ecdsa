"""
Class for performing Elliptic-curve Diffie-Hellman (ECDH) operations.
"""

import struct

from hashlib import sha256

from ._compat import normalise_bytes
from .hkdf import HKDFError, hkdf
from .util import number_to_string
from .ellipticcurve import INFINITY, CurveEdTw
from .keys import SigningKey, VerifyingKey


__all__ = [
    "ECDH",
    "NoKeyError",
    "NoCurveError",
    "InvalidCurveError",
    "InvalidSharedSecretError",
    "InvalidContextError",
    "HKDFContext",
    "HKDFError",
]


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


class InvalidContextError(ValueError):
    """
    ECDH/HKDF. Raised when the structured derivation context is invalid.

    Covers an invalid protocol name, public keys encoded on different
    (or unsupported) curves, public keys with an illegal encoding
    length, and context keys that do not match the local and the
    remote public key used by the ECDH agreement.
    """

    pass


def _length_prefixed(field):
    """
    Encode a single field with an unambiguous 2-octet length prefix.

    The length is encoded as a big-endian unsigned integer so that
    concatenating fields can never be ambiguous.
    """
    if len(field) > 0xFFFF:
        raise InvalidContextError(
            "Context field is too long to encode unambiguously, maximum "
            "is 65535 octets."
        )
    return struct.pack(">H", len(field)) + bytes(bytearray(field))


def _as_bytes(value, parameter_name):
    """
    Cast a bytes-like parameter to bytes or raise a clean HKDFError.

    Keeps the underlying keying material out of any error message.
    """
    try:
        return bytes(bytearray(normalise_bytes(value)))
    except TypeError:
        raise HKDFError(
            "{0} needs to be a bytes-like object.".format(parameter_name)
        )


class HKDFContext(object):
    """
    Structured context binding an HKDF derivation to a protocol run.

    The context binds:

    * the protocol name,
    * the role order (initiator and responder), and
    * both public keys in their canonical, unambiguous encoding.

    Public keys are encoded in canonical SEC1 uncompressed form
    (``0x04 || X || Y``) with both coordinates zero-padded to the
    field size of the curve. Every field is prefixed with its 2-octet
    big-endian length, so the encoding never relies on bare
    concatenation. The initiator's key is always encoded first and the
    responder's key second; the keys are deliberately never sorted, so
    swapping the two parties produces a different derived key.

    Both parties construct the context with the keys in the same roles
    and get an identical encoding regardless of which of the two keys
    is their own.
    """

    def __init__(
        self, protocol, initiator_public_key, responder_public_key
    ):
        """
        :param protocol: domain separation label identifying the
            application protocol, e.g. ``b"my-protocol-v1"``
        :type protocol: :term:`bytes-like object`
        :param initiator_public_key: public key of the party that
            initiated the key agreement
        :type initiator_public_key: VerifyingKey
        :param responder_public_key: public key of the party that
            responded to the key agreement
        :type responder_public_key: VerifyingKey

        :raises InvalidContextError: protocol is not bytes-like, keys
            are not VerifyingKey objects, keys use different or
            unsupported curves or have an illegal encoding length
        """
        if not isinstance(initiator_public_key, VerifyingKey):
            raise InvalidContextError(
                "initiator_public_key needs to be a VerifyingKey object."
            )
        if not isinstance(responder_public_key, VerifyingKey):
            raise InvalidContextError(
                "responder_public_key needs to be a VerifyingKey object."
            )
        if initiator_public_key.curve != responder_public_key.curve:
            raise InvalidContextError(
                "Public keys in the context need to use the same curve."
            )
        curve = initiator_public_key.curve
        if isinstance(curve.curve, CurveEdTw):
            raise InvalidContextError(
                "HKDF contexts are not supported for Edwards curves."
            )
        try:
            protocol_bytes = bytes(
                bytearray(normalise_bytes(protocol))
            )
        except TypeError:
            raise InvalidContextError(
                "protocol needs to be a bytes-like object."
            )

        initiator_encoding = self._canonical_public_key(
            initiator_public_key
        )
        responder_encoding = self._canonical_public_key(
            responder_public_key
        )
        if initiator_encoding == responder_encoding:
            raise InvalidContextError(
                "Initiator and responder public keys must be different."
            )

        self.protocol = protocol_bytes
        self.initiator_public_key = initiator_public_key
        self.responder_public_key = responder_public_key
        self._encoding = (
            _length_prefixed(protocol_bytes)
            + _length_prefixed(initiator_encoding)
            + _length_prefixed(responder_encoding)
        )

    @staticmethod
    def _canonical_public_key(public_key):
        """
        Return the canonical, fixed-width encoding of a public key.

        Uses SEC1 uncompressed encoding (0x04 prefix followed by the
        ``X`` and ``Y`` coordinates, each zero-padded to the field
        size) and rejects the result if it does not have the exact
        length prescribed by the curve.
        """
        curve = public_key.curve
        expected_length = 1 + curve.verifying_key_length
        try:
            encoded = bytes(
                bytearray(public_key.to_string("uncompressed"))
            )
        except (TypeError, ValueError):
            raise InvalidContextError(
                "Public key could not be encoded canonically."
            )
        if len(encoded) != expected_length:
            raise InvalidContextError(
                "Illegal public key encoding length for the curve, "
                "expected {0} octets, got {1}.".format(
                    expected_length, len(encoded)
                )
            )
        return encoded

    def encode_with(self, local_public_key, remote_public_key):
        """
        Return the context encoding verified against the ECDH parties.

        Checks that ``local_public_key`` is one of the context roles
        (initiator or responder) and ``remote_public_key`` is the other
        one. The returned encoding always keeps the initiator first and
        the responder second, it is independent of which side calls
        this method.

        :param local_public_key: public key matching the local private
            key used by the ECDH agreement
        :type local_public_key: VerifyingKey
        :param remote_public_key: public key received from the remote
            party
        :type remote_public_key: VerifyingKey

        :raises InvalidContextError: local or remote key does not match
            either context role or both match the same role

        :return: length-prefixed encoding of the context
        :rtype: bytes
        """
        if not isinstance(local_public_key, VerifyingKey):
            raise InvalidContextError(
                "local_public_key needs to be a VerifyingKey object."
            )
        if not isinstance(remote_public_key, VerifyingKey):
            raise InvalidContextError(
                "remote_public_key needs to be a VerifyingKey object."
            )
        local_encoding = self._canonical_public_key(local_public_key)
        remote_encoding = self._canonical_public_key(remote_public_key)
        initiator_encoding = self._canonical_public_key(
            self.initiator_public_key
        )
        responder_encoding = self._canonical_public_key(
            self.responder_public_key
        )
        if local_encoding not in (initiator_encoding, responder_encoding):
            raise InvalidContextError(
                "Local public key does not match any context role."
            )
        if remote_encoding not in (
            initiator_encoding,
            responder_encoding,
        ):
            raise InvalidContextError(
                "Remote public key does not match any context role."
            )
        if local_encoding == remote_encoding:
            raise InvalidContextError(
                "Local and remote public keys must be different."
            )
        return self._encoding

    def matches_role(self, role, public_key):
        """
        Check whether a public key is bound to the given context role.

        :param str role: ``"initiator"`` or ``"responder"``
        :param public_key: the public key to check
        :type public_key: VerifyingKey

        :raises InvalidContextError: when the role name is unknown or
            the key does not match the role
        """
        if role == "initiator":
            role_key = self.initiator_public_key
        elif role == "responder":
            role_key = self.responder_public_key
        else:
            raise InvalidContextError(
                "role needs to be either 'initiator' or 'responder'."
            )
        if not isinstance(public_key, VerifyingKey):
            raise InvalidContextError(
                "public_key needs to be a VerifyingKey object."
            )
        if self._canonical_public_key(role_key) != (
            self._canonical_public_key(public_key)
        ):
            raise InvalidContextError(
                "Local public key does not match the '{0}' role of the "
                "context.".format(role)
            )


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

    def derive_key(
        self,
        length,
        salt=None,
        info=None,
        context=None,
        role=None,
        hashfunc=sha256,
    ):
        """
        Derive a key from the shared secret using HKDF (RFC 5869).

        This is the explicit, standardised key derivation entry point.
        The ECDH shared secret is encoded with the fixed byte width
        mandated by the curve (leading zero octets of the shared
        coordinate are preserved) and is then passed through
        HKDF-Extract and HKDF-Expand with the selected hash function.

        :param int length: length of the derived key in octets, needs
            to be a positive integer not greater than 255*HashLen
        :param salt: optional HKDF salt, defaults to HashLen zero
            octets as specified by RFC 5869 when not provided
        :type salt: :term:`bytes-like object`
        :param info: optional application specific information included
            in HKDF-Expand; passed verbatim when no ``context`` is
            provided. When a ``context`` is provided too, the info and
            the context encoding are combined with length prefixes so
            that the boundary between them is unambiguous
        :type info: :term:`bytes-like object`
        :param context: optional structured context binding the
            protocol name, role order and both canonical public keys;
            see :class:`HKDFContext`
        :type context: HKDFContext
        :param str role: role of the local party in the key agreement,
            either ``"initiator"`` or ``"responder"``; required to
            detect a mismatch when a ``context`` is provided, it
            prevents silently swapping the initiator and responder
        :param hashfunc: hash constructor (like :class:`hashlib.sha256`)
            or a hash object (like ``hashlib.sha256()``) used by HKDF,
            defaults to SHA-256
        :type hashfunc: callable or hashlib hash object

        :raises NoKeyError: public key or private key is not set
        :raises InvalidCurveError: public key curve not the same as
            the private key curve
        :raises InvalidSharedSecretError: the shared point is INFINITY
        :raises InvalidContextError: the context does not match the
            local and the remote public keys
        :raises HKDFError: salt or info is not bytes-like or
            ``length`` is invalid for the selected hash

        :return: derived key of ``length`` octets
        :rtype: bytes
        """
        # The fixed-width shared secret is generated first, this also
        # performs all the key, curve and INFINITY validation.
        shared_secret = self.generate_sharedsecret_bytes()

        if context is not None:
            if not isinstance(context, HKDFContext):
                raise HKDFError(
                    "context needs to be an HKDFContext object."
                )
            local_public_key = self.private_key.get_verifying_key()
            if role is None:
                raise InvalidContextError(
                    "role ('initiator' or 'responder') needs to be "
                    "provided when a context is used."
                )
            context.matches_role(role, local_public_key)
            context_encoding = context.encode_with(
                local_public_key, self.public_key
            )
            hkdf_info = _length_prefixed(
                b"" if info is None else _as_bytes(info, "info")
            ) + _length_prefixed(context_encoding)
        else:
            hkdf_info = b"" if info is None else _as_bytes(info, "info")

        hkdf_salt = b"" if salt is None else _as_bytes(salt, "salt")

        return hkdf(
            hkdf_salt,
            shared_secret,
            hkdf_info,
            length,
            hashfunc,
        )
