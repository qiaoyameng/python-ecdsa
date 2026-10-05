"""
HMAC-based Key Derivation Function (HKDF) as described in RFC 5869.

The module provides the two HKDF stages (:func:`hkdf_extract` and
:func:`hkdf_expand`) and the combined :func:`hkdf` function.

Unlike a plain hash over a shared secret, HKDF takes an explicit salt and
context (``info``), turns potentially weak source key material into a
pseudorandom key and derives output of an application defined length.

Only the Python standard library (:mod:`hmac` and :mod:`hashlib`) is used,
so no new crypto backend dependency is introduced.
"""

import hmac
import hashlib

from six import int2byte

from ._compat import normalise_bytes


__all__ = [
    "hkdf",
    "hkdf_extract",
    "hkdf_expand",
    "HKDFError",
]


class HKDFError(Exception):
    """Raised when HKDF parameters are invalid."""

    pass


def _to_hash(hash_name):
    """
    Turn a hash specification into a hash constructor.

    :param hash_name: hash name accepted by :func:`hashlib.new` (like
        ``"sha256"``) or a callable returning a fresh hash object.
    :type hash_name: str or callable

    :return: hash constructor
    :rtype: callable
    """
    if hash_name is None:
        raise HKDFError("Hash function needs to be specified.")
    if isinstance(hash_name, str):
        try:
            hashlib.new(hash_name)
        except (ValueError, TypeError):
            raise HKDFError("Unsupported hash name: {0!r}.".format(hash_name))

        def hash_factory(data=b""):
            return hashlib.new(hash_name, data)

        return hash_factory
    if callable(hash_name):
        return hash_name
    raise HKDFError(
        "Hash needs to be a hashlib algorithm name or a callable."
    )


def _hmac_digest(hash_factory, key, message):
    """Return ``HMAC(key, message)`` using ``hash_factory``."""
    return hmac.new(
        bytes(normalise_bytes(key)),
        bytes(normalise_bytes(message)),
        digestmod=hash_factory,
    ).digest()


def hkdf_extract(salt, input_key_material, hash_name="sha256"):
    """
    HKDF-Extract, the first stage of HKDF (RFC 5869, section 2.2).

    If ``salt`` is not provided or is empty, a string of ``HashLen`` zero
    octets is used, as specified by the RFC.

    :param salt: optional salt value (a non-secret random value)
    :type salt: :term:`bytes-like object`
    :param input_key_material: input keying material, e.g. an ECDH shared
        secret
    :type input_key_material: :term:`bytes-like object`
    :param hash_name: hash name accepted by :func:`hashlib.new` (like
        ``"sha256"``) or a callable returning a fresh hash object
    :type hash_name: str or callable

    :return: a pseudorandom key of ``HashLen`` octets
    :rtype: bytes
    """
    hash_factory = _to_hash(hash_name)
    if salt is None:
        salt = b""
    else:
        salt = bytes(normalise_bytes(salt))
    if not salt:
        salt = b"\x00" * hash_factory().digest_size
    return _hmac_digest(
        hash_factory, salt, normalise_bytes(input_key_material)
    )


def hkdf_expand(pseudo_random_key, length, info=b"", hash_name="sha256"):
    """
    HKDF-Expand, the second stage of HKDF (RFC 5869, section 2.3).

    :param pseudo_random_key: pseudorandom key of at least ``HashLen``
        octets, usually the output of :func:`hkdf_extract`
    :type pseudo_random_key: :term:`bytes-like object`
    :param length: length of the output keying material in octets, it has
        to be at most ``255 * HashLen``
    :type length: int
    :param info: optional context and application specific information
    :type info: :term:`bytes-like object`
    :param hash_name: hash name accepted by :func:`hashlib.new` (like
        ``"sha256"``) or a callable returning a fresh hash object
    :type hash_name: str or callable

    :raises HKDFError: ``length`` is not a positive integer within the
        RFC limit or the pseudorandom key is shorter than ``HashLen``

    :return: output keying material of ``length`` octets
    :rtype: bytes
    """
    hash_factory = _to_hash(hash_name)
    hash_len = hash_factory().digest_size

    if not isinstance(length, int) or isinstance(length, bool):
        raise HKDFError("Output length needs to be an integer.")
    if length <= 0:
        raise HKDFError("Output length needs to be a positive integer.")
    if length > 255 * hash_len:
        raise HKDFError(
            "Output length too large for the selected hash function "
            "(maximum is {0} bytes).".format(255 * hash_len)
        )

    prk = bytes(normalise_bytes(pseudo_random_key))
    if len(prk) < hash_len:
        raise HKDFError(
            "Pseudorandom key is shorter than the hash output length."
        )

    if info is None:
        info = b""
    else:
        info = bytes(normalise_bytes(info))

    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = _hmac_digest(
            hash_factory, prk, previous + info + int2byte(counter)
        )
        output += previous
        counter += 1

    return output[:length]


def hkdf(input_key_material, length, salt=None, info=b"", hash_name="sha256"):
    """
    HKDF, HMAC-based Extract-and-Expand Key Derivation Function.

    Implements HKDF as defined in RFC 5869.

    :param input_key_material: input keying material, e.g. an ECDH shared
        secret
    :type input_key_material: :term:`bytes-like object`
    :param length: length of the output keying material in octets, it has
        to be at most ``255 * HashLen``
    :type length: int
    :param salt: optional salt value (a non-secret random value)
    :type salt: :term:`bytes-like object`
    :param info: optional context and application specific information
    :type info: :term:`bytes-like object`
    :param hash_name: hash name accepted by :func:`hashlib.new` (like
        ``"sha256"``) or a callable returning a fresh hash object
    :type hash_name: str or callable

    :raises HKDFError: the parameters do not satisfy the RFC 5869 limits

    :return: output keying material of ``length`` octets
    :rtype: bytes
    """
    prk = hkdf_extract(salt, input_key_material, hash_name)
    return hkdf_expand(prk, length, info, hash_name)
