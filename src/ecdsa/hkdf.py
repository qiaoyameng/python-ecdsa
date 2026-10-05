"""
RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF).

Provides explicit, standardised key derivation so that applications do
not need to hash the raw ECDH shared secret (or concatenate strings)
themselves, which historically caused interoperability problems.

The module uses only the Python standard library (:mod:`hmac` and
:mod:`hashlib`), it does not add any new cryptographic back-end
dependencies.
"""

import hmac

from ._compat import hmac_compat, normalise_bytes


__all__ = [
    "HKDFError",
    "hkdf_extract",
    "hkdf_expand",
    "hkdf",
]


class HKDFError(ValueError):
    """
    HKDF. Raised when a parameter passed to HKDF is invalid.

    Error messages never include the input keying material (e.g. the
    ECDH shared secret) as leaking it would defeat the purpose of the
    key derivation.
    """

    pass


def _hash_factory(hashfunc):
    """
    Normalise the ``hashfunc`` parameter to a zero-argument callable.

    Accepts either a hash constructor (like :class:`hashlib.sha256`)
    or an already constructed hash object (like ``hashlib.sha256()``),
    both are commonly accepted throughout the library.

    :param hashfunc: hash constructor or hash object implementing the
        :mod:`hashlib` interface
    :type hashfunc: callable or hashlib hash object

    :raises HKDFError: when the parameter is not a usable hash

    :return: zero-argument callable returning a fresh hash object
    :rtype: callable
    """
    if hashfunc is None:
        raise HKDFError(
            "hashfunc needs to be provided, e.g. hashlib.sha256."
        )
    try:
        digest_size = hashfunc().digest_size
    except (TypeError, AttributeError):
        try:
            digest_size = hashfunc.digest_size
        except AttributeError:
            raise HKDFError(
                "hashfunc needs to be a hash constructor (like "
                "hashlib.sha256) or a hash object (like "
                "hashlib.sha256())."
            )

        hash_object = hashfunc

        def hashfunc():
            return hash_object.copy()

    if not digest_size:
        raise HKDFError("hashfunc does not provide a valid digest size.")
    return hashfunc


def hkdf_extract(salt, input_key_material, hashfunc):
    """
    HKDF-Extract step from section 2.2 of RFC 5869.

    :param salt: optional salt value (a non-secret random value); if
        not provided, it is set to a string of HashLen zeros
    :type salt: :term:`bytes-like object`
    :param input_key_material: input keying material, e.g. the
        fixed-width ECDH shared secret
    :type input_key_material: :term:`bytes-like object`
    :param hashfunc: a hash constructor (like :class:`hashlib.sha256`)
        or a hash object (like ``hashlib.sha256()``)
    :type hashfunc: callable or hashlib hash object

    :raises HKDFError: when a parameter has an invalid type or value

    :return: a pseudorandom key of HashLen octets
    :rtype: bytes
    """
    hashfunc = _hash_factory(hashfunc)
    hash_len = hashfunc().digest_size
    salt = normalise_bytes(salt) if salt else b"\x00" * hash_len
    input_key_material = normalise_bytes(input_key_material)
    return hmac.new(
        hmac_compat(bytes(bytearray(salt))),
        hmac_compat(bytes(bytearray(input_key_material))),
        hashfunc,
    ).digest()


def hkdf_expand(pseudo_random_key, info, length, hashfunc):
    """
    HKDF-Expand step from section 2.3 of RFC 5869.

    :param pseudo_random_key: pseudorandom key of at least HashLen
        octets (usually, the output from HKDF-Extract)
    :type pseudo_random_key: :term:`bytes-like object`
    :param info: optional context and application specific information
        (can be a zero-length string)
    :type info: :term:`bytes-like object`
    :param int length: length of output keying material in octets,
        must be a positive integer not greater than 255*HashLen
    :param hashfunc: a hash constructor (like :class:`hashlib.sha256`)
        or a hash object (like ``hashlib.sha256()``)
    :type hashfunc: callable or hashlib hash object

    :raises HKDFError: when a parameter has an invalid type or value

    :return: output keying material of ``length`` octets
    :rtype: bytes
    """
    hashfunc = _hash_factory(hashfunc)
    hash_len = hashfunc().digest_size
    if not isinstance(length, int) or isinstance(length, bool):
        raise HKDFError("length needs to be an integer.")
    if length <= 0:
        raise HKDFError("length needs to be a positive integer.")
    max_length = 255 * hash_len
    if length > max_length:
        raise HKDFError(
            "length {0} is too long for the selected hash, maximum is "
            "{1} octets.".format(length, max_length)
        )
    try:
        pseudo_random_key = bytes(
            bytearray(normalise_bytes(pseudo_random_key))
        )
        info = bytes(bytearray(normalise_bytes(info))) if info else b""
    except TypeError:
        raise HKDFError(
            "pseudo_random_key and info need to be bytes-like objects."
        )
    if len(pseudo_random_key) < hash_len:
        raise HKDFError(
            "pseudo_random_key is too short, it needs to be at least "
            "{0} octets long.".format(hash_len)
        )

    okm = b""
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(
            pseudo_random_key,
            hmac_compat(previous + info + bytes(bytearray([counter]))),
            hashfunc,
        ).digest()
        okm += previous
        counter += 1
    return okm[:length]


def hkdf(salt, input_key_material, info, length, hashfunc):
    """
    HKDF key derivation function from section 2 of RFC 5869.

    It combines :func:`hkdf_extract` and :func:`hkdf_expand`::

        PRK = HMAC-Hash(salt, IKM)
        OKM = HKDF-Expand(PRK, info, L)

    :param salt: optional salt value (a non-secret random value); if
        not provided, it is set to a string of HashLen zeros
    :type salt: :term:`bytes-like object`
    :param input_key_material: input keying material, e.g. the
        fixed-width ECDH shared secret
    :type input_key_material: :term:`bytes-like object`
    :param info: optional context and application specific information
        (can be a zero-length string)
    :type info: :term:`bytes-like object`
    :param int length: length of output keying material in octets,
        must be a positive integer not greater than 255*HashLen
    :param hashfunc: a hash constructor (like :class:`hashlib.sha256`)
        or a hash object (like ``hashlib.sha256()``)
    :type hashfunc: callable or hashlib hash object

    :raises HKDFError: when a parameter has an invalid type or value

    :return: output keying material of ``length`` octets
    :rtype: bytes
    """
    prk = hkdf_extract(salt, input_key_material, hashfunc)
    return hkdf_expand(prk, info, length, hashfunc)
