"""
Compact recoverable ECDSA signatures.

The wire format is the fixed-length raw encoding of ``r`` followed by ``s``
and one recovery-ID byte. Recovery IDs 0 and 1 use ``r`` as the x-coordinate
of the nonce point; IDs 2 and 3 use ``r + n``. The low bit selects the point
y-coordinate's parity.
"""

from hashlib import sha256

from . import ecdsa
from ._compat import normalise_bytes
from .curves import NIST256p, SECP256k1
from .errors import MalformedPointError
from .keys import VerifyingKey, _truncate_and_convert_digest
from .util import randrange
from .util import sigdecode_string_recoverable
from .util import sigencode_string_recoverable


SUPPORTED_CURVES = (SECP256k1, NIST256p)

__all__ = [
    "SUPPORTED_CURVES",
    "sign_recoverable",
    "sign_recoverable_digest",
    "recover_public_key",
    "recover_public_key_from_data",
    "sigencode_string_recoverable",
    "sigdecode_string_recoverable",
]


def _check_curve(curve):
    if curve not in SUPPORTED_CURVES:
        raise ValueError(
            "Recoverable ECDSA is supported only for SECP256k1 and NIST256p"
        )


def sign_recoverable_digest(
    signing_key,
    digest,
    entropy=None,
    k=None,
    allow_truncate=False,
    low_s=True,
):
    """
    Create a compact recoverable signature over a digest.

    :param signing_key: the private key used for signing
    :type signing_key: ~ecdsa.keys.SigningKey
    :param digest: hash value that will be signed
    :type digest: bytes-like object
    :param callable entropy: randomness source, os.urandom by default
    :param int k: optional pre-selected ECDSA nonce
    :param bool allow_truncate: truncate ``digest`` in the same way as
        :meth:`~ecdsa.keys.SigningKey.sign_digest` and
        :meth:`~ecdsa.keys.VerifyingKey.verify_digest`
    :param bool low_s: normalise ``s`` to the lower half of the order and
        flip the recovery ID's parity bit when required
    :rtype: bytes
    """
    _check_curve(signing_key.curve)
    digest = normalise_bytes(digest)
    number = _truncate_and_convert_digest(
        digest, signing_key.curve, allow_truncate
    )
    order = signing_key.curve.order
    if k is None:
        k = randrange(order, entropy)

    signature, recovery_id = signing_key.privkey.sign_with_recovery(
        number, k, low_s
    )
    return sigencode_string_recoverable(
        signature.r, signature.s, recovery_id, order
    )


def sign_recoverable(
    signing_key,
    data,
    entropy=None,
    hashfunc=sha256,
    k=None,
    allow_truncate=True,
    low_s=True,
):
    """Create a compact recoverable signature over data."""
    digest = hashfunc(normalise_bytes(data)).digest()
    return sign_recoverable_digest(
        signing_key,
        digest,
        entropy=entropy,
        k=k,
        allow_truncate=allow_truncate,
        low_s=low_s,
    )


def recover_public_key(
    signature,
    digest,
    curve,
    hashfunc=sha256,
    allow_truncate=False,
):
    """
    Recover the one public key selected by a compact signature.

    The recovered key is independently checked with the ordinary
    :meth:`~ecdsa.keys.VerifyingKey.verify_digest` method before it is
    returned.
    """
    _check_curve(curve)
    signature = normalise_bytes(signature)
    digest = normalise_bytes(digest)
    order = curve.order
    r, s, recovery_id = sigdecode_string_recoverable(signature, order)
    number = _truncate_and_convert_digest(digest, curve, allow_truncate)
    sig = ecdsa.Signature(r, s)
    try:
        public_key = sig.recover_public_key(
            number, curve.generator, recovery_id
        )
        verifying_key = VerifyingKey.from_public_point(
            public_key.point, curve, hashfunc
        )
    except (
        ecdsa.InvalidRecoveryIdError,
        ecdsa.InvalidPointError,
        MalformedPointError,
    ) as error:
        raise ecdsa.InvalidRecoveryIdError(str(error))

    verifying_key.verify_digest(
        signature[:-1],
        digest,
        allow_truncate=allow_truncate,
    )
    return verifying_key


def recover_public_key_from_data(
    signature,
    data,
    curve,
    hashfunc=sha256,
    allow_truncate=True,
):
    """Recover the public key from a compact signature over data."""
    digest = hashfunc(normalise_bytes(data)).digest()
    return recover_public_key(
        signature,
        digest,
        curve,
        hashfunc=hashfunc,
        allow_truncate=allow_truncate,
    )
