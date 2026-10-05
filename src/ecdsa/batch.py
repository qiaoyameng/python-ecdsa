"""
Batch verification of multiple ECDSA signatures over their message digests.

This module provides :func:`verify_digests`, an entry point for auditing
situations in which many records signed by a (possibly repeated) set of
public keys need to be checked in a single call.

The batch interface has three defining properties:

* Every input item produces exactly one result, in the same order.
* Items that are well enough specified to be evaluated are checked
  individually with the same arithmetic as
  :meth:`ecdsa.keys.VerifyingKey.verify_digest`; there is no random
  weighting and no "merge and pass" shortcut, so one bad signature can
  never be masked by good ones.
* Parameter problems (unparseable keys, digests of the wrong size,
  unsupported curve types, ...) and cryptographic failures (a signature
  that simply does not verify) are reported separately, as
  ``INVALID_PARAMETER`` and ``INVALID_SIGNATURE`` respectively.

Precomputation is performed at most once per distinct public key (curve
and public point), so repeated keys - including the same key supplied in
different point encodings - share the scalar multiplication table. The
precomputed state never outlives the call unless the caller passes a
:class:`VerificationCache` explicitly, and the cache has a hard capacity
bound.
"""

from collections import deque, namedtuple

from six import string_types

from . import der, ecdsa
from ._compat import normalise_bytes
from .curves import Curve
from .ellipticcurve import CurveEdTw, PointJacobi
from .keys import BadSignatureError, VerifyingKey, _truncate_and_convert_digest
from .util import MalformedSignature, sigdecode_der, sigdecode_string


VALID = "valid"
"""The signature verifies for the digest under the public key."""

INVALID_SIGNATURE = "invalid_signature"
"""All parameters were usable, but the signature does not verify."""

INVALID_PARAMETER = "invalid_parameter"
"""The item could not be evaluated because one of its parameters was bad."""


DEFAULT_MAX_KEYS = 1024
"""Default bound on the number of public keys held in one cache."""


class BatchVerifyResult(
    namedtuple("BatchVerifyResult", ["status", "error", "index"])
):
    """
    Outcome of verifying a single batch item.

    :ivar str status: one of :data:`VALID`, :data:`INVALID_SIGNATURE`,
        or :data:`INVALID_PARAMETER`.
    :ivar error: the exception describing the problem, or ``None`` when
        the status is :data:`VALID`.
    :vartype error: Exception or None
    :ivar int index: position of the corresponding item in the input
        batch
    """

    __slots__ = ()

    @property
    def valid(self):
        """True only when the signature was verified successfully."""
        return self.status == VALID

    @property
    def reason(self):
        """Machine readable name of a failure, or ``None`` on success."""
        if self.status == VALID:
            return None
        return self.status


BatchItem = namedtuple(
    "BatchItem",
    [
        "public_key",
        "digest",
        "signature",
        "curve",
        "sigdecode",
        "allow_truncate",
    ],
)
BatchItem.__new__.__defaults__ = (None, None, None)
BatchItem.__doc__ = """
One verification request.

:ivar public_key: a :class:`~ecdsa.keys.VerifyingKey` or a bytes-like
    point encoding of the public key (in which case ``curve`` is
    required).
:ivar bytes digest: the digest that the signature is supposed to
    authenticate.
:ivar signature: encoded signature (raw or DER by default, see
    ``sigdecode``).
:ivar curve: curve of an encoded public key, ignored when
    ``public_key`` is a VerifyingKey.
:ivar sigdecode: signature decoder; ``None`` inherits the batch default,
    otherwise a callable or one of the strings ``"raw"``, ``"der"``,
    ``"auto"``.
:ivar allow_truncate: ``None`` inherits the batch default, otherwise
    a boolean.
"""


def _normalise_sigdecode(sigdecode):
    """Resolve a sigdecode parameter into a callable."""
    if sigdecode is None:
        return sigdecode_string
    if callable(sigdecode):
        return sigdecode
    if sigdecode == "raw":
        return sigdecode_string
    if sigdecode == "der":
        return sigdecode_der
    if sigdecode == "auto":
        return _sigdecode_auto
    raise ValueError(
        "Unsupported sigdecode: {0!r}, use a callable, 'raw', 'der', "
        "or 'auto'".format(sigdecode)
    )


def _sigdecode_auto(signature, order):
    """
    Decode a signature that may be in raw or DER format.

    DER encodings of ECDSA signatures always start with the SEQUENCE tag
    (0x30). To keep the result deterministic, DER is tried first whenever
    the first byte is 0x30 and any failure falls back to raw decoding. A
    failure of both attempts is reported as a malformed signature, never
    as a pass.
    """
    raw = bytes(bytearray(normalise_bytes(signature)))
    if raw[:1] == b"\x30":
        try:
            return sigdecode_der(raw, order)
        except (der.UnexpectedDER, MalformedSignature):
            pass
    return sigdecode_string(raw, order)


class VerificationCache(object):
    """
    Bounded store of prepared, precomputed public keys.

    A cache is created automatically for the duration of a single
    :func:`verify_digests` call. Callers that issue several calls with an
    overlapping set of public keys can construct one themselves and pass
    it in; nothing is ever cached globally or kept alive after a call
    when no cache was supplied.

    The cache holds at most ``max_keys`` distinct public keys. New keys
    beyond that evict the oldest entry (FIFO), which keeps the memory
    footprint bounded and the behaviour independent of hash ordering.

    :ivar int key_misses: number of items whose public key had to be
        decoded and precomputed.
    :ivar int key_hits: number of items served from the cache, i.e.
        items that reused another item's public key precomputation.
    :ivar int evictions: number of times an entry was displaced to make
        room.
    """

    def __init__(self, max_keys=DEFAULT_MAX_KEYS):
        if not isinstance(max_keys, int) or isinstance(max_keys, bool):
            raise ValueError(
                "max_keys must be an int, got {0!r}".format(max_keys)
            )
        if max_keys < 1:
            raise ValueError(
                "max_keys must be a positive integer, got {0}".format(
                    max_keys
                )
            )
        self.max_keys = max_keys
        self.key_misses = 0
        self.key_hits = 0
        self.evictions = 0
        self._entries = {}
        self._order = deque()

    def __len__(self):
        return len(self._entries)

    def clear(self):
        """Drop all prepared keys and statistics."""
        self._entries.clear()
        self._order.clear()
        self.key_misses = 0
        self.key_hits = 0
        self.evictions = 0

    def get_or_prepare(self, public_key, curve=None, hashfunc=None):
        """
        Return a precomputed VerifyingKey for the given public key.

        ``public_key`` is either a VerifyingKey or a bytes-like point
        encoding (then ``curve`` is required). Keys are de-duplicated by
        the curve and the (x, y) coordinates of the public point, so raw,
        compressed and uncompressed encodings of the same point share
        one precomputation table.
        """
        if isinstance(public_key, VerifyingKey):
            curve = public_key.curve
            source_point = public_key.pubkey.point
            hashfunc = public_key.default_hashfunc
        else:
            if curve is None:
                raise ValueError(
                    "curve is required when public_key is a point "
                    "encoding"
                )
            if not isinstance(curve, Curve):
                raise ValueError(
                    "curve must be an ecdsa.curves.Curve instance"
                )
            key_bytes = bytes(bytearray(normalise_bytes(public_key)))
            # this both decodes the encoding and performs the full public
            # point validation (on-curve and, for cofactor != 1 curves,
            # the subgroup check), so it must not be skipped
            decoded = VerifyingKey.from_string(
                key_bytes, curve, hashfunc=hashfunc
            )
            source_point = decoded.pubkey.point

        if isinstance(curve.curve, CurveEdTw):
            raise ValueError(
                "Batch verification supports only short Weierstrass "
                "curves, Ed25519/Ed448 are not supported "
                "(curve: {0})".format(curve.name)
            )

        cache_key = (id(curve), source_point.x(), source_point.y())
        prepared = self._entries.get(cache_key)
        if prepared is not None:
            self.key_hits += 1
            return prepared

        self.key_misses += 1
        # Points decoded from byte encodings do not carry the curve
        # order, and a generator-style point without an order cannot
        # build its multiplication table, so construct the precomputing
        # point with the order explicitly. The point was validated either
        # by the VerifyingKey constructor (object inputs) or by
        # from_string() (encoded inputs), so validate_point=False only
        # avoids duplicate work.
        precompute_point = PointJacobi(
            curve.curve,
            source_point.x(),
            source_point.y(),
            1,
            curve.order,
            generator=True,
        )
        prepared = VerifyingKey.from_public_point(
            precompute_point,
            curve,
            hashfunc=hashfunc,
            validate_point=False,
        )
        # Build the scalar multiplication table once, eagerly, so a
        # cache hit really means the expensive work was skipped.
        prepared.precompute()
        self._entries[cache_key] = prepared
        self._order.append(cache_key)
        if len(self._order) > self.max_keys:
            oldest = self._order.popleft()
            del self._entries[oldest]
            self.evictions += 1
        return prepared


def _coerce_item(item, index):
    """Turn a supported item representation into a BatchItem."""
    if isinstance(item, BatchItem):
        return item
    if isinstance(item, dict):
        try:
            public_key = item["public_key"]
            digest = item["digest"]
            signature = item["signature"]
        except KeyError as error:
            raise ValueError(
                "item {0} is missing required field {1!r}".format(
                    index, error.args[0]
                )
            )
        return BatchItem(
            public_key,
            digest,
            signature,
            item.get("curve"),
            item.get("sigdecode"),
            item.get("allow_truncate"),
        )
    if isinstance(item, string_types):
        raise ValueError(
            "item {0} is a string, expected a BatchItem, mapping or "
            "sequence".format(index)
        )
    try:
        values = tuple(item)
    except TypeError as error:
        raise ValueError(
            "item {0} is not a BatchItem, mapping or sequence: {1}"
            .format(index, error)
        )
    if not 3 <= len(values) <= 6:
        raise ValueError(
            "item {0} must have 3 to 6 fields (public_key, digest, "
            "signature[, curve[, sigdecode[, allow_truncate]]])"
            .format(index)
        )
    return BatchItem(*(values + (None,) * (6 - len(values))))


def verify_digests(
    items,
    curve=None,
    sigdecode="auto",
    allow_truncate=False,
    cache=None,
):
    """
    Verify a batch of ECDSA signatures against message digests.

    Only short Weierstrass curves are supported; Ed25519/Ed448 items are
    reported as :data:`INVALID_PARAMETER`. Curves, digest lengths and
    signature encodings may be mixed freely within one batch.

    Each result status distinguishes:

    * :data:`VALID` - same outcome as
      :meth:`~ecdsa.keys.VerifyingKey.verify_digest` returning True,
    * :data:`INVALID_SIGNATURE` - the signature is malformed or does
      not verify (the analogue of
      :class:`~ecdsa.keys.BadSignatureError`),
    * :data:`INVALID_PARAMETER` - the request itself is unusable, e.g.
      the public key encoding is invalid, the digest is too long without
      ``allow_truncate`` (the analogue of
      :class:`~ecdsa.keys.BadDigestError`), or the curve is unsupported.

    :param items: iterable of :class:`BatchItem`, mappings, or sequences
        ``(public_key, digest, signature[, curve[, sigdecode[,
        allow_truncate]]])``. ``public_key`` is either a
        :class:`~ecdsa.keys.VerifyingKey` or a bytes-like point
        encoding; an encoded key requires a curve, given per item or
        with the ``curve`` argument.
    :param curve: default curve for items that provide an encoded public
        key without an item-level curve.
    :param sigdecode: default signature decoder: a callable, or one of
        ``"raw"``, ``"der"`` or ``"auto"`` (default; deterministic DER
        with raw fallback, see :func:`_sigdecode_auto`). Item-level
        values override this.
    :param bool allow_truncate: default for whether digests longer than
        the curve order may be truncated. Item-level values override
        this.
    :param cache: an explicit :class:`VerificationCache` to share
        between calls. When ``None`` (default), a fresh cache is
        created and discarded at the end of this call.
    :type cache: VerificationCache or None

    :return: a list of :class:`BatchVerifyResult`, one per input item,
        in order. An empty batch yields an empty list.
    :rtype: list
    """
    default_decode = _normalise_sigdecode(sigdecode)

    items = list(items)
    own_cache = cache is None
    if own_cache:
        cache = VerificationCache()

    results = []
    for index, raw_item in enumerate(items):
        try:
            item = _coerce_item(raw_item, index)
            item_curve = item.curve if item.curve is not None else curve
            if item.sigdecode is None:
                decoder = default_decode
            else:
                decoder = _normalise_sigdecode(item.sigdecode)
            truncate = (
                allow_truncate
                if item.allow_truncate is None
                else item.allow_truncate
            )
            prepared = cache.get_or_prepare(item.public_key, item_curve)
            digest = bytes(bytearray(normalise_bytes(item.digest)))
            number = _truncate_and_convert_digest(
                digest, prepared.curve, truncate
            )
            try:
                r, s = decoder(item.signature, prepared.pubkey.order)
            except (der.UnexpectedDER, MalformedSignature) as decode_error:
                raise BadSignatureError(
                    "Malformed formatting of signature", decode_error
                )
            signature = ecdsa.Signature(r, s)
            if prepared.pubkey.verifies(number, signature):
                results.append(BatchVerifyResult(VALID, None, index))
            else:
                results.append(
                    BatchVerifyResult(
                        INVALID_SIGNATURE,
                        BadSignatureError("Signature verification failed"),
                        index,
                    )
                )
        except BadSignatureError as error:
            results.append(
                BatchVerifyResult(INVALID_SIGNATURE, error, index)
            )
        except Exception as error:
            results.append(
                BatchVerifyResult(INVALID_PARAMETER, error, index)
            )

    if own_cache:
        # The cache must not outlive the call that created it.
        cache.clear()
    return results
