"""Batch verification of ECDSA signatures over precomputed digests."""

from collections import namedtuple

from . import der
from ._compat import normalise_bytes
from .curves import Curve
from .ecdsa import Public_key, Signature
from .ellipticcurve import CurveEdTw, PointJacobi
from .keys import (
    BadDigestError,
    BadSignatureError,
    MalformedPointError,
    VerifyingKey,
    _truncate_and_convert_digest,
)
from .util import MalformedSignature, sigdecode_der, sigdecode_string


VALID = "valid"
INVALID = "invalid"
PARAMETER_ERROR = "parameter_error"

_RAW_SIGNATURE = "raw"
_DER_SIGNATURE = "der"
_RAW_PUBLIC_KEY = "raw"
_DER_PUBLIC_KEY = "der"

class BatchVerificationRequest(
    namedtuple(
        "_BatchVerificationRequest",
        [
            "public_key",
            "signature",
            "digest",
            "curve",
            "signature_format",
            "public_key_format",
        ],
    )
):
    __slots__ = ()

    def __new__(
        cls,
        public_key,
        signature,
        digest,
        curve,
        signature_format="raw",
        public_key_format="auto",
    ):
        return super(BatchVerificationRequest, cls).__new__(
            cls,
            public_key,
            signature,
            digest,
            curve,
            signature_format,
            public_key_format,
        )

BatchVerificationStats = namedtuple(
    "BatchVerificationStats",
    [
        "records",
        "unique_keys",
        "unique_curves",
        "key_hits",
        "key_misses",
        "curve_hits",
        "curve_misses",
        "keys_precomputed",
        "curves_precomputed",
    ],
)


class BatchVerificationResult(object):
    """Result of verifying one signature in a batch."""

    def __init__(self, status, error=None, error_type=None):
        self.status = status
        self.error = error
        self.error_type = error_type

    def __bool__(self):
        return self.status == VALID

    __nonzero__ = __bool__

    def __repr__(self):
        if self.error is None:
            return "BatchVerificationResult({0!r})".format(self.status)
        return "BatchVerificationResult({0!r}, {1!r})".format(
            self.status, self.error
        )

    def __eq__(self, other):
        if isinstance(other, BatchVerificationResult):
            return (
                self.status == other.status
                and self.error == other.error
                and self.error_type == other.error_type
            )
        if isinstance(other, bool):
            return bool(self) == other
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.status, self.error, self.error_type))


def valid_signature():
    """Return the result for a signature that verifies."""
    return BatchVerificationResult(VALID)


def invalid_signature(error):
    """Return the result for a malformed or non-matching signature."""
    return BatchVerificationResult(
        INVALID,
        error,
        type(error),
    )


def parameter_error(error):
    """Return the result for an invalid verification parameter."""
    return BatchVerificationResult(
        PARAMETER_ERROR,
        error,
        type(error),
    )


class BatchVerificationCache(object):
    """
    Bounded precomputation table cache for batch verification.

    The cache is not global. Pass one instance to multiple batch calls to
    retain precomputations; omit it to limit precomputations to one call.
    """

    def __init__(self, max_entries=1024):
        if isinstance(max_entries, bool) or not isinstance(
            max_entries, int
        ):
            raise TypeError("max_entries must be a positive integer")
        if max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        self.max_entries = max_entries
        self._keys = {}
        self._curves = {}
        self.records = 0
        self.key_hits = 0
        self.key_misses = 0
        self.curve_hits = 0
        self.curve_misses = 0
        self.keys_precomputed = 0
        self.curves_precomputed = 0

    def __len__(self):
        return len(self._keys)

    @property
    def stats(self):
        """Return counters useful for proving precomputation reuse."""
        return BatchVerificationStats(
            self.records,
            len(self._keys),
            len(self._curves),
            self.key_hits,
            self.key_misses,
            self.curve_hits,
            self.curve_misses,
            self.keys_precomputed,
            self.curves_precomputed,
        )

    def record_checked(self):
        self.records += 1

    def prepare_key(self, verifying_key):
        """Return a cached key and generator for a parsed public key."""
        curve = verifying_key.curve
        curve_id = _curve_identity(curve)
        generator = self._curves.get(curve_id)
        if generator is not None:
            self.curve_hits += 1
        else:
            self.curve_misses += 1
            generator = PointJacobi(
                curve.curve,
                curve.generator.x(),
                curve.generator.y(),
                1,
                curve.order,
                generator=True,
            )
            generator._maybe_precompute()
            self.curves_precomputed += 1
            self._curves[curve_id] = generator
            self._evict_if_needed(self._curves)

        point = verifying_key.pubkey.point
        key_id = (curve_id, point.x(), point.y())
        public_key = self._keys.get(key_id)
        if public_key is not None:
            self.key_hits += 1
        else:
            self.key_misses += 1
            cached_point = PointJacobi(
                curve.curve,
                point.x(),
                point.y(),
                1,
                curve.order,
                generator=True,
            )
            public_key = Public_key(generator, cached_point, verify=False)
            public_key.order = curve.order
            cached_point._maybe_precompute()
            self.keys_precomputed += 1
            self._keys[key_id] = public_key
            self._evict_if_needed(self._keys)
        return public_key

    def _evict_if_needed(self, entries):
        while len(entries) > self.max_entries:
            oldest = next(iter(entries))
            del entries[oldest]
            if entries is self._curves:
                self._remove_keys_for_curve(oldest)
            else:
                self._remove_orphaned_curves()

    def _remove_keys_for_curve(self, curve_id):
        for key_id in list(self._keys):
            if key_id[0] == curve_id:
                del self._keys[key_id]

    def _remove_orphaned_curves(self):
        curve_ids = set(key_id[0] for key_id in self._keys)
        for curve_id in list(self._curves):
            if curve_id not in curve_ids:
                del self._curves[curve_id]


def _curve_identity(curve):
    return (
        curve.curve.p(),
        curve.curve.a(),
        curve.curve.b(),
        curve.curve.cofactor(),
        curve.order,
        curve.generator.x(),
        curve.generator.y(),
    )


def batch_verify_digests(
    records,
    sigdecode=None,
    allow_truncate=False,
    cache=None,
    max_cache_entries=1024,
):
    """
    Verify a batch of ECDSA signatures over precomputed digests.

    Each tuple record is ``(public_key, signature, digest, curve)``; append
    ``"der"`` as a fifth element for a DER signature, or a custom decoder.
    Dictionaries and :class:`BatchVerificationRequest` values are accepted
    too. Dictionaries may set ``public_key_format`` or ``key_format`` to
    ``"raw"`` or ``"der"``; encoding is detected automatically by default.
    """
    if cache is None:
        cache = BatchVerificationCache(max_cache_entries)
    elif not isinstance(cache, BatchVerificationCache):
        raise TypeError("cache must be a BatchVerificationCache instance")

    if not isinstance(allow_truncate, bool):
        raise TypeError("allow_truncate must be a boolean")
    if sigdecode is not None and not callable(sigdecode):
        raise TypeError("sigdecode must be callable")

    if isinstance(
        records, (str, bytes, bytearray, memoryview)
    ) or not hasattr(records, "__iter__"):
        raise TypeError("records must be an iterable of verification records")

    results = []
    for position, record in enumerate(records):
        results.append(
            _verify_record(
                record,
                position,
                sigdecode,
                allow_truncate,
                cache,
            )
        )
    return results


verify_digests = batch_verify_digests


def _verify_record(record, position, default_sigdecode, allow_truncate, cache):
    cache.record_checked()
    try:
        request = _normalise_request(record, position, default_sigdecode)
        verifying_key = _parse_public_key(request)
        number = _digest_number(
            request.digest, verifying_key.curve, allow_truncate
        )
        decoder = _resolve_sigdecode(
            request.signature_format, request.sigdecode
        )
        r, s = decoder(request.signature, verifying_key.curve.order)
        signature = Signature(r, s)
        public_key = cache.prepare_key(verifying_key)
        if public_key.verifies(number, signature):
            return valid_signature()
        return invalid_signature(
            BadSignatureError("Signature verification failed")
        )
    except (
        der.UnexpectedDER,
        MalformedSignature,
        BadSignatureError,
    ) as error:
        return invalid_signature(error)
    except (
        BadDigestError,
        MalformedPointError,
        TypeError,
        ValueError,
    ) as error:
        return parameter_error(error)


_RequestWithDecoder = namedtuple(
    "_RequestWithDecoder",
    [
        "public_key",
        "signature",
        "digest",
        "curve",
        "signature_format",
        "sigdecode",
        "public_key_format",
    ],
)


def _normalise_request(record, position, default_sigdecode):
    public_key_format = "auto"
    if isinstance(record, BatchVerificationRequest):
        return _RequestWithDecoder(
            record.public_key,
            record.signature,
            record.digest,
            record.curve,
            record.signature_format,
            default_sigdecode,
            record.public_key_format,
        )

    if isinstance(record, _RequestWithDecoder):
        if record.sigdecode is not None:
            return record
        return _RequestWithDecoder(
            record.public_key,
            record.signature,
            record.digest,
            record.curve,
            record.signature_format,
            record.sigdecode or default_sigdecode,
            record.public_key_format,
        )

    if isinstance(record, dict):
        try:
            public_key = record["public_key"]
            signature = record["signature"]
            digest = record["digest"]
        except KeyError as error:
            raise TypeError(
                "record {0} is missing field {1}".format(position, error)
            )
        curve = record.get("curve")
        signature_format = record.get("signature_format") or _RAW_SIGNATURE
        per_record_decode = record.get("sigdecode", default_sigdecode)
        public_key_format = record.get("public_key_format")
        if public_key_format is None:
            public_key_format = record.get("key_format") or "auto"
    elif isinstance(record, (tuple, list)):
        if len(record) not in (4, 5):
            raise TypeError(
                "record {0} must have four or five fields".format(position)
            )
        if len(record) == 4:
            public_key, signature, digest, curve = record
            signature_format = _RAW_SIGNATURE
            per_record_decode = default_sigdecode
        else:
            (
                public_key,
                signature,
                digest,
                curve,
                format_or_decoder,
            ) = record
            if callable(format_or_decoder):
                signature_format = _RAW_SIGNATURE
                per_record_decode = format_or_decoder
            elif format_or_decoder is None:
                signature_format = _RAW_SIGNATURE
                per_record_decode = default_sigdecode
            else:
                signature_format = format_or_decoder
                per_record_decode = default_sigdecode
    else:
        raise TypeError(
            "record {0} must be a tuple, list, dict, or request".format(
                position
            )
        )

    if per_record_decode is not None and not callable(per_record_decode):
        raise TypeError("sigdecode must be callable")
    return _RequestWithDecoder(
        public_key,
        signature,
        digest,
        curve,
        signature_format,
        per_record_decode,
        public_key_format,
    )


def _resolve_sigdecode(signature_format, per_record_decode=None):
    if per_record_decode is not None:
        if signature_format != _RAW_SIGNATURE:
            raise TypeError(
                "signature_format and sigdecode cannot be specified together"
            )
        return per_record_decode

    formats = {
        _RAW_SIGNATURE: sigdecode_string,
        _DER_SIGNATURE: sigdecode_der,
    }
    try:
        return formats[signature_format]
    except KeyError:
        raise ValueError(
            "unsupported signature format: {0!r}".format(signature_format)
        )


def _parse_public_key(request):
    public_key = request.public_key
    if isinstance(public_key, VerifyingKey):
        if isinstance(public_key.curve.curve, CurveEdTw):
            raise ValueError("Edwards curves are not supported")
        if request.curve is not None and request.curve != public_key.curve:
            raise ValueError("curve does not match public key")
        return public_key

    if isinstance(public_key, (bytes, bytearray, memoryview)):
        public_bytes = bytes(normalise_bytes(public_key))
        curve = request.curve
        if not isinstance(curve, Curve):
            raise TypeError(
                "curve is required for encoded public keys and "
                "must be a Curve"
            )
        if isinstance(curve.curve, CurveEdTw):
            raise ValueError("Edwards curves are not supported")

        public_key_format = request.public_key_format or "auto"
        if public_key_format == _DER_PUBLIC_KEY:
            try:
                parsed = VerifyingKey.from_der(public_bytes)
            except der.UnexpectedDER as error:
                raise MalformedPointError(
                    "Malformed encoding of public key"
                )
        elif public_key_format == _RAW_PUBLIC_KEY:
            parsed = VerifyingKey.from_string(public_bytes, curve)
        elif public_key_format != "auto":
            raise ValueError(
                "unsupported public key format: {0!r}".format(
                    public_key_format
                )
            )
        elif public_bytes[:1] == b"\x30":
            try:
                parsed = VerifyingKey.from_der(public_bytes)
            except der.UnexpectedDER:
                try:
                    parsed = VerifyingKey.from_string(public_bytes, curve)
                except MalformedPointError:
                    raise MalformedPointError(
                        "Malformed encoding of public key"
                    )
        else:
            parsed = VerifyingKey.from_string(public_bytes, curve)

        if parsed.curve != curve:
            raise ValueError("public key is not on the specified curve")
        return parsed

    raise TypeError(
        "public_key must be a VerifyingKey or bytes-like object"
    )


def _digest_number(digest, curve, allow_truncate):
    digest = normalise_bytes(digest)
    return _truncate_and_convert_digest(
        bytes(digest), curve, allow_truncate
    )
