import hashlib

import pytest

from .batchverify import (
    INVALID,
    PARAMETER_ERROR,
    VALID,
    BatchVerificationCache,
    batch_verify_digests,
)
from .curves import NIST256p, NIST384p, SECP256k1
from .keys import (
    BadDigestError,
    BadSignatureError,
    MalformedPointError,
    SigningKey,
    VerifyingKey,
)
from .util import (
    MalformedSignature,
    sigdecode_der,
    sigdecode_string,
    sigencode_der,
    sigencode_string,
)


def _signed_record(
    signing_key, digest, key_encoding="object", signature_format="raw"
):
    verifying_key = signing_key.verifying_key
    if signature_format == "raw":
        signature = signing_key.sign_digest_deterministic(
            digest, sigencode=sigencode_string
        )
    else:
        signature = signing_key.sign_digest_deterministic(
            digest, sigencode=sigencode_der
        )

    if key_encoding == "object":
        public_key = verifying_key
        curve = None
    elif key_encoding == "der":
        public_key = verifying_key.to_der()
        curve = verifying_key.curve
    elif key_encoding == "compressed":
        public_key = verifying_key.to_string("compressed")
        curve = verifying_key.curve
    else:
        public_key = verifying_key.to_string()
        curve = verifying_key.curve

    return (public_key, signature, digest, curve, signature_format)


def test_batch_matches_verify_digest_and_reuses_same_public_key():
    signing_keys = [
        SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256),
        SigningKey.generate(curve=NIST384p, hashfunc=hashlib.sha384),
        SigningKey.generate(curve=SECP256k1, hashfunc=hashlib.sha256),
    ]
    digests = [
        hashlib.sha256(b"one").digest(),
        hashlib.sha384(b"two").digest(),
        hashlib.sha256(b"three").digest(),
    ]
    records = [
        _signed_record(signing_keys[0], digests[0]),
        _signed_record(
            signing_keys[0],
            digests[0],
            key_encoding="compressed",
            signature_format="der",
        ),
        _signed_record(signing_keys[0], digests[0], key_encoding="der"),
        _signed_record(
            signing_keys[1], digests[1], signature_format="der"
        ),
        _signed_record(signing_keys[2], digests[2], key_encoding="raw"),
    ]

    cache = BatchVerificationCache()
    results = batch_verify_digests(records, cache=cache)

    assert len(results) == len(records)
    assert [result.status for result in results] == [VALID] * len(records)
    for record, result in zip(records, results):
        assert bool(result)
        verifying_key = record[0]
        if not isinstance(verifying_key, VerifyingKey):
            if record[0].startswith(b"\x30"):
                verifying_key = VerifyingKey.from_der(record[0])
            else:
                verifying_key = VerifyingKey.from_string(record[0], record[3])
        decoder = sigdecode_der if record[4] == "der" else sigdecode_string
        assert verifying_key.verify_digest(
            record[1], record[2], sigdecode=decoder
        )

    stats = cache.stats
    assert stats.records == 5
    assert stats.unique_keys == 3
    assert stats.unique_curves == 3
    assert stats.key_misses == 3
    assert stats.key_hits == 2
    assert stats.keys_precomputed == 3
    assert stats.curve_misses == 3
    assert stats.curve_hits == 2
    assert stats.curves_precomputed == 3


def test_batch_separates_invalid_signatures_from_parameter_errors():
    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    digest = hashlib.sha256(b"message").digest()
    signature = signing_key.sign_digest_deterministic(digest)
    valid_key = signing_key.verifying_key

    malformed = (valid_key, b"bad", digest, None, "raw")
    wrong_digest = (
        valid_key,
        signature,
        hashlib.sha256(b"other").digest(),
        None,
        "raw",
    )
    bad_key = (
        b"not a key",
        signature,
        digest,
        NIST256p,
        "raw",
    )
    long_digest = (valid_key, signature, digest + b"\x00", None, "raw")

    results = batch_verify_digests(
        [malformed, wrong_digest, bad_key, long_digest]
    )

    assert [result.status for result in results] == [
        INVALID,
        INVALID,
        PARAMETER_ERROR,
        PARAMETER_ERROR,
    ]
    assert [result.error_type for result in results[:2]] == [
        MalformedSignature,
        BadSignatureError,
    ]
    assert [result.error_type for result in results[2:]] == [
        MalformedPointError,
        BadDigestError,
    ]
    assert all(result.error for result in results)
    assert not results[0] and not results[1]

    with pytest.raises(BadSignatureError):
        valid_key.verify_digest(b"bad", digest)


def test_batch_results_match_verify_digest_outcomes():
    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    digest = hashlib.sha256(b"compare").digest()
    raw_signature = signing_key.sign_digest_deterministic(
        digest, sigencode=sigencode_string
    )
    der_signature = signing_key.sign_digest_deterministic(
        digest, sigencode=sigencode_der
    )

    cases = [
        ((signing_key.verifying_key, raw_signature, digest, None), False),
        (
            (
                signing_key.verifying_key,
                der_signature,
                digest,
                None,
                "der",
            ),
            False,
        ),
        (
            (
                signing_key.verifying_key,
                b"bad-signature",
                digest,
                None,
            ),
            True,
        ),
        (
            (
                signing_key.verifying_key,
                raw_signature,
                digest + b"\x00",
                None,
            ),
            True,
        ),
    ]

    results = batch_verify_digests([case[0] for case in cases])
    for (record, _), result in zip(cases, results):
        signature_format = (
            record[4] if len(record) == 5 and isinstance(record[4], str)
            else "raw"
        )
        decoder = (
            sigdecode_der
            if signature_format == "der"
            else sigdecode_string
        )
        try:
            ordinary_result = signing_key.verifying_key.verify_digest(
                record[1], record[2], sigdecode=decoder
            )
            ordinary_error = None
        except (BadSignatureError, BadDigestError) as error:
            ordinary_result = False
            ordinary_error = type(error)

        assert bool(result) == ordinary_result
        if ordinary_error is BadDigestError:
            assert result.status == PARAMETER_ERROR
            assert result.error_type is BadDigestError
        elif ordinary_error is BadSignatureError:
            assert result.status == INVALID


def test_empty_batch_has_empty_results_and_creates_no_precomputation():
    cache = BatchVerificationCache()

    assert batch_verify_digests([], cache=cache) == []
    assert cache.stats.records == 0
    assert cache.stats.unique_keys == 0
    assert cache.stats.key_misses == 0


def test_explicit_cache_is_reused_across_calls():
    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    digest = hashlib.sha256(b"cached").digest()
    record = _signed_record(signing_key, digest)
    cache = BatchVerificationCache()

    first = batch_verify_digests([record, record], cache=cache)
    second = batch_verify_digests(
        [
            _signed_record(signing_key, digest, key_encoding="compressed"),
        ],
        cache=cache,
    )

    assert [result.status for result in first] == [VALID, VALID]
    assert second[0].status == VALID
    assert cache.stats.records == 3
    assert cache.stats.unique_keys == 1
    assert cache.stats.key_misses == 1
    assert cache.stats.key_hits == 2


def test_cache_respects_capacity_boundary():
    signing_keys = [
        SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256),
        SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256),
    ]
    digest = hashlib.sha256(b"boundary").digest()
    cache = BatchVerificationCache(max_entries=1)

    batch_verify_digests(
        [
            _signed_record(signing_keys[0], digest),
            _signed_record(signing_keys[1], digest),
        ],
        cache=cache,
    )

    assert len(cache) == 1
    assert cache.stats.unique_keys == 1
    assert cache.stats.unique_curves == 1


def test_verifying_key_batch_helper_accepts_mixed_formats():
    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    digest = hashlib.sha256(b"helper").digest()
    raw_signature = signing_key.sign_digest_deterministic(
        digest, sigencode=sigencode_string
    )
    der_signature = signing_key.sign_digest_deterministic(
        digest, sigencode=sigencode_der
    )

    results = signing_key.verifying_key.verify_digests(
        [
            (raw_signature, digest),
            {"signature": der_signature, "digest": digest,
             "signature_format": "der"},
            (b"bad", digest),
        ]
    )

    assert [result.status for result in results] == [
        VALID,
        VALID,
        INVALID,
    ]


def test_batch_accepts_per_record_custom_decoder():
    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    digest = hashlib.sha256(b"decoder").digest()
    raw_signature = signing_key.sign_digest_deterministic(
        digest, sigencode=sigencode_string
    )
    der_signature = signing_key.sign_digest_deterministic(
        digest, sigencode=sigencode_der
    )

    results = batch_verify_digests(
        [
            (signing_key.verifying_key, raw_signature, digest, None),
            (
                signing_key.verifying_key,
                der_signature,
                digest,
                None,
                sigdecode_der,
            ),
        ]
    )

    assert [result.status for result in results] == [VALID, VALID]


def test_batch_accepts_explicit_der_public_key_format():
    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    digest = hashlib.sha256(b"public-format").digest()
    signature = signing_key.sign_digest_deterministic(
        digest, sigencode=sigencode_der
    )

    result = batch_verify_digests(
        [
            {
                "public_key": signing_key.verifying_key.to_der(),
                "signature": signature,
                "digest": digest,
                "curve": NIST256p,
                "signature_format": "der",
                "public_key_format": "der",
            }
        ]
    )[0]

    assert result.status == VALID


def test_malformed_der_public_key_is_parameter_error():
    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    digest = hashlib.sha256(b"bad-public-key").digest()
    signature = signing_key.sign_digest_deterministic(digest)

    result = batch_verify_digests(
        [
            {
                "public_key": b"\x30\x02\x01",
                "signature": signature,
                "digest": digest,
                "curve": NIST256p,
                "public_key_format": "der",
            }
        ]
    )[0]

    assert result.status == PARAMETER_ERROR
    assert result.error_type is MalformedPointError


def test_duplicate_records_have_deterministic_results():
    signing_key = SigningKey.generate(curve=NIST256p, hashfunc=hashlib.sha256)
    digest = hashlib.sha256(b"duplicate").digest()
    record = _signed_record(signing_key, digest)

    first = batch_verify_digests([record, record])
    second = batch_verify_digests([record, record])

    assert first == second
    assert [result.status for result in first] == [VALID, VALID]
