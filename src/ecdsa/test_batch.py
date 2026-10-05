"""Tests for the batch ECDSA digest verification entry point."""

import contextlib
import hashlib
import random

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import ecdsa as ecdsa_api
from .batch import (
    BatchItem,
    BatchVerifyResult,
    DEFAULT_MAX_KEYS,
    INVALID_PARAMETER,
    INVALID_SIGNATURE,
    VALID,
    VerificationCache,
    verify_digests,
)
from .curves import (
    BRAINPOOLP256r1,
    Ed25519,
    NIST192p,
    NIST256p,
    SECP112r1,
    SECP160r1,
    SECP256k1,
    curves,
)
from .ellipticcurve import PointJacobi
from .keys import (
    BadDigestError,
    BadSignatureError,
    SigningKey,
)
from .util import (
    sigdecode_der,
    sigdecode_strings,
    sigdecode_string,
    sigencode_der,
)


SHA1 = hashlib.sha1
SHA256 = hashlib.sha256


# Identities of the shared module-level generator points; every other
# PointJacobi that builds a multiplication table is a batch public key.
_GENERATOR_IDS = set()
for _curve in curves:
    if not isinstance(_curve.generator, PointJacobi):
        continue
    _GENERATOR_IDS.add(id(_curve.generator))


@contextlib.contextmanager
def count_precompute_builds():
    """
    Count multiplication-table builds during the wrapped code.

    Builds on shared module-level curve generators and builds on batch
    public key points are counted separately. The evidence is a counter,
    not a timing ratio.
    """
    original = PointJacobi._maybe_precompute
    counts = {"generator": 0, "public": 0}

    def spy(self):
        if not self._PointJacobi__precompute:
            if id(self) in _GENERATOR_IDS:
                counts["generator"] += 1
            else:
                counts["public"] += 1
        return original(self)

    PointJacobi._maybe_precompute = spy
    try:
        yield counts
    finally:
        PointJacobi._maybe_precompute = original


@contextlib.contextmanager
def empty_generator_tables(curve):
    """Temporarily empty one curve generator's multiplication table."""
    generator = curve.generator
    saved = generator._PointJacobi__precompute
    generator._PointJacobi__precompute = []
    try:
        yield
    finally:
        generator._PointJacobi__precompute = saved


def make_key(curve=NIST256p, hashfunc=SHA256):
    signing_key = SigningKey.generate(curve=curve)
    return signing_key, signing_key.get_verifying_key()


def make_record(signing_key, message=b"message", hashfunc=SHA256, der=False):
    digest = hashfunc(message).digest()
    if der:
        signature = signing_key.sign_digest(
            digest, sigencode=sigencode_der
        )
    else:
        signature = signing_key.sign_digest(digest)
    return digest, signature


def reference_status(verifying_key, digest, signature, decoder, truncate):
    """Status and exception type that verify_digest() would produce."""
    try:
        verifying_key.verify_digest(
            signature,
            digest,
            sigdecode=decoder,
            allow_truncate=truncate,
        )
        return VALID, None
    except BadSignatureError:
        return INVALID_SIGNATURE, BadSignatureError
    except BadDigestError:
        return INVALID_PARAMETER, BadDigestError


class TestBasicBatch(unittest.TestCase):
    def test_empty_batch(self):
        self.assertEqual(verify_digests([]), [])
        self.assertEqual(verify_digests(iter([])), [])

    def test_single_valid_signature(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        results = verify_digests(
            [BatchItem(verifying_key, digest, signature)]
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], BatchVerifyResult(VALID, None, 0))
        self.assertTrue(results[0].valid)
        self.assertIsNone(results[0].reason)
        self.assertIsNone(results[0].error)

    def test_result_length_order_and_indices(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        items = [BatchItem(verifying_key, digest, signature)] * 7
        results = verify_digests(items)
        self.assertEqual(len(results), 7)
        self.assertTrue(all(result.valid for result in results))
        self.assertEqual(
            [result.index for result in results], list(range(7))
        )

    def test_accepts_iterator_input(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)

        def items():
            yield BatchItem(verifying_key, digest, signature)

        results = verify_digests(items())
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].valid)

    def test_dict_tuple_and_batchitem_inputs(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        results = verify_digests(
            [
                BatchItem(verifying_key, digest, signature),
                (verifying_key, digest, signature),
                {
                    "public_key": verifying_key,
                    "digest": digest,
                    "signature": signature,
                },
            ]
        )
        self.assertTrue(all(result.valid for result in results))

    def test_duplicate_items_have_independent_results(self):
        sk1, vk1 = make_key()
        sk2, vk2 = make_key()
        digest1, signature1 = make_record(sk1, b"one")
        digest2, signature2 = make_record(sk2, b"two")
        good = BatchItem(vk1, digest1, signature1)
        # valid signature for a different digest under a different key
        bad = BatchItem(vk2, digest1, signature2)
        results = verify_digests([good, bad, good, bad, good])
        self.assertEqual(
            [result.status for result in results],
            [VALID, INVALID_SIGNATURE, VALID, INVALID_SIGNATURE, VALID],
        )
        self.assertEqual(
            [result.index for result in results], [0, 1, 2, 3, 4]
        )

    def test_duplicate_items_are_deterministic(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        item = BatchItem(verifying_key, digest, signature)
        first = verify_digests([item] * 5)
        second = verify_digests([item] * 5)
        self.assertEqual(
            [result.status for result in first], [VALID] * 5
        )
        self.assertEqual(first, second)

    def test_one_bad_signature_is_not_masked(self):
        keys = [make_key() for _ in range(6)]
        digest = SHA256(b"same message").digest()
        signatures = [sk.sign_digest(digest) for sk, _ in keys]
        # key 0's valid signature is presented to every other key
        items = [BatchItem(keys[0][1], digest, signatures[0])] + [
            BatchItem(verifying_key, digest, signatures[0])
            for _, verifying_key in keys[1:]
        ]
        results = verify_digests(items)
        self.assertEqual(results[0].status, VALID)
        self.assertTrue(
            all(result.status == INVALID_SIGNATURE for result in results[1:])
        )


class TestStatusClassification(unittest.TestCase):
    def test_wrong_key_is_invalid_signature(self):
        sk1, vk1 = make_key()
        sk2, vk2 = make_key()
        digest1, _ = make_record(sk1, b"one")
        digest2, signature2 = make_record(sk2, b"two")
        results = verify_digests(
            [
                BatchItem(vk1, digest1, signature2),
                BatchItem(vk2, digest2, signature2),
            ]
        )
        self.assertEqual(results[0].status, INVALID_SIGNATURE)
        self.assertIsInstance(results[0].error, BadSignatureError)
        self.assertEqual(results[0].reason, INVALID_SIGNATURE)
        self.assertEqual(results[1].status, VALID)

    def test_tampered_signature_is_invalid_signature(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        broken = bytearray(signature)
        broken[-1] ^= 0x01
        results = verify_digests(
            [BatchItem(verifying_key, digest, bytes(broken))]
        )
        self.assertEqual(results[0].status, INVALID_SIGNATURE)

    def test_zero_r_s_is_invalid_signature(self):
        signing_key, verifying_key = make_key()
        digest, _ = make_record(signing_key)
        results = verify_digests(
            [BatchItem(verifying_key, digest, b"\x00" * 64)]
        )
        self.assertEqual(results[0].status, INVALID_SIGNATURE)

    def test_bad_raw_length_is_invalid_signature(self):
        signing_key, verifying_key = make_key()
        digest, _ = make_record(signing_key)
        results = verify_digests(
            [BatchItem(verifying_key, digest, b"\x00" * 32)]
        )
        self.assertEqual(results[0].status, INVALID_SIGNATURE)
        self.assertIsInstance(results[0].error, BadSignatureError)

    def test_truncated_der_is_invalid_signature(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key, der=True)
        results = verify_digests(
            [BatchItem(verifying_key, digest, signature[:-2], None, "der")]
        )
        self.assertEqual(results[0].status, INVALID_SIGNATURE)

    def test_invalid_public_key_encoding_is_invalid_parameter(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        results = verify_digests(
            [BatchItem(b"\x00" * 64, digest, signature, NIST256p)],
            sigdecode="raw",
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)
        self.assertNotIsInstance(results[0].error, BadSignatureError)

    def test_point_not_on_curve_is_invalid_parameter(self):
        signing_key, _ = make_key()
        digest, signature = make_record(signing_key)
        results = verify_digests(
            [BatchItem(b"\x04" + b"\x00" * 64, digest, signature, NIST256p)]
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)

    def test_encoded_key_without_curve_is_invalid_parameter(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        encoded = verifying_key.to_string("raw")
        results = verify_digests(
            [BatchItem(encoded, digest, signature)]
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)

    def test_ed25519_key_is_invalid_parameter(self):
        signing_key = SigningKey.generate(curve=Ed25519)
        verifying_key = signing_key.get_verifying_key()
        results = verify_digests(
            [BatchItem(verifying_key, b"digest", b"signature")]
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)

    def test_encoded_ed25519_key_is_invalid_parameter(self):
        signing_key = SigningKey.generate(curve=Ed25519)
        encoded = signing_key.get_verifying_key().to_string("raw")
        results = verify_digests(
            [BatchItem(encoded, b"0" * 32, b"0" * 64, Ed25519)]
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)

    def test_digest_too_long_is_invalid_parameter(self):
        signing_key, verifying_key = make_key()
        long_digest = hashlib.sha512(b"x").digest()
        signature = signing_key.sign_digest(
            long_digest, allow_truncate=True
        )
        results = verify_digests(
            [BatchItem(verifying_key, long_digest, signature)]
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)
        self.assertIsInstance(results[0].error, BadDigestError)

    def test_non_bytes_digest_is_invalid_parameter(self):
        signing_key, verifying_key = make_key()
        _, signature = make_record(signing_key)
        results = verify_digests(
            [BatchItem(verifying_key, 12345, signature)]
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)

    def test_malformed_item_shapes_are_invalid_parameter(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        results = verify_digests(
            [
                "not an item",
                42,
                (verifying_key, digest),  # too few fields
                (verifying_key, digest, signature, NIST256p, "raw", False, 1),
                {"digest": digest, "signature": signature},
            ]
        )
        self.assertEqual(
            [result.status for result in results],
            [INVALID_PARAMETER] * 5,
        )

    def test_bad_item_level_sigdecode_is_invalid_parameter(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        results = verify_digests(
            [BatchItem(verifying_key, digest, signature, None, "bogus")]
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)

    def test_bad_batch_level_sigdecode_raises_value_error(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        with self.assertRaises(ValueError):
            verify_digests(
                [BatchItem(verifying_key, digest, signature)],
                sigdecode="bogus",
            )

    def test_bad_item_curve_type_is_invalid_parameter(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        encoded = verifying_key.to_string("raw")
        results = verify_digests(
            [BatchItem(encoded, digest, signature, "NIST256p")]
        )
        self.assertEqual(results[0].status, INVALID_PARAMETER)

    def test_failures_are_isolated_within_one_batch(self):
        sk_good, vk_good = make_key()
        sk_bad, vk_bad = make_key()
        digest_good, signature_good = make_record(sk_good, b"good")
        digest_bad, _ = make_record(sk_bad, b"bad")
        results = verify_digests(
            [
                BatchItem(vk_good, digest_good, signature_good),
                BatchItem(vk_bad, digest_bad, b"\x00" * 64),
                BatchItem(b"\x00", digest_good, signature_good, NIST256p),
                BatchItem(vk_good, digest_good, signature_good),
            ]
        )
        self.assertEqual(
            [result.status for result in results],
            [VALID, INVALID_SIGNATURE, INVALID_PARAMETER, VALID],
        )


class TestSignatureEncoding(unittest.TestCase):
    def test_auto_detects_der_and_raw(self):
        signing_key, verifying_key = make_key()
        digest, raw_signature = make_record(signing_key)
        der_signature = sk_sign_der(signing_key, digest)
        tampered = bytearray(raw_signature)
        tampered[0] ^= 0x01
        results = verify_digests(
            [
                BatchItem(verifying_key, digest, raw_signature),
                BatchItem(verifying_key, digest, der_signature),
                BatchItem(verifying_key, digest, bytes(tampered)),
                BatchItem(verifying_key, digest, der_signature[:5]),
            ]
        )
        self.assertEqual(
            [result.status for result in results],
            [VALID, VALID, INVALID_SIGNATURE, INVALID_SIGNATURE],
        )

    def test_raw_decoder_rejects_der(self):
        signing_key, verifying_key = make_key()
        digest, der_signature = make_record(signing_key, der=True)
        results = verify_digests(
            [BatchItem(verifying_key, digest, der_signature, None, "raw")]
        )
        self.assertEqual(results[0].status, INVALID_SIGNATURE)

    def test_der_decoder_rejects_raw(self):
        signing_key, verifying_key = make_key()
        digest, raw_signature = make_record(signing_key)
        results = verify_digests(
            [BatchItem(verifying_key, digest, raw_signature, None, "der")]
        )
        self.assertEqual(results[0].status, INVALID_SIGNATURE)

    def test_batch_level_der(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key, der=True)
        results = verify_digests(
            [BatchItem(verifying_key, digest, signature)], sigdecode="der"
        )
        self.assertTrue(results[0].valid)

    def test_item_decoder_overrides_batch_default(self):
        signing_key, verifying_key = make_key()
        digest, raw_signature = make_record(signing_key)
        der_signature = sk_sign_der(signing_key, digest)
        results = verify_digests(
            [
                BatchItem(verifying_key, digest, raw_signature),
                BatchItem(verifying_key, digest, der_signature, None, "der"),
            ],
            sigdecode="raw",
        )
        self.assertTrue(all(result.valid for result in results))

    def test_custom_sigdecode_callable(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        length = NIST256p.baselen
        results = verify_digests(
            [
                BatchItem(
                    verifying_key,
                    digest,
                    (signature[:length], signature[length:]),
                    None,
                    sigdecode_strings,
                )
            ]
        )
        self.assertTrue(results[0].valid)

    def test_auto_falls_back_to_raw_when_first_byte_is_0x30(self):
        # A valid raw signature whose most significant byte of r happens
        # to be 0x30 is not DER. "auto" must try DER, fail, and accept it
        # as raw; the result must remain deterministic.
        signing_key = SigningKey.generate(curve=SECP112r1)
        verifying_key = signing_key.get_verifying_key()
        candidate = None
        for counter in range(5000):
            digest = SHA1(b"amb-%d" % counter).digest()[:SECP112r1.baselen]
            signature = signing_key.sign_digest(digest)
            if signature[:1] == b"\x30":
                candidate = (digest, signature)
                break
        if candidate is None:
            self.skipTest("did not generate a 0x30-leading raw signature")
        digest, signature = candidate
        self.assertTrue(
            verify_digests([BatchItem(verifying_key, digest, signature)])[0]
                .valid
        )
        self.assertTrue(
            verify_digests(
                [BatchItem(verifying_key, digest, signature, None, "raw")]
            )[0].valid
        )
        self.assertEqual(
            verify_digests(
                [BatchItem(verifying_key, digest, signature, None, "der")]
            )[0].status,
            INVALID_SIGNATURE,
        )

    def test_auto_fallback_is_deterministic(self):
        signing_key, verifying_key = make_key()
        digest, raw_signature = make_record(signing_key)
        der_signature = sk_sign_der(signing_key, digest)
        for _ in range(5):
            results = verify_digests(
                [
                    BatchItem(verifying_key, digest, raw_signature),
                    BatchItem(verifying_key, digest, der_signature),
                ]
            )
            self.assertEqual(
                [result.status for result in results], [VALID, VALID]
            )


def sk_sign_der(signing_key, digest):
    return signing_key.sign_digest(digest, sigencode=sigencode_der)


class TestMixedCurvesAndDigests(unittest.TestCase):
    CONFIGS = [
        (NIST256p, SHA256),
        (NIST192p, SHA1),
        (SECP256k1, SHA256),
        (BRAINPOOLP256r1, SHA256),
    ]

    def test_mixed_curves_in_one_batch(self):
        rng = random.Random(0xC0FFEE)
        items = []
        expected = []
        for curve, hashfunc in self.CONFIGS:
            signing_key, verifying_key = make_key(curve, hashfunc)
            digest, signature = make_record(
                signing_key,
                b"mixed-" + curve.name.encode("ascii"),
                hashfunc,
            )
            items.append(BatchItem(verifying_key, digest, signature))
            expected.append(VALID)
            # flip a random byte of a second copy of the signature
            broken = bytearray(signature)
            broken[rng.randrange(len(broken))] ^= 0x01
            items.append(
                BatchItem(verifying_key, digest, bytes(broken))
            )
            expected.append(INVALID_SIGNATURE)
        results = verify_digests(items)
        self.assertEqual(
            [result.status for result in results], expected
        )

    def test_encoded_keys_use_batch_default_curve(self):
        signing_key, _ = make_key()
        verifying_key = signing_key.get_verifying_key()
        digest, signature = make_record(signing_key)
        encodings = [
            verifying_key.to_string("raw"),
            verifying_key.to_string("uncompressed"),
            verifying_key.to_string("compressed"),
            verifying_key.to_string("hybrid"),
            bytearray(verifying_key.to_string("raw")),
        ]
        items = [
            BatchItem(encoded, digest, signature) for encoded in encodings
        ]
        results = verify_digests(items, curve=NIST256p)
        self.assertTrue(all(result.valid for result in results))

    def test_item_curve_overrides_default_curve(self):
        sk192, _ = make_key(NIST192p, SHA1)
        vk192 = sk192.get_verifying_key()
        digest192, signature192 = make_record(sk192, b"m", SHA1)
        sk256, vk256 = make_key(NIST256p, SHA256)
        digest256, signature256 = make_record(sk256, b"m", SHA256)
        results = verify_digests(
            [
                BatchItem(
                    vk192.to_string("raw"),
                    digest192,
                    signature192,
                    NIST192p,
                ),
                BatchItem(
                    vk256.to_string("raw"),
                    digest256,
                    signature256,
                    NIST256p,
                ),
            ],
            curve=NIST256p,
        )
        self.assertTrue(all(result.valid for result in results))

    def test_allow_truncate_per_item_and_default(self):
        signing_key, verifying_key = make_key()
        long_digest = hashlib.sha512(b"truncate me").digest()
        signature = signing_key.sign_digest(
            long_digest, allow_truncate=True
        )
        results = verify_digests(
            [
                BatchItem(verifying_key, long_digest, signature),
                BatchItem(
                    verifying_key, long_digest, signature, None, None, True
                ),
            ]
        )
        self.assertEqual(
            [result.status for result in results],
            [INVALID_PARAMETER, VALID],
        )
        results = verify_digests(
            [BatchItem(verifying_key, long_digest, signature)],
            allow_truncate=True,
        )
        self.assertTrue(results[0].valid)


class TestCacheReuse(unittest.TestCase):
    def setUp(self):
        self.cache = VerificationCache()

    def test_repeated_key_counts_as_hits(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        items = [BatchItem(verifying_key, digest, signature)] * 8
        results = verify_digests(items, cache=self.cache)
        self.assertTrue(all(result.valid for result in results))
        self.assertEqual(self.cache.key_misses, 1)
        self.assertEqual(self.cache.key_hits, 7)
        self.assertEqual(len(self.cache), 1)

    def test_different_encodings_share_one_entry(self):
        signing_key, _ = make_key()
        verifying_key = signing_key.get_verifying_key()
        digest, signature = make_record(signing_key)
        encodings = [
            verifying_key,
            verifying_key.to_string("raw"),
            verifying_key.to_string("uncompressed"),
            verifying_key.to_string("compressed"),
            verifying_key.to_string("hybrid"),
        ]
        items = [
            BatchItem(key, digest, signature, NIST256p) for key in encodings
        ]
        results = verify_digests(items, cache=self.cache)
        self.assertTrue(all(result.valid for result in results))
        self.assertEqual(self.cache.key_misses, 1)
        self.assertEqual(self.cache.key_hits, 4)
        self.assertEqual(len(self.cache), 1)

    def test_hits_share_one_precomputed_entry(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        verify_digests(
            [BatchItem(verifying_key, digest, signature)], cache=self.cache
        )
        self.assertEqual(self.cache.key_misses, 1)
        (entry,) = list(self.cache._entries.values())
        verify_digests(
            [
                BatchItem(
                    verifying_key.to_string("compressed"),
                    digest,
                    signature,
                    NIST256p,
                )
            ],
            cache=self.cache,
        )
        self.assertEqual(len(self.cache), 1)
        self.assertIs(
            list(self.cache._entries.values())[0], entry
        )
        self.assertTrue(entry.pubkey.point._PointJacobi__precompute)
        self.assertEqual(self.cache.key_hits, 1)

    def test_distinct_keys_are_separate_entries(self):
        keys = [make_key() for _ in range(3)]
        digest = SHA256(b"m").digest()
        items = []
        for signing_key, verifying_key in keys:
            signature = signing_key.sign_digest(digest)
            items.extend(
                [
                    BatchItem(verifying_key, digest, signature),
                    BatchItem(verifying_key, digest, signature),
                ]
            )
        results = verify_digests(items, cache=self.cache)
        self.assertTrue(all(result.valid for result in results))
        self.assertEqual(self.cache.key_misses, 3)
        self.assertEqual(self.cache.key_hits, 3)
        self.assertEqual(len(self.cache), 3)

    def test_cache_is_reused_across_calls(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        item = BatchItem(verifying_key, digest, signature)
        first = verify_digests([item] * 3, cache=self.cache)
        second = verify_digests([item] * 3, cache=self.cache)
        self.assertTrue(all(r.valid for r in first + second))
        self.assertEqual(self.cache.key_misses, 1)
        self.assertEqual(self.cache.key_hits, 5)

    def test_fifo_eviction_is_bounded(self):
        keys = [make_key() for _ in range(3)]
        digest = SHA256(b"m").digest()
        items = []
        for signing_key, verifying_key in keys:
            signature = signing_key.sign_digest(digest)
            items.append(BatchItem(verifying_key, digest, signature))
        cache = VerificationCache(max_keys=2)
        results = verify_digests(
            [
                items[0],
                items[0],  # hit, does not change order
                items[1],
                items[2],  # evicts key 0
                items[1],  # key 1 retained, hit
            ],
            cache=cache,
        )
        self.assertTrue(all(result.valid for result in results))
        self.assertEqual(cache.key_misses, 3)
        self.assertEqual(cache.key_hits, 2)
        self.assertEqual(cache.evictions, 1)
        self.assertEqual(len(cache), 2)

    def test_invalid_max_keys_are_rejected(self):
        for bad in (0, -1, 1.5, "2", None, True):
            with self.assertRaises(ValueError):
                VerificationCache(max_keys=bad)

    def test_default_capacity_is_a_positive_bound(self):
        self.assertIsInstance(DEFAULT_MAX_KEYS, int)
        self.assertGreaterEqual(DEFAULT_MAX_KEYS, 1)
        cache = VerificationCache()
        self.assertEqual(cache.max_keys, DEFAULT_MAX_KEYS)

    def test_clear_resets_cache_and_statistics(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        verify_digests(
            [BatchItem(verifying_key, digest, signature)], cache=self.cache
        )
        self.assertEqual(len(self.cache), 1)
        self.cache.clear()
        self.assertEqual(len(self.cache), 0)
        self.assertEqual(self.cache.key_hits, 0)
        self.assertEqual(self.cache.key_misses, 0)
        self.assertEqual(self.cache.evictions, 0)

    def test_ephemeral_cache_does_not_leak_state(self):
        signing_key, verifying_key = make_key()
        digest, signature = make_record(signing_key)
        # two independent calls cannot observe each other's precomputation
        first = verify_digests(
            [BatchItem(verifying_key, digest, signature)]
        )
        second = verify_digests(
            [BatchItem(verifying_key, digest, signature)]
        )
        self.assertTrue(first[0].valid and second[0].valid)


class TestPrecomputeReuseCounting(unittest.TestCase):
    def _precomputed_key(self):
        # SECP160r1 keeps the counting test fast.
        signing_key = SigningKey.generate(curve=SECP160r1)
        return signing_key, signing_key.get_verifying_key()

    def test_repeated_key_builds_public_table_once(self):
        signing_key, verifying_key = self._precomputed_key()
        digest = SHA1(b"counted").digest()
        signature = signing_key.sign_digest(digest)
        item = BatchItem(verifying_key, digest, signature)
        cache = VerificationCache()
        with empty_generator_tables(SECP160r1):
            with count_precompute_builds() as counts:
                results = verify_digests([item] * 12, cache=cache)
        self.assertTrue(all(result.valid for result in results))
        # both tables are built exactly once on the first item
        self.assertEqual(counts["generator"], 1)
        self.assertEqual(counts["public"], 1)
        self.assertEqual(cache.key_misses, 1)
        self.assertEqual(cache.key_hits, 11)

    def test_second_call_with_shared_cache_builds_nothing(self):
        signing_key, verifying_key = self._precomputed_key()
        digest = SHA1(b"counted").digest()
        signature = signing_key.sign_digest(digest)
        item = BatchItem(verifying_key, digest, signature)
        cache = VerificationCache()
        with empty_generator_tables(SECP160r1):
            with count_precompute_builds() as counts:
                first = verify_digests([item] * 4, cache=cache)
                # the shared cache keeps the prepared public key and the
                # generator already has its table, so nothing is rebuilt
                second = verify_digests([item] * 4, cache=cache)
        self.assertTrue(all(r.valid for r in first + second))
        self.assertEqual(counts["generator"], 1)
        self.assertEqual(counts["public"], 1)
        self.assertEqual(cache.key_misses, 1)
        self.assertEqual(cache.key_hits, 7)

    def test_independent_calls_without_cache_rebuild_tables(self):
        signing_key, verifying_key = self._precomputed_key()
        digest = SHA1(b"counted").digest()
        signature = signing_key.sign_digest(digest)
        item = BatchItem(verifying_key, digest, signature)
        with empty_generator_tables(SECP160r1):
            with count_precompute_builds() as counts:
                first = verify_digests([item])
                second = verify_digests([item])
        self.assertTrue(first[0].valid and second[0].valid)
        # the generator table survives (it is module global) but the
        # per-call public key table is built anew each time
        self.assertEqual(counts["generator"], 1)
        self.assertEqual(counts["public"], 2)

    def test_encodings_reuse_precomputation(self):
        signing_key, _ = self._precomputed_key()
        verifying_key = signing_key.get_verifying_key()
        digest = SHA1(b"counted").digest()
        signature = signing_key.sign_digest(digest)
        items = [
            BatchItem(verifying_key, digest, signature),
            BatchItem(
                verifying_key.to_string("raw"), digest, signature, SECP160r1
            ),
            BatchItem(
                verifying_key.to_string("compressed"),
                digest,
                signature,
                SECP160r1,
            ),
            BatchItem(
                verifying_key.to_string("uncompressed"),
                digest,
                signature,
                SECP160r1,
            ),
        ]
        cache = VerificationCache()
        with empty_generator_tables(SECP160r1):
            with count_precompute_builds() as counts:
                results = verify_digests(items, cache=cache)
        self.assertTrue(all(result.valid for result in results))
        self.assertEqual(counts["public"], 1)
        self.assertEqual(cache.key_misses, 1)
        self.assertEqual(cache.key_hits, 3)


class TestParityWithVerifyDigest(unittest.TestCase):
    def test_randomised_parity_against_verify_digest(self):
        rng = random.Random(0xBADC0DE)
        configs = [
            (NIST256p, SHA256, False),
            (NIST192p, SHA1, False),
            (SECP256k1, SHA256, False),
            (BRAINPOOLP256r1, SHA256, False),
            (NIST256p, hashlib.sha512, True),
        ]
        items = []
        references = []
        for _ in range(80):
            curve, hashfunc, truncate = configs[
                rng.randrange(len(configs))
            ]
            signing_key, verifying_key = make_key(curve, hashfunc)
            digest = hashfunc(
                b"record-%d" % rng.randrange(1 << 20)
            ).digest()
            use_der = rng.choice([True, False])
            if use_der:
                signature = signing_key.sign_digest(
                    digest,
                    sigencode=sigencode_der,
                    allow_truncate=truncate,
                )
                decoder = sigdecode_der
            else:
                signature = signing_key.sign_digest(
                    digest, allow_truncate=truncate
                )
                decoder = sigdecode_string
            encoding = rng.randrange(4)
            if encoding == 0:
                public_key = verifying_key
                item_curve = curve
            elif encoding == 1:
                public_key = verifying_key.to_string("raw")
                item_curve = curve
            elif encoding == 2:
                public_key = verifying_key.to_string("compressed")
                item_curve = curve
            else:
                public_key = bytearray(
                    verifying_key.to_string("uncompressed")
                )
                item_curve = curve
            items.append(
                BatchItem(
                    public_key,
                    digest,
                    signature,
                    item_curve,
                    decoder,
                    truncate,
                )
            )
            references.append(
                reference_status(
                    verifying_key, digest, signature, decoder, truncate
                )
            )
        results = verify_digests(items)
        self.assertEqual(len(results), len(items))
        for index, (result, reference) in enumerate(
            zip(results, references)
        ):
            status, error_type = reference
            self.assertEqual(
                result.status,
                status,
                "item {0}: {1!r}".format(index, result.error),
            )
            if error_type is not None:
                self.assertIsInstance(result.error, error_type)

    def test_parity_with_wrong_keys_and_tampering(self):
        rng = random.Random(4242)
        configs = [
            (NIST256p, SHA256),
            (NIST192p, SHA1),
            (SECP256k1, SHA256),
        ]
        generated = []
        for curve, hashfunc in configs:
            signing_key, verifying_key = make_key(curve, hashfunc)
            generated.append((curve, hashfunc, signing_key, verifying_key))
        items = []
        references = []
        for index, (curve, hashfunc, signing_key, _) in enumerate(generated):
            digest = hashfunc(b"parity-%d" % index).digest()
            use_der = rng.choice([True, False])
            signature = (
                signing_key.sign_digest(digest, sigencode=sigencode_der)
                if use_der
                else signing_key.sign_digest(digest)
            )
            decoder = sigdecode_der if use_der else sigdecode_string
            if index % 2 == 0:
                chosen_key = generated[index][3]
            else:
                # verify under a different key on the same or another curve
                chosen_key = generated[(index + 1) % len(generated)][3]
            items.append(
                BatchItem(chosen_key, digest, signature, None, decoder)
            )
            references.append(
                reference_status(
                    chosen_key, digest, signature, decoder, False
                )
            )
            # tampered copy of a valid signature
            tampered = bytearray(signature)
            tampered[rng.randrange(len(tampered))] ^= 0x01
            own_key = generated[index][3]
            items.append(
                BatchItem(own_key, digest, bytes(tampered), None, decoder)
            )
            references.append(
                reference_status(
                    own_key, digest, bytes(tampered), decoder, False
                )
            )
        results = verify_digests(items)
        for index, (result, reference) in enumerate(
            zip(results, references)
        ):
            status, error_type = reference
            self.assertEqual(result.status, status, "item {0}".format(index))
            if error_type is not None:
                self.assertIsInstance(result.error, error_type)




class TestPublicApi(unittest.TestCase):
    def test_symbols_exported_from_package(self):
        for name in (
            "verify_digests",
            "BatchItem",
            "BatchVerifyResult",
            "VerificationCache",
            "VALID",
            "INVALID_SIGNATURE",
            "INVALID_PARAMETER",
            "DEFAULT_MAX_KEYS",
        ):
            self.assertTrue(hasattr(ecdsa_api, name), name)

    def test_status_constants_are_distinct_strings(self):
        self.assertEqual(VALID, "valid")
        self.assertEqual(INVALID_SIGNATURE, "invalid_signature")
        self.assertEqual(INVALID_PARAMETER, "invalid_parameter")
        self.assertEqual(
            len({VALID, INVALID_SIGNATURE, INVALID_PARAMETER}), 3
        )
