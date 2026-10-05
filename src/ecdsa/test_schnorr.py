"""
Tests for the BIP 340 Schnorr signature module (ecdsa.schnorr).

The primary acceptance criterion is the official BIP 340 test vector
set (bip-0340/test-vectors.csv in the bitcoin/bips repository).
"""

import pytest

from . import schnorr
from .schnorr import (
    PrivateKey,
    PublicKey,
    InvalidSecretKeyError,
    InvalidPublicKeyError,
    pubkey_from_secret,
    sign,
    verify,
)


# Official BIP 340 test vectors:
# (index, secret key, public key, aux rand, message, signature, result)
# secret key and aux rand are None for verify-only vectors
BIP340_VECTORS = [
    (
        0,
        "0000000000000000000000000000000000000000000000000000000000000003",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        True,
    ),
    (
        1,
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        True,
    ),
    (
        2,
        "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
        "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        True,
    ),
    (
        3,
        "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
        "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
        True,
    ),
    (
        4,
        None,
        "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
        None,
        "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
        "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63"
        "76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
        True,
    ),
    # public key not on the curve
    (
        5,
        None,
        "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
        "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        False,
    ),
    # has_even_y(R) is false
    (
        6,
        None,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
        "3CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
        False,
    ),
    # negated message
    (
        7,
        None,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F"
        "28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
        False,
    ),
    # negated s value
    (
        8,
        None,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
        "961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
        False,
    ),
    # sG - eP is infinite
    (
        9,
        None,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "0000000000000000000000000000000000000000000000000000000000000000"
        "123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
        False,
    ),
    # sG - eP is infinite
    (
        10,
        None,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "0000000000000000000000000000000000000000000000000000000000000001"
        "7615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
        False,
    ),
    # sig[0:32] is not an X coordinate on the curve
    (
        11,
        None,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D"
        "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        False,
    ),
    # sig[0:32] is equal to field size
    (
        12,
        None,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
        "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        False,
    ),
    # sig[32:64] is equal to curve order
    (
        13,
        None,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        False,
    ),
    # public key is not a valid X coordinate because it exceeds the field size
    (
        14,
        None,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        None,
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
        "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        False,
    ),
]


@pytest.mark.parametrize(
    "index,secret,pubkey,aux,msg,sig,result", BIP340_VECTORS
)
def test_bip340_verify_vectors(index, secret, pubkey, aux, msg, sig, result):
    assert (
        verify(bytes.fromhex(msg), bytes.fromhex(pubkey), bytes.fromhex(sig))
        is result
    )


@pytest.mark.parametrize(
    "index,secret,pubkey,aux,msg,sig,result",
    [v for v in BIP340_VECTORS if v[1] is not None],
)
def test_bip340_sign_vectors(index, secret, pubkey, aux, msg, sig, result):
    secret = bytes.fromhex(secret)
    assert pubkey_from_secret(secret) == bytes.fromhex(pubkey)
    assert (
        sign(bytes.fromhex(msg), secret, bytes.fromhex(aux))
        == bytes.fromhex(sig)
    )


def test_reproducible_signature_with_fixed_aux_rand():
    secret = bytes(range(1, 33))
    aux = bytes(range(32, 64))
    msg = b"a reproducible signature with fixed auxiliary input"
    sig1 = sign(msg, secret, aux)
    sig2 = sign(msg, secret, aux)
    assert sig1 == sig2
    assert len(sig1) == 64
    assert verify(msg, pubkey_from_secret(secret), sig1)


def test_random_aux_rand_roundtrip():
    secret = bytes(range(1, 33))
    msg = b"randomised aux rand"
    sig = sign(msg, secret)
    assert verify(msg, pubkey_from_secret(secret), sig)


@pytest.mark.parametrize("length", [0, 1, 17, 32, 33, 100, 128])
def test_arbitrary_message_lengths(length):
    # the current BIP 340 revision permits messages of arbitrary length
    key = PrivateKey.generate()
    msg = bytes(bytearray((i * 7 + 3) % 256 for i in range(length)))
    sig = key.sign(msg)
    assert key.public_key().verify(sig, msg)


def test_private_key_object_roundtrip():
    key = PrivateKey.generate()
    msg = b"object oriented API"
    sig = key.sign(msg)
    assert key.public_key().verify(sig, msg)
    assert not key.public_key().verify(sig, msg + b"x")
    assert PrivateKey(key.to_bytes()) == key
    assert PublicKey(key.public_key().to_bytes()) == key.public_key()


def test_private_key_repr_hides_secret():
    secret = bytes(range(1, 33))
    key = PrivateKey(secret)
    assert secret.hex() not in repr(key)
    assert secret.hex().upper() not in repr(key)


def test_secret_key_errors_do_not_leak_secret():
    # zero and curve order are invalid secrets
    for secret in (bytes(32), (schnorr._n).to_bytes(32, "big")):
        with pytest.raises(InvalidSecretKeyError) as exc_info:
            PrivateKey(secret)
        assert secret.hex() not in str(exc_info.value)
    with pytest.raises(InvalidSecretKeyError):
        PrivateKey(bytes(31))
    with pytest.raises(InvalidSecretKeyError):
        sign(b"msg", bytes(32))


def test_invalid_public_key_rejected():
    # x coordinate equal to the field size
    with pytest.raises(InvalidPublicKeyError):
        PublicKey(bytes.fromhex("FF" * 27 + "FEFFFFFC2F"))
    # x coordinate with no curve point (vector 5 public key)
    with pytest.raises(InvalidPublicKeyError):
        PublicKey(
            bytes.fromhex(
                "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04"
                "A2D4A34"
            )
        )
    with pytest.raises(InvalidPublicKeyError):
        PublicKey(bytes(31))


def test_verify_rejects_malformed_lengths():
    key = PrivateKey.generate()
    msg = b"length checks"
    sig = key.sign(msg)
    pubkey = key.public_key().to_bytes()
    assert not verify(msg, pubkey, sig[:63])
    assert not verify(msg, pubkey, sig + b"\x00")
    assert not verify(msg, pubkey[:31], sig)
    assert not verify(msg, pubkey + b"\x00", sig)


def test_wrong_aux_rand_length_rejected():
    key = PrivateKey.generate()
    with pytest.raises(ValueError):
        key.sign(b"msg", bytes(31))
    with pytest.raises(ValueError):
        key.sign(b"msg", bytes(33))


def test_modified_signature_fails():
    key = PrivateKey.generate()
    msg = b"tamper check"
    sig = bytearray(key.sign(msg))
    pubkey = key.public_key().to_bytes()
    sig[10] ^= 1
    assert not verify(msg, pubkey, bytes(sig))
