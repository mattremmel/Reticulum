#!/usr/bin/env python3
"""
Extract HKDF-SHA256 test vectors from the Reticulum reference implementation
into a JSON file for consumption by alternative implementations.

Includes RFC 5869 standard vectors and Reticulum-specific ECDH key derivation.

Usage:
    python3 test_vectors/extract_hkdf.py

Output:
    test_vectors/hkdf.json
"""

import hashlib
import json
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

import RNS
from RNS.Cryptography import HKDF, HMAC
from RNS.Cryptography import X25519PrivateKey, X25519PublicKey
from tests.identity import fixed_keys

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hkdf.json")


def hmac_sha256(key, data):
    """Mirror the internal HKDF helper."""
    return HMAC.new(key, data).digest()


def extract_rfc5869_vectors():
    """RFC 5869 Appendix A test vectors for HKDF-SHA256."""
    vectors = []

    # Test Case 1
    ikm_1 = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt_1 = bytes.fromhex("000102030405060708090a0b0c")
    info_1 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    length_1 = 42
    expected_prk_1 = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    expected_okm_1 = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

    prk_1 = hmac_sha256(salt_1, ikm_1)
    assert prk_1.hex() == expected_prk_1, f"RFC 5869 TC1 PRK mismatch: {prk_1.hex()}"

    okm_1 = HKDF.hkdf(length=length_1, derive_from=ikm_1, salt=salt_1, context=info_1)
    assert okm_1.hex() == expected_okm_1, f"RFC 5869 TC1 OKM mismatch: {okm_1.hex()}"

    vectors.append({
        "description": "RFC 5869 Test Case 1 (basic, 22-byte IKM)",
        "ikm": ikm_1.hex(),
        "salt": salt_1.hex(),
        "info": info_1.hex(),
        "length": length_1,
        "prk": prk_1.hex(),
        "okm": okm_1.hex(),
    })

    # Test Case 2 (longer inputs/outputs)
    ikm_2 = bytes(range(0x00, 0x50))
    salt_2 = bytes(range(0x60, 0xb0))
    info_2 = bytes(range(0xb0, 0x100))
    length_2 = 82
    expected_prk_2 = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    expected_okm_2 = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"

    prk_2 = hmac_sha256(salt_2, ikm_2)
    assert prk_2.hex() == expected_prk_2, f"RFC 5869 TC2 PRK mismatch: {prk_2.hex()}"

    okm_2 = HKDF.hkdf(length=length_2, derive_from=ikm_2, salt=salt_2, context=info_2)
    assert okm_2.hex() == expected_okm_2, f"RFC 5869 TC2 OKM mismatch: {okm_2.hex()}"

    vectors.append({
        "description": "RFC 5869 Test Case 2 (longer inputs/outputs)",
        "ikm": ikm_2.hex(),
        "salt": salt_2.hex(),
        "info": info_2.hex(),
        "length": length_2,
        "prk": prk_2.hex(),
        "okm": okm_2.hex(),
    })

    # Test Case 3 (zero-length salt and info)
    ikm_3 = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt_3 = b""
    info_3 = b""
    length_3 = 42
    expected_prk_3 = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    expected_okm_3 = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"

    prk_3 = hmac_sha256(bytes(32), ikm_3)  # empty salt -> 32 zero bytes per HKDF spec
    assert prk_3.hex() == expected_prk_3, f"RFC 5869 TC3 PRK mismatch: {prk_3.hex()}"

    okm_3 = HKDF.hkdf(length=length_3, derive_from=ikm_3, salt=salt_3, context=info_3)
    assert okm_3.hex() == expected_okm_3, f"RFC 5869 TC3 OKM mismatch: {okm_3.hex()}"

    vectors.append({
        "description": "RFC 5869 Test Case 3 (zero-length salt/info, salt becomes 32 zero bytes)",
        "ikm": ikm_3.hex(),
        "salt": "",
        "salt_note": "Empty salt; implementation uses 32 zero bytes per spec",
        "info": "",
        "length": length_3,
        "prk": prk_3.hex(),
        "okm": okm_3.hex(),
    })

    return vectors


def extract_reticulum_vector():
    """
    Reticulum-specific HKDF vector: ECDH shared key between keypair 0 and
    keypair 1, derived through hkdf(length=64, derive_from=shared, salt=identity_hash).

    This mirrors how Link keys are derived.
    """
    # Load keypair 0 and keypair 1
    id0 = RNS.Identity.from_bytes(bytes.fromhex(fixed_keys[0][0]))
    id1 = RNS.Identity.from_bytes(bytes.fromhex(fixed_keys[1][0]))

    # Perform X25519 ECDH: id0's private * id1's public
    prv0 = X25519PrivateKey.from_private_bytes(id0.prv_bytes)
    pub1 = X25519PublicKey.from_public_bytes(id1.pub_bytes)
    shared_key = prv0.exchange(pub1)

    # Also verify the reverse direction
    prv1 = X25519PrivateKey.from_private_bytes(id1.prv_bytes)
    pub0 = X25519PublicKey.from_public_bytes(id0.pub_bytes)
    shared_key_reverse = prv1.exchange(pub0)
    assert shared_key == shared_key_reverse, "ECDH shared key mismatch between directions"

    # Derive using HKDF with identity_hash of keypair 0 as salt (no context)
    salt = id0.hash
    derived = HKDF.hkdf(length=64, derive_from=shared_key, salt=salt)

    # Compute intermediate PRK for debugging
    prk = hmac_sha256(salt, shared_key)

    return {
        "description": "Reticulum ECDH + HKDF: X25519 shared secret between keypair 0 and keypair 1, derived with HKDF",
        "keypair_0_x25519_private": id0.prv_bytes.hex(),
        "keypair_0_x25519_public": id0.pub_bytes.hex(),
        "keypair_1_x25519_private": id1.prv_bytes.hex(),
        "keypair_1_x25519_public": id1.pub_bytes.hex(),
        "shared_key": shared_key.hex(),
        "salt": salt.hex(),
        "salt_note": "identity_hash of keypair 0",
        "info": "",
        "info_note": "Empty context (Reticulum default)",
        "length": 64,
        "prk": prk.hex(),
        "derived_key": derived.hex(),
    }


def build_output(rfc_vectors, reticulum_vector):
    return {
        "description": "Reticulum v1.1.3 reference implementation - HKDF-SHA256 test vectors",
        "source": "RNS/Cryptography/HKDF.py",
        "constants": {
            "hash_length_bytes": 32,
            "hash_algorithm": "SHA-256",
        },
        "algorithm_notes": {
            "extract": "PRK = HMAC-SHA256(salt, IKM)",
            "expand": "T(i) = HMAC-SHA256(PRK, T(i-1) || info || i) where i is 1-indexed byte",
            "empty_salt": "When salt is empty or None, 32 zero bytes are used",
            "counter_wrapping": "Counter byte is (i+1) % 256 in Reticulum implementation",
        },
        "rfc5869_vectors": rfc_vectors,
        "reticulum_vector": reticulum_vector,
    }


def verify(output):
    # Verify all RFC vectors have matching PRK and OKM
    for i, vec in enumerate(output["rfc5869_vectors"]):
        salt = bytes.fromhex(vec["salt"]) if vec["salt"] else b""
        ikm = bytes.fromhex(vec["ikm"])
        info = bytes.fromhex(vec["info"]) if vec["info"] else b""
        okm = HKDF.hkdf(length=vec["length"], derive_from=ikm, salt=salt, context=info)
        assert okm.hex() == vec["okm"], f"RFC vector {i} OKM verification failed"
    print(f"  [OK] All {len(output['rfc5869_vectors'])} RFC 5869 vectors verified")

    # Verify Reticulum vector
    rv = output["reticulum_vector"]
    derived = HKDF.hkdf(
        length=rv["length"],
        derive_from=bytes.fromhex(rv["shared_key"]),
        salt=bytes.fromhex(rv["salt"]),
    )
    assert derived.hex() == rv["derived_key"], "Reticulum HKDF vector verification failed"
    print("  [OK] Reticulum ECDH + HKDF vector verified")

    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting HKDF vectors...")
    rfc_vectors = extract_rfc5869_vectors()
    print(f"  Extracted {len(rfc_vectors)} RFC 5869 vectors")

    reticulum_vector = extract_reticulum_vector()
    print("  Extracted Reticulum ECDH + HKDF vector")

    print("Building output...")
    output = build_output(rfc_vectors, reticulum_vector)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
