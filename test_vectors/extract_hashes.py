#!/usr/bin/env python3
"""
Extract SHA-256 and SHA-512 hash test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

Usage:
    python3 test_vectors/extract_hashes.py

Output:
    test_vectors/hashes.json
"""

import hashlib
import json
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

import RNS

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hashes.json")


def extract_sha256_vectors():
    vectors = []

    cases = [
        ("empty string", b""),
        ("'abc' (3 bytes, less than block length)", b"abc"),
        ("'a' * 64 (exactly one block)", b"a" * 64),
        ("'a' * 1000000 (many blocks)", b"a" * 1000000),
    ]

    for desc, data in cases:
        digest = RNS.Cryptography.sha256(data)
        # Cross-verify against hashlib
        assert digest == hashlib.sha256(data).digest(), f"SHA-256 mismatch for: {desc}"
        vectors.append({
            "description": desc,
            "input": data.hex(),
            "input_length": len(data),
            "digest": digest.hex(),
        })

    return vectors


def extract_sha512_vectors():
    vectors = []

    cases = [
        ("empty string", b""),
        ("'abc' (3 bytes, less than block length)", b"abc"),
        ("'a' * 128 (exactly one block)", b"a" * 128),
        ("'a' * 1000000 (many blocks)", b"a" * 1000000),
    ]

    for desc, data in cases:
        digest = RNS.Cryptography.sha512(data)
        assert digest == hashlib.sha512(data).digest(), f"SHA-512 mismatch for: {desc}"
        vectors.append({
            "description": desc,
            "input": data.hex(),
            "input_length": len(data),
            "digest": digest.hex(),
        })

    return vectors


def extract_truncated_hash_vectors():
    """Demonstrate Reticulum's truncated hash: SHA-256(data)[:16]."""
    vectors = []

    cases = [
        ("'abc'", b"abc"),
        ("'Hello Reticulum'", b"Hello Reticulum"),
        ("256 zero bytes", bytes(256)),
    ]

    for desc, data in cases:
        full = RNS.Cryptography.sha256(data)
        truncated = full[:16]
        assert truncated == RNS.Identity.truncated_hash(data)
        vectors.append({
            "description": desc,
            "input": data.hex(),
            "input_length": len(data),
            "full_sha256": full.hex(),
            "truncated_hash": truncated.hex(),
            "truncated_length_bytes": 16,
        })

    return vectors


def build_output(sha256_vectors, sha512_vectors, truncated_vectors):
    return {
        "description": "Reticulum v1.1.3 reference implementation - SHA-256 / SHA-512 hash test vectors",
        "source": "tests/hashes.py",
        "constants": {
            "sha256_digest_length_bytes": 32,
            "sha512_digest_length_bytes": 64,
            "truncated_hash_length_bytes": 16,
            "truncated_hash_length_bits": 128,
        },
        "sha256": sha256_vectors,
        "sha512": sha512_vectors,
        "truncated_hash": truncated_vectors,
    }


def verify(output):
    # Verify SHA-256 vectors against known values from tests/hashes.py
    known_sha256 = {
        0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        1: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        2: "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        3: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    }
    for idx, vec in enumerate(output["sha256"]):
        assert vec["digest"] == known_sha256[idx], f"SHA-256 vector {idx} mismatch"
    print(f"  [OK] All {len(output['sha256'])} SHA-256 vectors match known values")

    known_sha512 = {
        0: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        1: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        2: "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321",
        3: "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
    }
    for idx, vec in enumerate(output["sha512"]):
        assert vec["digest"] == known_sha512[idx], f"SHA-512 vector {idx} mismatch"
    print(f"  [OK] All {len(output['sha512'])} SHA-512 vectors match known values")

    for vec in output["truncated_hash"]:
        assert vec["truncated_hash"] == vec["full_sha256"][:32], "Truncated hash is not first 16 bytes of SHA-256"
    print(f"  [OK] All {len(output['truncated_hash'])} truncated hash vectors verified")

    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting hash vectors...")
    sha256_vectors = extract_sha256_vectors()
    print(f"  Extracted {len(sha256_vectors)} SHA-256 vectors")

    sha512_vectors = extract_sha512_vectors()
    print(f"  Extracted {len(sha512_vectors)} SHA-512 vectors")

    truncated_vectors = extract_truncated_hash_vectors()
    print(f"  Extracted {len(truncated_vectors)} truncated hash vectors")

    print("Building output...")
    output = build_output(sha256_vectors, sha512_vectors, truncated_vectors)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
