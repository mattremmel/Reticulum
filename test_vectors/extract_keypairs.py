#!/usr/bin/env python3
"""
Extract fixed keypairs from the Reticulum reference implementation test suite
into a JSON file for consumption by alternative implementations (e.g., Rust cargo test).

Usage:
    python3 test_vectors/extract_keypairs.py

Output:
    test_vectors/keypairs.json
"""

import json
import os
import sys

# Ensure we can import from the repo root
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

import RNS
from RNS.Cryptography import X25519PrivateKey, X25519PublicKey
from tests.identity import (
    encrypted_message,
    fixed_keys,
    fixed_token,
    sig_from_key_0,
    signed_message,
)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")


def extract_keypairs():
    keypairs = []

    for idx, (prv_hex, expected_hash_hex) in enumerate(fixed_keys):
        identity = RNS.Identity.from_bytes(bytes.fromhex(prv_hex))
        assert identity is not None, f"Failed to load keypair {idx}"

        # Verify identity hash matches expected value
        assert identity.hash == bytes.fromhex(expected_hash_hex), (
            f"Keypair {idx}: identity hash mismatch: "
            f"{identity.hash.hex()} != {expected_hash_hex}"
        )

        # Extract key components
        x25519_prv = identity.prv_bytes        # 32 bytes
        ed25519_prv = identity.sig_prv_bytes    # 32 bytes
        x25519_pub = identity.pub_bytes         # 32 bytes
        ed25519_pub = identity.sig_pub_bytes    # 32 bytes

        assert len(x25519_prv) == 32
        assert len(ed25519_prv) == 32
        assert len(x25519_pub) == 32
        assert len(ed25519_pub) == 32

        # Compute destination hash for "rns_unit_tests.link.establish"
        dest_hash = RNS.Destination.hash(identity, "rns_unit_tests", "link", "establish")

        entry = {
            "index": idx,
            "private_key": prv_hex,
            "x25519_private": x25519_prv.hex(),
            "ed25519_private": ed25519_prv.hex(),
            "public_key": identity.get_public_key().hex(),
            "x25519_public": x25519_pub.hex(),
            "ed25519_public": ed25519_pub.hex(),
            "identity_hash": identity.hash.hex(),
            "destination_hashes": {
                "rns_unit_tests.link.establish": dest_hash.hex(),
            },
        }
        keypairs.append(entry)

    return keypairs


def extract_ecdh_vectors():
    """
    Extract X25519 ECDH shared secrets between keypair combinations.
    Both sides must compute the same shared secret.
    """
    pairs = [(0, 1), (0, 2), (0, 3), (1, 2)]
    vectors = []

    identities = []
    for prv_hex, _ in fixed_keys:
        identities.append(RNS.Identity.from_bytes(bytes.fromhex(prv_hex)))

    for a, b in pairs:
        id_a = identities[a]
        id_b = identities[b]

        # a's private × b's public
        shared_ab = id_a.prv.exchange(
            X25519PublicKey.from_public_bytes(id_b.pub_bytes)
        )
        # b's private × a's public
        shared_ba = id_b.prv.exchange(
            X25519PublicKey.from_public_bytes(id_a.pub_bytes)
        )
        assert shared_ab == shared_ba, (
            f"ECDH mismatch for keypairs {a}↔{b}: "
            f"{shared_ab.hex()} != {shared_ba.hex()}"
        )

        vectors.append({
            "keypair_a": a,
            "keypair_b": b,
            "shared_secret": shared_ab.hex(),
            "shared_secret_length": len(shared_ab),
        })

    return vectors


def extract_signature_vectors():
    """
    Extract Ed25519 signatures from all 5 keypairs.
    Uses the same message for cross-comparison, plus one unique message per keypair.
    """
    common_message = b"Reticulum test vector"
    vectors = []

    for idx, (prv_hex, _) in enumerate(fixed_keys):
        identity = RNS.Identity.from_bytes(bytes.fromhex(prv_hex))

        # Sign common message
        sig_common = identity.sign(common_message)
        assert len(sig_common) == 64

        # Sign unique message
        unique_message = f"keypair {idx} unique message".encode("utf-8")
        sig_unique = identity.sign(unique_message)
        assert len(sig_unique) == 64

        vectors.append({
            "keypair_index": idx,
            "common_message": common_message.hex(),
            "common_signature": sig_common.hex(),
            "unique_message": unique_message.hex(),
            "unique_message_utf8": unique_message.decode("utf-8"),
            "unique_signature": sig_unique.hex(),
        })

    return vectors


def build_output(keypairs, ecdh_vectors, signature_vectors):
    # Signature test vector (original, from tests/identity.py)
    # Critical: signed_message is signed as .encode("utf-8") — the UTF-8 bytes
    # of the hex string literal, NOT the decoded binary.
    message_bytes = signed_message.encode("utf-8")

    # Encryption test vector
    token_bytes = bytes.fromhex(fixed_token)
    ephemeral_pub = token_bytes[:32]
    fernet_token = token_bytes[32:]

    return {
        "description": "Reticulum v1.1.3 reference implementation - fixed keypair test vectors",
        "source": "tests/identity.py",
        "constants": {
            "truncated_hash_length_bytes": 16,
            "name_hash_length_bytes": 10,
            "key_size_bytes": 64,
            "signature_length_bytes": 64,
            "token_overhead_bytes": 48,
        },
        "keypairs": keypairs,
        "signature_test": {
            "keypair_index": 0,
            "message": message_bytes.hex(),
            "message_note": "UTF-8 encoding of hex string literal, NOT decoded hex bytes",
            "signature": sig_from_key_0,
        },
        "signature_vectors": signature_vectors,
        "ecdh_vectors": ecdh_vectors,
        "encryption_test": {
            "keypair_index": 0,
            "plaintext": encrypted_message,
            "ciphertext_token": fixed_token,
            "ephemeral_public_key": ephemeral_pub.hex(),
            "fernet_token": fernet_token.hex(),
            "note": "Decryption-only. Encryption is non-deterministic (random ephemeral key).",
        },
    }


def verify(output):
    """Run inline verification before writing."""

    # 1. All identity hashes match fixed_keys
    for kp in output["keypairs"]:
        expected = fixed_keys[kp["index"]][1]
        assert kp["identity_hash"] == expected, (
            f"Keypair {kp['index']}: hash mismatch {kp['identity_hash']} != {expected}"
        )
    print(f"  [OK] All {len(output['keypairs'])} identity hashes match fixed_keys")

    # 2. Decrypt fixed_token with keypair 0 and verify plaintext
    fid = RNS.Identity.from_bytes(bytes.fromhex(fixed_keys[0][0]))
    plaintext = fid.decrypt(bytes.fromhex(fixed_token))
    assert plaintext == bytes.fromhex(encrypted_message), "Decryption verification failed"
    print("  [OK] Decryption of fixed_token produces encrypted_message")

    # 3. Verify original signature
    sig = fid.sign(signed_message.encode("utf-8"))
    assert sig == bytes.fromhex(sig_from_key_0), "Signature verification failed"
    print("  [OK] Signature of signed_message matches sig_from_key_0")

    # 4. Verify ECDH vectors (both sides produce same shared secret)
    identities = []
    for prv_hex, _ in fixed_keys:
        identities.append(RNS.Identity.from_bytes(bytes.fromhex(prv_hex)))

    for vec in output["ecdh_vectors"]:
        a, b = vec["keypair_a"], vec["keypair_b"]
        shared = identities[a].prv.exchange(
            X25519PublicKey.from_public_bytes(identities[b].pub_bytes)
        )
        assert shared.hex() == vec["shared_secret"], (
            f"ECDH verify failed for {a}↔{b}"
        )
    print(f"  [OK] All {len(output['ecdh_vectors'])} ECDH shared secrets verified")

    # 5. Verify all signature vectors
    for vec in output["signature_vectors"]:
        idx = vec["keypair_index"]
        identity = identities[idx]

        sig_c = identity.sign(bytes.fromhex(vec["common_message"]))
        assert sig_c.hex() == vec["common_signature"], (
            f"Common signature verify failed for keypair {idx}"
        )
        identity.validate(sig_c, bytes.fromhex(vec["common_message"]))

        sig_u = identity.sign(bytes.fromhex(vec["unique_message"]))
        assert sig_u.hex() == vec["unique_signature"], (
            f"Unique signature verify failed for keypair {idx}"
        )
        identity.validate(sig_u, bytes.fromhex(vec["unique_message"]))
    print(f"  [OK] All {len(output['signature_vectors'])} signature vectors verified")

    # 6. JSON round-trip integrity
    json_str = json.dumps(output, indent=2)
    roundtripped = json.loads(json_str)
    assert roundtripped == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting keypairs from tests/identity.py...")
    keypairs = extract_keypairs()
    print(f"  Extracted {len(keypairs)} keypairs")

    print("Extracting ECDH shared secrets...")
    ecdh_vectors = extract_ecdh_vectors()
    print(f"  Extracted {len(ecdh_vectors)} ECDH vectors")

    print("Extracting signature vectors from all keypairs...")
    signature_vectors = extract_signature_vectors()
    print(f"  Extracted {len(signature_vectors)} signature vectors")

    print("Building output...")
    output = build_output(keypairs, ecdh_vectors, signature_vectors)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
