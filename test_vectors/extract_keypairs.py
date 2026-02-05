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


def build_output(keypairs):
    # Signature test vector
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

    # 3. Verify signature
    sig = fid.sign(signed_message.encode("utf-8"))
    assert sig == bytes.fromhex(sig_from_key_0), "Signature verification failed"
    print("  [OK] Signature of signed_message matches sig_from_key_0")

    # 4. JSON round-trip integrity
    json_str = json.dumps(output, indent=2)
    roundtripped = json.loads(json_str)
    assert roundtripped == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting keypairs from tests/identity.py...")
    keypairs = extract_keypairs()
    print(f"  Extracted {len(keypairs)} keypairs")

    print("Building output...")
    output = build_output(keypairs)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
