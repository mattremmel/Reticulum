#!/usr/bin/env python3
"""
Extract Token (modified Fernet) test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

Covers PKCS7 padding, HMAC-SHA256, and deterministic Fernet token construction.

Usage:
    python3 test_vectors/extract_token.py

Output:
    test_vectors/token.json
"""

import json
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

import RNS
from RNS.Cryptography import HMAC, PKCS7, AES
from RNS.Cryptography.AES import AES_256_CBC
from RNS.Cryptography.Token import Token as TokenClass
from tests.identity import encrypted_message, fixed_keys, fixed_token

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "token.json")


def extract_pkcs7_vectors():
    """PKCS7 padding vectors for block size 16."""
    vectors = []

    cases = [
        ("empty (0 bytes)", b""),
        ("1 byte", b"\x01"),
        ("15 bytes", bytes(range(15))),
        ("16 bytes (full block)", bytes(range(16))),
        ("31 bytes", bytes(range(31))),
    ]

    for desc, data in cases:
        padded = PKCS7.pad(data)
        assert len(padded) % 16 == 0, f"PKCS7 padding not block-aligned for: {desc}"
        unpadded = PKCS7.unpad(padded)
        assert unpadded == data, f"PKCS7 round-trip failed for: {desc}"

        pad_byte = padded[-1]
        pad_length = pad_byte

        vectors.append({
            "description": desc,
            "input": data.hex(),
            "input_length": len(data),
            "padded": padded.hex(),
            "padded_length": len(padded),
            "pad_byte": f"{pad_byte:02x}",
            "pad_length": pad_length,
        })

    return vectors


def extract_hmac_vectors():
    """HMAC-SHA256 vectors with known inputs."""
    vectors = []

    cases = [
        ("key=32 zero bytes, msg=empty", bytes(32), b""),
        ("key=32 zero bytes, msg='abc'", bytes(32), b"abc"),
        ("key='Reticulum' padded to 32, msg='Hello'", b"Reticulum" + bytes(23), b"Hello"),
        ("key=all 0xff (32 bytes), msg=16 zero bytes", bytes([0xff] * 32), bytes(16)),
    ]

    for desc, key, msg in cases:
        digest = HMAC.new(key, msg).digest()
        vectors.append({
            "description": desc,
            "key": key.hex(),
            "message": msg.hex(),
            "digest": digest.hex(),
            "digest_length": len(digest),
        })

    return vectors


def extract_deterministic_fernet_vector():
    """
    Construct a Fernet token deterministically with a fixed key and IV,
    then verify Token.decrypt() can decode it.

    Token format (Reticulum modified Fernet, no version/timestamp):
        IV (16 bytes) + AES-256-CBC(PKCS7.pad(plaintext)) + HMAC-SHA256(signing_key, IV + ciphertext)

    Key split: 64-byte key -> signing_key[:32] + encryption_key[32:]
    """
    # Use a deterministic key (64 bytes for AES-256)
    key = bytes(range(64))
    signing_key = key[:32]
    encryption_key = key[32:]

    # Fixed IV
    iv = bytes([0x10] * 16)

    # Plaintext
    plaintext = b"Hello, Reticulum!"

    # Pad
    padded = PKCS7.pad(plaintext)

    # Encrypt
    ciphertext = AES_256_CBC.encrypt(plaintext=padded, key=encryption_key, iv=iv)

    # Compute HMAC over IV + ciphertext
    signed_parts = iv + ciphertext
    hmac_digest = HMAC.new(signing_key, signed_parts).digest()

    # Assemble token
    token_bytes = signed_parts + hmac_digest

    # Verify Token.decrypt() can decode it
    t = TokenClass(key=key)
    decrypted = t.decrypt(token_bytes)
    assert decrypted == plaintext, f"Deterministic token decryption failed: {decrypted} != {plaintext}"

    return {
        "description": "Deterministic Fernet token with fixed key and IV",
        "key": key.hex(),
        "key_split": {
            "signing_key": signing_key.hex(),
            "encryption_key": encryption_key.hex(),
            "note": "64-byte key split: first 32 bytes = signing_key, last 32 bytes = encryption_key",
        },
        "iv": iv.hex(),
        "plaintext": plaintext.hex(),
        "plaintext_utf8": plaintext.decode("utf-8"),
        "padded_plaintext": padded.hex(),
        "ciphertext": ciphertext.hex(),
        "signed_parts": signed_parts.hex(),
        "signed_parts_note": "IV + ciphertext (input to HMAC)",
        "hmac": hmac_digest.hex(),
        "token": token_bytes.hex(),
        "token_layout": {
            "iv_offset": 0,
            "iv_length": 16,
            "ciphertext_offset": 16,
            "ciphertext_length": len(ciphertext),
            "hmac_offset": 16 + len(ciphertext),
            "hmac_length": 32,
            "total_length": len(token_bytes),
        },
    }


def decompose_fixed_token():
    """
    Decompose the fixed_token from tests/identity.py into its components.

    The fixed_token is an Identity.encrypt() output:
        ephemeral_public_key (32 bytes) + fernet_token (rest)

    The fernet_token itself is:
        IV (16 bytes) + ciphertext + HMAC (32 bytes)
    """
    token_bytes = bytes.fromhex(fixed_token)

    ephemeral_pub = token_bytes[:32]
    fernet_token = token_bytes[32:]

    fernet_iv = fernet_token[:16]
    fernet_hmac = fernet_token[-32:]
    fernet_ciphertext = fernet_token[16:-32]

    # Verify decryption works
    fid = RNS.Identity.from_bytes(bytes.fromhex(fixed_keys[0][0]))
    plaintext = fid.decrypt(token_bytes)
    assert plaintext == bytes.fromhex(encrypted_message), "Fixed token decryption verification failed"

    return {
        "description": "Decomposition of fixed_token from tests/identity.py (Identity.encrypt output)",
        "fixed_token": fixed_token,
        "total_length": len(token_bytes),
        "layout": {
            "ephemeral_public_key": {
                "offset": 0,
                "length": 32,
                "value": ephemeral_pub.hex(),
                "note": "X25519 ephemeral public key for ECDH",
            },
            "fernet_token": {
                "offset": 32,
                "length": len(fernet_token),
                "value": fernet_token.hex(),
                "components": {
                    "iv": {
                        "offset": 0,
                        "length": 16,
                        "value": fernet_iv.hex(),
                    },
                    "ciphertext": {
                        "offset": 16,
                        "length": len(fernet_ciphertext),
                        "value": fernet_ciphertext.hex(),
                    },
                    "hmac": {
                        "offset": 16 + len(fernet_ciphertext),
                        "length": 32,
                        "value": fernet_hmac.hex(),
                    },
                },
            },
        },
        "plaintext": encrypted_message,
        "decryption_note": "Decryption-only vector. The ephemeral key is random, so encryption is non-deterministic.",
    }


def build_output(pkcs7_vectors, hmac_vectors, deterministic_vector, fixed_token_decomp):
    return {
        "description": "Reticulum v1.1.3 reference implementation - Token (modified Fernet) test vectors",
        "source": "RNS/Cryptography/Token.py, RNS/Cryptography/PKCS7.py",
        "constants": {
            "token_overhead_bytes": 48,
            "token_overhead_note": "16 (IV) + 32 (HMAC-SHA256)",
            "aes_block_size_bytes": 16,
            "hmac_digest_length_bytes": 32,
            "aes_256_key_length_bytes": 32,
            "total_token_key_length_bytes": 64,
        },
        "token_format": {
            "description": "Modified Fernet: no VERSION or TIMESTAMP fields (unlike standard Fernet)",
            "layout": "IV (16 bytes) || AES-256-CBC(PKCS7.pad(plaintext)) || HMAC-SHA256(signing_key, IV || ciphertext)",
            "key_split": "64-byte key -> signing_key = key[:32], encryption_key = key[32:]",
        },
        "pkcs7_padding": pkcs7_vectors,
        "hmac_sha256": hmac_vectors,
        "deterministic_fernet": deterministic_vector,
        "fixed_token_decomposition": fixed_token_decomp,
    }


def verify(output):
    # Verify PKCS7 round-trips
    for vec in output["pkcs7_padding"]:
        padded = bytes.fromhex(vec["padded"])
        unpadded = PKCS7.unpad(padded)
        assert unpadded == bytes.fromhex(vec["input"]), f"PKCS7 verify failed: {vec['description']}"
    print(f"  [OK] All {len(output['pkcs7_padding'])} PKCS7 vectors round-trip verified")

    # Verify HMAC vectors
    for vec in output["hmac_sha256"]:
        digest = HMAC.new(bytes.fromhex(vec["key"]), bytes.fromhex(vec["message"])).digest()
        assert digest.hex() == vec["digest"], f"HMAC verify failed: {vec['description']}"
    print(f"  [OK] All {len(output['hmac_sha256'])} HMAC-SHA256 vectors verified")

    # Verify deterministic token
    det = output["deterministic_fernet"]
    t = TokenClass(key=bytes.fromhex(det["key"]))
    decrypted = t.decrypt(bytes.fromhex(det["token"]))
    assert decrypted == bytes.fromhex(det["plaintext"]), "Deterministic Fernet verification failed"
    print("  [OK] Deterministic Fernet token verified")

    # Verify fixed token decomposition
    decomp = output["fixed_token_decomposition"]
    fid = RNS.Identity.from_bytes(bytes.fromhex(fixed_keys[0][0]))
    pt = fid.decrypt(bytes.fromhex(decomp["fixed_token"]))
    assert pt == bytes.fromhex(decomp["plaintext"]), "Fixed token decomposition verification failed"
    print("  [OK] Fixed token decomposition verified")

    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting Token vectors...")

    pkcs7_vectors = extract_pkcs7_vectors()
    print(f"  Extracted {len(pkcs7_vectors)} PKCS7 padding vectors")

    hmac_vectors = extract_hmac_vectors()
    print(f"  Extracted {len(hmac_vectors)} HMAC-SHA256 vectors")

    deterministic_vector = extract_deterministic_fernet_vector()
    print("  Extracted deterministic Fernet vector")

    fixed_token_decomp = decompose_fixed_token()
    print("  Decomposed fixed_token from tests/identity.py")

    print("Building output...")
    output = build_output(pkcs7_vectors, hmac_vectors, deterministic_vector, fixed_token_decomp)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
