#!/usr/bin/env python3
"""
Extract destination hash test vectors from the Reticulum reference implementation
into a JSON file for consumption by alternative implementations.

Shows the full derivation chain: expand_name -> name_hash -> addr_hash_material -> destination_hash.

Usage:
    python3 test_vectors/extract_destinations.py

Output:
    test_vectors/destination_hashes.json
"""

import hashlib
import json
import os
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

import RNS
from tests.identity import fixed_keys

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "destination_hashes.json")

# Load the known destination hashes from keypairs.json for cross-verification
KEYPAIRS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")


def derive_destination_hash(identity, app_name, *aspects):
    """
    Manually derive a destination hash step-by-step, matching the algorithm
    in RNS/Destination.py:hash().

    Steps:
        1. expand_name(None, app_name, *aspects) -> full_name (without identity hash)
        2. SHA-256(full_name.encode("utf-8"))[:10] -> name_hash (NAME_HASH_LENGTH=80 bits)
        3. name_hash + identity.hash -> addr_hash_material (26 bytes)
        4. SHA-256(addr_hash_material)[:16] -> destination_hash (TRUNCATED_HASHLENGTH=128 bits)
    """
    # Step 1: expand name without identity to get base name
    base_name = RNS.Destination.expand_name(None, app_name, *aspects)

    # Step 2: name_hash = SHA-256(base_name.encode("utf-8"))[:10]
    name_hash = hashlib.sha256(base_name.encode("utf-8")).digest()[:10]

    # Step 3: addr_hash_material = name_hash + identity_hash
    identity_hash = identity.hash
    addr_hash_material = name_hash + identity_hash

    # Step 4: destination_hash = SHA-256(addr_hash_material)[:16]
    destination_hash = hashlib.sha256(addr_hash_material).digest()[:16]

    # Verify against the library
    lib_hash = RNS.Destination.hash(identity, app_name, *aspects)
    assert destination_hash == lib_hash, (
        f"Manual derivation mismatch: {destination_hash.hex()} != {lib_hash.hex()}"
    )

    # Also get the full expanded name (with identity hash) for reference
    full_name = RNS.Destination.expand_name(identity, app_name, *aspects)

    return {
        "app_name": app_name,
        "aspects": list(aspects),
        "base_name": base_name,
        "base_name_note": "expand_name(None, app_name, *aspects) — without identity hash suffix",
        "full_name": full_name,
        "full_name_note": "expand_name(identity, app_name, *aspects) — with identity hexhash suffix",
        "name_hash": name_hash.hex(),
        "name_hash_length_bytes": len(name_hash),
        "identity_hash": identity_hash.hex(),
        "addr_hash_material": addr_hash_material.hex(),
        "addr_hash_material_length_bytes": len(addr_hash_material),
        "destination_hash": destination_hash.hex(),
    }


def derive_plain_destination_hash(app_name, *aspects):
    """
    Derive a PLAIN destination hash (no identity).

    Steps:
        1. expand_name(None, app_name, *aspects) -> full_name
        2. SHA-256(full_name.encode("utf-8"))[:10] -> name_hash
        3. addr_hash_material = name_hash (no identity hash)
        4. SHA-256(addr_hash_material)[:16] -> destination_hash
    """
    base_name = RNS.Destination.expand_name(None, app_name, *aspects)
    name_hash = hashlib.sha256(base_name.encode("utf-8")).digest()[:10]
    addr_hash_material = name_hash  # No identity hash for PLAIN
    destination_hash = hashlib.sha256(addr_hash_material).digest()[:16]

    # Verify against the library
    lib_hash = RNS.Destination.hash(None, app_name, *aspects)
    assert destination_hash == lib_hash, (
        f"PLAIN derivation mismatch: {destination_hash.hex()} != {lib_hash.hex()}"
    )

    return {
        "app_name": app_name,
        "aspects": list(aspects),
        "base_name": base_name,
        "name_hash": name_hash.hex(),
        "name_hash_length_bytes": len(name_hash),
        "identity_hash": None,
        "addr_hash_material": addr_hash_material.hex(),
        "addr_hash_material_length_bytes": len(addr_hash_material),
        "destination_hash": destination_hash.hex(),
        "note": "PLAIN destination: no identity, addr_hash_material is just name_hash",
    }


def extract_vectors():
    """Extract destination hash vectors for all 5 keypairs with multiple app/aspect combos."""
    identities = []
    for idx, (prv_hex, expected_hash_hex) in enumerate(fixed_keys):
        identity = RNS.Identity.from_bytes(bytes.fromhex(prv_hex))
        assert identity.hash == bytes.fromhex(expected_hash_hex)
        identities.append(identity)

    vectors = []

    # Primary: all 5 keypairs with "rns_unit_tests.link.establish"
    for idx, identity in enumerate(identities):
        entry = derive_destination_hash(identity, "rns_unit_tests", "link", "establish")
        entry["keypair_index"] = idx
        vectors.append(entry)

    # Additional app/aspect combos for diversity (using keypair 0)
    extra_combos = [
        ("myapp", "delivery"),
        ("myapp", "messaging", "incoming"),
        ("lxmf", "delivery"),
        ("nomadnet", "node"),
    ]
    for combo in extra_combos:
        app_name = combo[0]
        aspects = combo[1:]
        entry = derive_destination_hash(identities[0], app_name, *aspects)
        entry["keypair_index"] = 0
        vectors.append(entry)

    return vectors


def extract_plain_vectors():
    """Extract PLAIN destination hash vectors (no identity)."""
    vectors = []
    combos = [
        ("rns_unit_tests", "link", "establish"),
        ("myapp", "discovery"),
    ]
    for combo in combos:
        app_name = combo[0]
        aspects = combo[1:]
        vectors.append(derive_plain_destination_hash(app_name, *aspects))

    return vectors


def build_output(vectors, plain_vectors):
    return {
        "description": "Reticulum v1.1.3 reference implementation - destination hash test vectors",
        "source": "RNS/Destination.py",
        "constants": {
            "name_hash_length_bits": 80,
            "name_hash_length_bytes": 10,
            "truncated_hash_length_bits": 128,
            "truncated_hash_length_bytes": 16,
        },
        "algorithm": {
            "step_1": "base_name = app_name + '.' + aspect1 + '.' + aspect2 + ... (no identity hash)",
            "step_2": "name_hash = SHA-256(base_name.encode('utf-8'))[:10]",
            "step_3": "addr_hash_material = name_hash + identity_hash (26 bytes for SINGLE destinations)",
            "step_4": "destination_hash = SHA-256(addr_hash_material)[:16]",
            "plain_note": "For PLAIN destinations, addr_hash_material = name_hash only (10 bytes, no identity_hash)",
            "full_name_note": "expand_name(identity, ...) appends '.' + identity.hexhash to the base name",
        },
        "single_destinations": vectors,
        "plain_destinations": plain_vectors,
    }


def verify(output):
    # Cross-verify against keypairs.json
    if os.path.exists(KEYPAIRS_PATH):
        with open(KEYPAIRS_PATH, "r") as f:
            keypairs = json.load(f)

        for vec in output["single_destinations"]:
            if "keypair_index" in vec and vec["app_name"] == "rns_unit_tests" and vec["aspects"] == ["link", "establish"]:
                idx = vec["keypair_index"]
                expected = keypairs["keypairs"][idx]["destination_hashes"]["rns_unit_tests.link.establish"]
                assert vec["destination_hash"] == expected, (
                    f"Keypair {idx}: destination hash mismatch with keypairs.json: "
                    f"{vec['destination_hash']} != {expected}"
                )
        print("  [OK] Destination hashes cross-verified against keypairs.json")
    else:
        print("  [SKIP] keypairs.json not found for cross-verification")

    # Verify all derivations independently
    for vec in output["single_destinations"]:
        idx = vec["keypair_index"]
        identity = RNS.Identity.from_bytes(bytes.fromhex(fixed_keys[idx][0]))
        lib_hash = RNS.Destination.hash(identity, vec["app_name"], *vec["aspects"])
        assert lib_hash.hex() == vec["destination_hash"], (
            f"Library verification failed for {vec['base_name']}"
        )
    print(f"  [OK] All {len(output['single_destinations'])} SINGLE destination vectors verified")

    for vec in output["plain_destinations"]:
        lib_hash = RNS.Destination.hash(None, vec["app_name"], *vec["aspects"])
        assert lib_hash.hex() == vec["destination_hash"], (
            f"Library verification failed for PLAIN {vec['base_name']}"
        )
    print(f"  [OK] All {len(output['plain_destinations'])} PLAIN destination vectors verified")

    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting destination hash vectors...")

    vectors = extract_vectors()
    print(f"  Extracted {len(vectors)} SINGLE destination vectors")

    plain_vectors = extract_plain_vectors()
    print(f"  Extracted {len(plain_vectors)} PLAIN destination vectors")

    print("Building output...")
    output = build_output(vectors, plain_vectors)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
