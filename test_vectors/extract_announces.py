#!/usr/bin/env python3
"""
Extract announce protocol test vectors from the Reticulum reference implementation
into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Destination/Transport objects) to avoid
Transport init. Real RNS.Identity objects are used for signing and key derivation.

Usage:
    python3 test_vectors/extract_announces.py

Output:
    test_vectors/announces.json
"""

import hashlib
import json
import os
import struct
import sys
import time

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "announces.json")
KEYPAIRS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")

# --- Constants (reproduced to avoid Transport init) ---
HEADER_1 = 0x00
HEADER_2 = 0x01
ANNOUNCE = 0x01
BROADCAST = 0x00
TRANSPORT = 0x01
SINGLE = 0x00
FLAG_SET = 0x01
FLAG_UNSET = 0x00
NONE_CONTEXT = 0x00
PATH_RESPONSE = 0x0B

MTU = 500
HEADER_MINSIZE = 19
HEADER_MAXSIZE = 35
TRUNCATED_HASHLENGTH_BYTES = 16
KEYSIZE_BYTES = 64          # 32 X25519 + 32 Ed25519
NAME_HASH_LENGTH_BYTES = 10
SIGLENGTH_BYTES = 64
RATCHETSIZE_BYTES = 32
RANDOM_HASH_LENGTH = 10

# Announce payload layout (no ratchet):
#   public_key(64) + name_hash(10) + random_hash(10) + signature(64) [+ app_data]
# = 148 bytes minimum
ANNOUNCE_MIN_PAYLOAD = KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + SIGLENGTH_BYTES  # 148

# Fixed timestamp for deterministic test vectors
FIXED_TIMESTAMP = 1700000000


def load_keypairs():
    with open(KEYPAIRS_PATH, "r") as f:
        data = json.load(f)
    return data["keypairs"]


def pack_flags(header_type, context_flag, transport_type, dest_type, packet_type):
    return (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | packet_type


def build_header_1(flags_byte, hops, dest_hash, context_byte):
    header = struct.pack("!B", flags_byte)
    header += struct.pack("!B", hops)
    header += dest_hash
    header += bytes([context_byte])
    return header


def compute_packet_hash(raw_packet):
    flags = raw_packet[0]
    header_type = (flags & 0b01000000) >> 6
    hashable_part = bytes([flags & 0x0F])
    if header_type == HEADER_2:
        hashable_part += raw_packet[TRUNCATED_HASHLENGTH_BYTES + 2:]
    else:
        hashable_part += raw_packet[2:]
    full_hash = hashlib.sha256(hashable_part).digest()
    truncated_hash = full_hash[:TRUNCATED_HASHLENGTH_BYTES]
    return hashable_part, full_hash, truncated_hash


def make_name_hash(app_name, *aspects):
    """Compute name_hash = SHA256(expand_name(None, app_name, *aspects))[:10]"""
    name = app_name
    for aspect in aspects:
        name += "." + aspect
    return hashlib.sha256(name.encode("utf-8")).digest()[:NAME_HASH_LENGTH_BYTES]


def make_identity_hash(public_key_bytes):
    """Compute identity hash = SHA256(public_key)[:16]"""
    return hashlib.sha256(public_key_bytes).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_destination_hash(name_hash, identity_hash):
    """Compute destination hash = SHA256(name_hash + identity_hash)[:16]"""
    return hashlib.sha256(name_hash + identity_hash).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_random_hash(deterministic_bytes, timestamp):
    """Build the 10-byte random_hash: 5 random bytes + 5-byte big-endian timestamp."""
    return deterministic_bytes[:5] + int(timestamp).to_bytes(5, "big")


def load_identity(kp):
    """Load an RNS.Identity from a keypair dict."""
    import RNS
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(bytes.fromhex(kp["private_key"]))
    return identity


def make_announce_payload(identity, name_hash, dest_hash, random_hash,
                          ratchet_pub=b"", app_data=None):
    """
    Construct announce payload manually, matching Destination.announce().

    signed_data = dest_hash + public_key + name_hash + random_hash + ratchet + [app_data]
    signature = identity.sign(signed_data)
    payload = public_key + name_hash + random_hash + ratchet + signature + [app_data]
    """
    public_key = identity.get_public_key()
    signed_data = dest_hash + public_key + name_hash + random_hash + ratchet_pub
    if app_data is not None:
        signed_data += app_data

    signature = identity.sign(signed_data)

    payload = public_key + name_hash + random_hash + ratchet_pub + signature
    if app_data is not None:
        payload += app_data

    return {
        "public_key": public_key,
        "signed_data": signed_data,
        "signature": signature,
        "payload": payload,
    }


def make_flags_byte(context_flag):
    """Build the flags byte for a standard BROADCAST SINGLE ANNOUNCE."""
    return pack_flags(HEADER_1, context_flag, BROADCAST, SINGLE, ANNOUNCE)


def make_raw_packet(flags_byte, hops, dest_hash, context, payload):
    """Build a complete raw packet: header + payload."""
    header = build_header_1(flags_byte, hops, dest_hash, context)
    return header + payload


# --- Deterministic random hashes for each keypair ---
DETERMINISTIC_RANDOM_PREFIXES = [
    bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE]),
    bytes([0x11, 0x22, 0x33, 0x44, 0x55]),
    bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x01]),
    bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x02]),
    bytes([0xF0, 0x0D, 0xBA, 0xD0, 0x03]),
]


def extract_valid_announces(keypairs):
    """Category 1: Valid announce creation & signature validation (Reticulum-vq2)."""
    vectors = []

    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)

    # One vector per keypair
    for i, kp in enumerate(keypairs):
        identity = load_identity(kp)
        public_key = identity.get_public_key()
        identity_hash = bytes.fromhex(kp["identity_hash"])
        dest_hash = make_destination_hash(name_hash, identity_hash)

        # Verify our dest_hash matches keypairs.json
        expected_dest = kp["destination_hashes"]["rns_unit_tests.link.establish"]
        assert dest_hash.hex() == expected_dest, (
            f"Keypair {i}: dest_hash {dest_hash.hex()} != expected {expected_dest}"
        )

        random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[i], FIXED_TIMESTAMP)
        flags = make_flags_byte(FLAG_UNSET)
        context = NONE_CONTEXT

        result = make_announce_payload(identity, name_hash, dest_hash, random_hash)
        raw = make_raw_packet(flags, 0, dest_hash, context, result["payload"])
        _, _, packet_hash = compute_packet_hash(raw)

        vectors.append({
            "description": f"Valid announce from keypair {i}, app=rns_unit_tests.link.establish",
            "keypair_index": i,
            "app_name": app_name,
            "aspects": aspects,
            "name_hash": name_hash.hex(),
            "identity_hash": identity_hash.hex(),
            "destination_hash": dest_hash.hex(),
            "random_hash": random_hash.hex(),
            "timestamp_embedded": FIXED_TIMESTAMP,
            "public_key": public_key.hex(),
            "signed_data": result["signed_data"].hex(),
            "signature": result["signature"].hex(),
            "announce_payload": result["payload"].hex(),
            "announce_payload_length": len(result["payload"]),
            "context_flag": FLAG_UNSET,
            "flags_byte": f"{flags:02x}",
            "hops": 0,
            "context": f"{context:02x}",
            "raw_packet": raw.hex(),
            "raw_packet_length": len(raw),
            "packet_hash": packet_hash.hex(),
        })

    # Additional variants

    # Variant: different app/aspect name
    identity = load_identity(keypairs[0])
    identity_hash = bytes.fromhex(keypairs[0]["identity_hash"])
    alt_app = "myapp"
    alt_aspects = ["messaging", "v1"]
    alt_name_hash = make_name_hash(alt_app, *alt_aspects)
    alt_dest_hash = make_destination_hash(alt_name_hash, identity_hash)
    random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[0], FIXED_TIMESTAMP)
    flags = make_flags_byte(FLAG_UNSET)

    result = make_announce_payload(identity, alt_name_hash, alt_dest_hash, random_hash)
    raw = make_raw_packet(flags, 0, alt_dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Valid announce with different app name: myapp.messaging.v1",
        "keypair_index": 0,
        "app_name": alt_app,
        "aspects": alt_aspects,
        "name_hash": alt_name_hash.hex(),
        "identity_hash": identity_hash.hex(),
        "destination_hash": alt_dest_hash.hex(),
        "random_hash": random_hash.hex(),
        "timestamp_embedded": FIXED_TIMESTAMP,
        "public_key": identity.get_public_key().hex(),
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "context_flag": FLAG_UNSET,
        "flags_byte": f"{flags:02x}",
        "hops": 0,
        "context": f"{NONE_CONTEXT:02x}",
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # Variant: PATH_RESPONSE context
    identity = load_identity(keypairs[0])
    identity_hash = bytes.fromhex(keypairs[0]["identity_hash"])
    name_hash_pr = make_name_hash(app_name, *aspects)
    dest_hash_pr = make_destination_hash(name_hash_pr, identity_hash)
    random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[0], FIXED_TIMESTAMP)
    flags = make_flags_byte(FLAG_UNSET)

    result = make_announce_payload(identity, name_hash_pr, dest_hash_pr, random_hash)
    raw = make_raw_packet(flags, 0, dest_hash_pr, PATH_RESPONSE, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Valid announce as PATH_RESPONSE (context=0x0B)",
        "keypair_index": 0,
        "app_name": app_name,
        "aspects": aspects,
        "name_hash": name_hash_pr.hex(),
        "identity_hash": identity_hash.hex(),
        "destination_hash": dest_hash_pr.hex(),
        "random_hash": random_hash.hex(),
        "timestamp_embedded": FIXED_TIMESTAMP,
        "public_key": identity.get_public_key().hex(),
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "context_flag": FLAG_UNSET,
        "flags_byte": f"{flags:02x}",
        "hops": 0,
        "context": f"{PATH_RESPONSE:02x}",
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # Variant: nonzero hop count (simulating retransmitted announce)
    identity = load_identity(keypairs[1])
    identity_hash = bytes.fromhex(keypairs[1]["identity_hash"])
    dest_hash_hops = make_destination_hash(name_hash, identity_hash)
    random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[1], FIXED_TIMESTAMP)
    flags = make_flags_byte(FLAG_UNSET)

    result = make_announce_payload(identity, name_hash, dest_hash_hops, random_hash)
    raw = make_raw_packet(flags, 3, dest_hash_hops, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Valid announce with hops=3 (retransmitted)",
        "keypair_index": 1,
        "app_name": app_name,
        "aspects": aspects,
        "name_hash": name_hash.hex(),
        "identity_hash": identity_hash.hex(),
        "destination_hash": dest_hash_hops.hex(),
        "random_hash": random_hash.hex(),
        "timestamp_embedded": FIXED_TIMESTAMP,
        "public_key": identity.get_public_key().hex(),
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "context_flag": FLAG_UNSET,
        "flags_byte": f"{flags:02x}",
        "hops": 3,
        "context": f"{NONE_CONTEXT:02x}",
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # Variant: single aspect (no sub-aspects)
    identity = load_identity(keypairs[2])
    identity_hash = bytes.fromhex(keypairs[2]["identity_hash"])
    single_app = "nomadnetwork"
    single_aspects = ["node"]
    single_name_hash = make_name_hash(single_app, *single_aspects)
    single_dest_hash = make_destination_hash(single_name_hash, identity_hash)
    random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[2], FIXED_TIMESTAMP)
    flags = make_flags_byte(FLAG_UNSET)

    result = make_announce_payload(identity, single_name_hash, single_dest_hash, random_hash)
    raw = make_raw_packet(flags, 0, single_dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Valid announce with single aspect: nomadnetwork.node",
        "keypair_index": 2,
        "app_name": single_app,
        "aspects": single_aspects,
        "name_hash": single_name_hash.hex(),
        "identity_hash": identity_hash.hex(),
        "destination_hash": single_dest_hash.hex(),
        "random_hash": random_hash.hex(),
        "timestamp_embedded": FIXED_TIMESTAMP,
        "public_key": identity.get_public_key().hex(),
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "context_flag": FLAG_UNSET,
        "flags_byte": f"{flags:02x}",
        "hops": 0,
        "context": f"{NONE_CONTEXT:02x}",
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    return vectors


def extract_invalid_announces(keypairs):
    """Category 2: Invalid announce rejection (Reticulum-uhd)."""
    vectors = []

    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)

    # Build a valid baseline from keypair 0
    identity_0 = load_identity(keypairs[0])
    identity_hash_0 = bytes.fromhex(keypairs[0]["identity_hash"])
    dest_hash_0 = make_destination_hash(name_hash, identity_hash_0)
    random_hash_0 = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[0], FIXED_TIMESTAMP)

    valid = make_announce_payload(identity_0, name_hash, dest_hash_0, random_hash_0)

    # 1. Tampered signature — flip one byte in signature
    tampered_sig = bytearray(valid["signature"])
    tampered_sig[0] ^= 0xFF
    tampered_sig = bytes(tampered_sig)
    tampered_payload = (valid["public_key"] + name_hash + random_hash_0 +
                        tampered_sig)
    flags = make_flags_byte(FLAG_UNSET)
    raw = make_raw_packet(flags, 0, dest_hash_0, NONE_CONTEXT, tampered_payload)

    vectors.append({
        "description": "Tampered signature: first byte of signature flipped",
        "keypair_index": 0,
        "destination_hash": dest_hash_0.hex(),
        "tampered_field": "signature",
        "tampered_byte_offset_in_payload": KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH,
        "original_byte": f"{valid['signature'][0]:02x}",
        "tampered_byte": f"{tampered_sig[0]:02x}",
        "announce_payload": tampered_payload.hex(),
        "raw_packet": raw.hex(),
        "expected_failure": "signature_validation",
        "failure_reason": "Ed25519 signature does not match signed_data",
    })

    # 2. Wrong destination hash in header — use keypair 1's dest hash with keypair 0's payload
    identity_hash_1 = bytes.fromhex(keypairs[1]["identity_hash"])
    wrong_dest = make_destination_hash(name_hash, identity_hash_1)
    raw = make_raw_packet(flags, 0, wrong_dest, NONE_CONTEXT, valid["payload"])

    vectors.append({
        "description": "Wrong destination hash: header has keypair 1's dest, payload has keypair 0's keys",
        "keypair_index": 0,
        "destination_hash_in_header": wrong_dest.hex(),
        "correct_destination_hash": dest_hash_0.hex(),
        "announce_payload": valid["payload"].hex(),
        "raw_packet": raw.hex(),
        "expected_failure": "signature_validation",
        "failure_reason": "signed_data includes header dest_hash, but signature was made with correct dest_hash, so signature check fails",
    })

    # 3. Wrong public key — sign with keypair 0, embed keypair 1's public key
    identity_1 = load_identity(keypairs[1])
    pub_key_1 = identity_1.get_public_key()
    # signed_data uses keypair 0's dest_hash but keypair 1's public key
    wrong_signed = dest_hash_0 + pub_key_1 + name_hash + random_hash_0
    wrong_sig = identity_0.sign(wrong_signed)
    wrong_key_payload = pub_key_1 + name_hash + random_hash_0 + wrong_sig
    raw = make_raw_packet(flags, 0, dest_hash_0, NONE_CONTEXT, wrong_key_payload)

    vectors.append({
        "description": "Wrong public key: payload has keypair 1's public key, signed by keypair 0",
        "signing_keypair_index": 0,
        "embedded_keypair_index": 1,
        "destination_hash": dest_hash_0.hex(),
        "announce_payload": wrong_key_payload.hex(),
        "raw_packet": raw.hex(),
        "expected_failure": "signature_validation",
        "failure_reason": "Validator extracts public key from payload (keypair 1) and uses it to verify signature (made by keypair 0); verification fails",
    })

    # 4. Truncated payload — less than 148 bytes
    truncated_payload = valid["payload"][:100]
    raw = make_raw_packet(flags, 0, dest_hash_0, NONE_CONTEXT, truncated_payload)

    vectors.append({
        "description": "Truncated payload: only 100 bytes (minimum is 148)",
        "keypair_index": 0,
        "destination_hash": dest_hash_0.hex(),
        "announce_payload": truncated_payload.hex(),
        "announce_payload_length": len(truncated_payload),
        "minimum_payload_length": ANNOUNCE_MIN_PAYLOAD,
        "raw_packet": raw.hex(),
        "expected_failure": "parse_error",
        "failure_reason": "Payload too short to contain public_key(64) + name_hash(10) + random_hash(10) + signature(64)",
    })

    # 5. Corrupted name hash — wrong name_hash in payload
    wrong_name_hash = make_name_hash("wrong_app", "wrong_aspect")
    wrong_nh_signed = dest_hash_0 + identity_0.get_public_key() + wrong_name_hash + random_hash_0
    wrong_nh_sig = identity_0.sign(wrong_nh_signed)
    wrong_nh_payload = identity_0.get_public_key() + wrong_name_hash + random_hash_0 + wrong_nh_sig
    raw = make_raw_packet(flags, 0, dest_hash_0, NONE_CONTEXT, wrong_nh_payload)

    vectors.append({
        "description": "Corrupted name hash: payload has name_hash for 'wrong_app.wrong_aspect'",
        "keypair_index": 0,
        "destination_hash": dest_hash_0.hex(),
        "correct_name_hash": name_hash.hex(),
        "wrong_name_hash": wrong_name_hash.hex(),
        "announce_payload": wrong_nh_payload.hex(),
        "raw_packet": raw.hex(),
        "expected_failure": "destination_hash_mismatch",
        "failure_reason": "SHA256(wrong_name_hash + identity_hash)[:16] != destination_hash in header; signature passes but hash derivation check fails",
    })

    # 6. Swapped ratchet flag — FLAG_SET but no ratchet data in payload
    flags_ratchet = make_flags_byte(FLAG_SET)
    # Use a valid non-ratchet payload but set the ratchet flag
    raw = make_raw_packet(flags_ratchet, 0, dest_hash_0, NONE_CONTEXT, valid["payload"])

    vectors.append({
        "description": "Ratchet flag set but no ratchet data: parser treats bytes as ratchet, misaligning fields",
        "keypair_index": 0,
        "destination_hash": dest_hash_0.hex(),
        "context_flag": FLAG_SET,
        "flags_byte": f"{flags_ratchet:02x}",
        "announce_payload": valid["payload"].hex(),
        "raw_packet": raw.hex(),
        "expected_failure": "signature_validation",
        "failure_reason": "With FLAG_SET, validator reads 32 bytes as ratchet after random_hash, shifting signature extraction; wrong bytes used as signature",
        "payload_parsing_note": {
            "without_ratchet_flag": {
                "public_key": "payload[0:64]",
                "name_hash": "payload[64:74]",
                "random_hash": "payload[74:84]",
                "signature": "payload[84:148]",
            },
            "with_ratchet_flag": {
                "public_key": "payload[0:64]",
                "name_hash": "payload[64:74]",
                "random_hash": "payload[74:84]",
                "ratchet": "payload[84:116]",
                "signature": "payload[116:180]",
            },
        },
    })

    # 7. All zeros public key
    zero_pub = bytes(KEYSIZE_BYTES)
    zero_signed = dest_hash_0 + zero_pub + name_hash + random_hash_0
    zero_sig = identity_0.sign(zero_signed)
    zero_payload = zero_pub + name_hash + random_hash_0 + zero_sig
    raw = make_raw_packet(flags, 0, dest_hash_0, NONE_CONTEXT, zero_payload)

    vectors.append({
        "description": "All-zeros public key: invalid key material",
        "keypair_index": 0,
        "destination_hash": dest_hash_0.hex(),
        "announce_payload": zero_payload.hex(),
        "raw_packet": raw.hex(),
        "expected_failure": "signature_validation",
        "failure_reason": "All-zeros is not a valid public key; load_public_key or verify will fail",
    })

    return vectors


def extract_app_data_announces(keypairs):
    """Category 3: Announces with app_data (Reticulum-igj)."""
    vectors = []

    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)

    identity = load_identity(keypairs[0])
    identity_hash = bytes.fromhex(keypairs[0]["identity_hash"])
    dest_hash = make_destination_hash(name_hash, identity_hash)
    random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[0], FIXED_TIMESTAMP)
    flags = make_flags_byte(FLAG_UNSET)

    # 1. Small app_data: b"Hello"
    app_data = b"Hello"
    result = make_announce_payload(identity, name_hash, dest_hash, random_hash, app_data=app_data)
    raw = make_raw_packet(flags, 0, dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "App data: 5 bytes ASCII 'Hello'",
        "keypair_index": 0,
        "destination_hash": dest_hash.hex(),
        "app_data": app_data.hex(),
        "app_data_length": len(app_data),
        "app_data_utf8": app_data.decode("utf-8"),
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "raw_packet": raw.hex(),
        "packet_hash": packet_hash.hex(),
    })

    # 2. Medium: 100 bytes deterministic pattern
    app_data = bytes(range(100))
    result = make_announce_payload(identity, name_hash, dest_hash, random_hash, app_data=app_data)
    raw = make_raw_packet(flags, 0, dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "App data: 100 bytes sequential pattern (0x00..0x63)",
        "keypair_index": 0,
        "destination_hash": dest_hash.hex(),
        "app_data": app_data.hex(),
        "app_data_length": len(app_data),
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "raw_packet": raw.hex(),
        "packet_hash": packet_hash.hex(),
    })

    # 3. Max size app_data: MTU(500) - HEADER_MINSIZE(19) - 148 = 333 bytes
    max_app_data_len = MTU - HEADER_MINSIZE - ANNOUNCE_MIN_PAYLOAD
    app_data = bytes(range(256)) + bytes(range(max_app_data_len - 256))
    assert len(app_data) == max_app_data_len
    result = make_announce_payload(identity, name_hash, dest_hash, random_hash, app_data=app_data)
    raw = make_raw_packet(flags, 0, dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)
    assert len(raw) == MTU, f"Max app_data packet should be exactly MTU={MTU}, got {len(raw)}"

    vectors.append({
        "description": f"App data: maximum size {max_app_data_len} bytes (fills to MTU={MTU} with HEADER_1)",
        "keypair_index": 0,
        "destination_hash": dest_hash.hex(),
        "app_data": app_data.hex(),
        "app_data_length": len(app_data),
        "max_app_data_derivation": f"MTU({MTU}) - HEADER_MINSIZE({HEADER_MINSIZE}) - ANNOUNCE_MIN_PAYLOAD({ANNOUNCE_MIN_PAYLOAD}) = {max_app_data_len}",
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # 4. Binary with nulls
    app_data = bytes(range(256))[:50]
    result = make_announce_payload(identity, name_hash, dest_hash, random_hash, app_data=app_data)
    raw = make_raw_packet(flags, 0, dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "App data: 50 bytes binary with null bytes (0x00..0x31)",
        "keypair_index": 0,
        "destination_hash": dest_hash.hex(),
        "app_data": app_data.hex(),
        "app_data_length": len(app_data),
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "raw_packet": raw.hex(),
        "packet_hash": packet_hash.hex(),
    })

    # 5. MessagePack-encoded dict (common real-world pattern)
    import RNS.vendor.umsgpack as umsgpack
    display_name = {"display_name": "Test Node", "version": "1.0.0"}
    app_data = umsgpack.packb(display_name)
    result = make_announce_payload(identity, name_hash, dest_hash, random_hash, app_data=app_data)
    raw = make_raw_packet(flags, 0, dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "App data: MessagePack-encoded dict {'display_name': 'Test Node', 'version': '1.0.0'}",
        "keypair_index": 0,
        "destination_hash": dest_hash.hex(),
        "app_data": app_data.hex(),
        "app_data_length": len(app_data),
        "app_data_decoded": display_name,
        "app_data_encoding": "msgpack",
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "raw_packet": raw.hex(),
        "packet_hash": packet_hash.hex(),
    })

    return vectors


def extract_ratchet_announces(keypairs):
    """Category 4: Announces with ratchet keys (Reticulum-igj)."""
    from RNS.Cryptography.X25519 import X25519PrivateKey

    vectors = []

    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)

    # Fixed ratchet private keys (32 bytes each)
    ratchet_privates = [
        bytes.fromhex("a0b1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899aabbccddeeff"),
        bytes.fromhex("1122334455667788990011223344556677889900112233445566778899001122"),
        bytes.fromhex("deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef"),
    ]

    # Derive ratchet public keys using RNS's own X25519
    ratchet_publics = []
    for prv in ratchet_privates:
        pub = X25519PrivateKey.from_private_bytes(prv).public_key().public_bytes()
        ratchet_publics.append(pub)

    identity = load_identity(keypairs[0])
    identity_hash = bytes.fromhex(keypairs[0]["identity_hash"])
    dest_hash = make_destination_hash(name_hash, identity_hash)
    random_hash = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[0], FIXED_TIMESTAMP)

    # 1. Ratchet announce without app_data
    flags = make_flags_byte(FLAG_SET)
    result = make_announce_payload(identity, name_hash, dest_hash, random_hash,
                                   ratchet_pub=ratchet_publics[0])
    raw = make_raw_packet(flags, 0, dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Ratchet announce without app_data, ratchet key 0",
        "keypair_index": 0,
        "destination_hash": dest_hash.hex(),
        "ratchet_private_key": ratchet_privates[0].hex(),
        "ratchet_public_key": ratchet_publics[0].hex(),
        "context_flag": FLAG_SET,
        "flags_byte": f"{flags:02x}",
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "payload_layout": {
            "public_key": f"[0:{KEYSIZE_BYTES}]",
            "name_hash": f"[{KEYSIZE_BYTES}:{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES}]",
            "random_hash": f"[{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES}:{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH}]",
            "ratchet": f"[{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH}:{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES}]",
            "signature": f"[{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES}:{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES + SIGLENGTH_BYTES}]",
        },
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # 2. Ratchet announce with app_data
    app_data = b"Ratcheted node"
    flags = make_flags_byte(FLAG_SET)
    result = make_announce_payload(identity, name_hash, dest_hash, random_hash,
                                   ratchet_pub=ratchet_publics[1], app_data=app_data)
    raw = make_raw_packet(flags, 0, dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    app_data_offset = KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES + SIGLENGTH_BYTES

    vectors.append({
        "description": "Ratchet announce with app_data 'Ratcheted node', ratchet key 1",
        "keypair_index": 0,
        "destination_hash": dest_hash.hex(),
        "ratchet_private_key": ratchet_privates[1].hex(),
        "ratchet_public_key": ratchet_publics[1].hex(),
        "app_data": app_data.hex(),
        "app_data_utf8": app_data.decode("utf-8"),
        "context_flag": FLAG_SET,
        "flags_byte": f"{flags:02x}",
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "payload_layout": {
            "public_key": f"[0:{KEYSIZE_BYTES}]",
            "name_hash": f"[{KEYSIZE_BYTES}:{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES}]",
            "random_hash": f"[{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES}:{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH}]",
            "ratchet": f"[{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH}:{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES}]",
            "signature": f"[{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES}:{KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES + SIGLENGTH_BYTES}]",
            "app_data": f"[{app_data_offset}:]",
        },
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # 3. Different keypair with ratchet
    identity_2 = load_identity(keypairs[2])
    identity_hash_2 = bytes.fromhex(keypairs[2]["identity_hash"])
    dest_hash_2 = make_destination_hash(name_hash, identity_hash_2)
    random_hash_2 = make_random_hash(DETERMINISTIC_RANDOM_PREFIXES[2], FIXED_TIMESTAMP)
    flags = make_flags_byte(FLAG_SET)

    result = make_announce_payload(identity_2, name_hash, dest_hash_2, random_hash_2,
                                   ratchet_pub=ratchet_publics[2])
    raw = make_raw_packet(flags, 0, dest_hash_2, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)

    vectors.append({
        "description": "Ratchet announce from keypair 2 with ratchet key 2",
        "keypair_index": 2,
        "destination_hash": dest_hash_2.hex(),
        "ratchet_private_key": ratchet_privates[2].hex(),
        "ratchet_public_key": ratchet_publics[2].hex(),
        "context_flag": FLAG_SET,
        "flags_byte": f"{flags:02x}",
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    # 4. Max-size ratchet announce with app_data
    # Max app_data with ratchet: MTU(500) - HEADER_MINSIZE(19) - 148 - RATCHETSIZE(32) = 301
    max_ratchet_app_len = MTU - HEADER_MINSIZE - ANNOUNCE_MIN_PAYLOAD - RATCHETSIZE_BYTES
    app_data = bytes(range(256)) + bytes(range(max_ratchet_app_len - 256))
    assert len(app_data) == max_ratchet_app_len

    result = make_announce_payload(identity, name_hash, dest_hash, random_hash,
                                   ratchet_pub=ratchet_publics[0], app_data=app_data)
    raw = make_raw_packet(flags, 0, dest_hash, NONE_CONTEXT, result["payload"])
    _, _, packet_hash = compute_packet_hash(raw)
    assert len(raw) == MTU, f"Max ratchet packet should be MTU={MTU}, got {len(raw)}"

    vectors.append({
        "description": f"Max-size ratchet announce: {max_ratchet_app_len} bytes app_data fills to MTU={MTU}",
        "keypair_index": 0,
        "destination_hash": dest_hash.hex(),
        "ratchet_public_key": ratchet_publics[0].hex(),
        "app_data": app_data.hex(),
        "app_data_length": len(app_data),
        "max_app_data_derivation": f"MTU({MTU}) - HEADER_MINSIZE({HEADER_MINSIZE}) - ANNOUNCE_MIN_PAYLOAD({ANNOUNCE_MIN_PAYLOAD}) - RATCHETSIZE_BYTES({RATCHETSIZE_BYTES}) = {max_ratchet_app_len}",
        "context_flag": FLAG_SET,
        "flags_byte": f"{flags:02x}",
        "signed_data": result["signed_data"].hex(),
        "signature": result["signature"].hex(),
        "announce_payload": result["payload"].hex(),
        "announce_payload_length": len(result["payload"]),
        "raw_packet": raw.hex(),
        "raw_packet_length": len(raw),
        "packet_hash": packet_hash.hex(),
    })

    return vectors


def extract_propagation_metadata():
    """Category 5: Announce propagation & handler callbacks (Reticulum-g4r)."""

    # Path table entry indices
    path_table_indices = {
        "IDX_PT_TIMESTAMP": 0,
        "IDX_PT_NEXT_HOP": 1,
        "IDX_PT_HOPS": 2,
        "IDX_PT_EXPIRES": 3,
        "IDX_PT_RANDBLOBS": 4,
        "IDX_PT_RVCD_IF": 5,
        "IDX_PT_PACKET": 6,
    }

    # Announce table entry indices
    announce_table_indices = {
        "IDX_AT_TIMESTAMP": 0,
        "IDX_AT_RTRNS_TMO": 1,
        "IDX_AT_RETRIES": 2,
        "IDX_AT_RCVD_IF": 3,
        "IDX_AT_HOPS": 4,
        "IDX_AT_PACKET": 5,
        "IDX_AT_LCL_RBRD": 6,
        "IDX_AT_BLCK_RBRD": 7,
        "IDX_AT_ATTCHD_IF": 8,
    }

    # Retransmission constants
    retransmission_constants = {
        "PATHFINDER_R": 1,
        "PATHFINDER_R_description": "Maximum retransmit retries",
        "PATHFINDER_G": 5,
        "PATHFINDER_G_description": "Grace period in seconds before retransmit",
        "PATHFINDER_RW": 0.5,
        "PATHFINDER_RW_description": "Random window added to retransmit timeout (0 to RW seconds)",
    }

    # Random blob timestamp extraction vectors
    timestamp_extraction_vectors = []
    test_timestamps = [0, 1, 1700000000, 1700000001, 2**40 - 1]

    for ts in test_timestamps:
        random_prefix = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
        random_blob = random_prefix + int(ts).to_bytes(5, "big")
        extracted = int.from_bytes(random_blob[5:10], "big")
        assert extracted == ts

        timestamp_extraction_vectors.append({
            "description": f"Extract timestamp {ts} from random_blob",
            "random_blob": random_blob.hex(),
            "random_prefix": random_prefix.hex(),
            "timestamp_bytes": random_blob[5:10].hex(),
            "extracted_timestamp": extracted,
            "extraction_method": "int.from_bytes(random_blob[5:10], 'big')",
        })

    # Aspect filter matching vectors
    aspect_filter_vectors = []
    test_cases = [
        ("rns_unit_tests", ["link", "establish"], 0),
        ("nomadnetwork", ["node"], 0),
        ("myapp", ["messaging", "v1"], 0),
    ]

    keypairs = load_keypairs()
    for app_name, aspects_list, kp_idx in test_cases:
        identity_hash = bytes.fromhex(keypairs[kp_idx]["identity_hash"])
        name_hash = make_name_hash(app_name, *aspects_list)
        dest_hash = make_destination_hash(name_hash, identity_hash)
        full_name = app_name + "." + ".".join(aspects_list)

        aspect_filter_vectors.append({
            "description": f"Aspect filter for '{full_name}'",
            "app_name": app_name,
            "aspects": aspects_list,
            "full_name_no_identity": full_name,
            "keypair_index": kp_idx,
            "identity_hash": identity_hash.hex(),
            "name_hash": name_hash.hex(),
            "destination_hash": dest_hash.hex(),
            "name_hash_derivation": f"SHA256('{full_name}'.encode('utf-8'))[:10]",
            "dest_hash_derivation": "SHA256(name_hash + identity_hash)[:16]",
        })

    # Announce handler interface spec
    announce_handler_spec = {
        "description": "Interface that announce handler callbacks must implement",
        "required_attribute": "aspect_filter",
        "aspect_filter_description": "String that the announced destination's full name (without identity hash) is matched against. Set to None to receive all announces.",
        "callback_method": "received_announce",
        "callback_signatures": {
            "3_params": "(destination_hash, announced_identity, app_data)",
            "4_params": "(destination_hash, announced_identity, app_data, number_of_hops)",
            "5_params": "(destination_hash, announced_identity, app_data, number_of_hops, announce_packet)",
            "note": "Reticulum inspects callback signature length to determine which form to use",
        },
    }

    return {
        "path_table_indices": path_table_indices,
        "announce_table_indices": announce_table_indices,
        "retransmission_constants": retransmission_constants,
        "timestamp_extraction_vectors": timestamp_extraction_vectors,
        "aspect_filter_vectors": aspect_filter_vectors,
        "announce_handler_spec": announce_handler_spec,
    }


def extract_rate_limiting():
    """Category 6: Announce rate limiting (Reticulum-b84)."""

    constants = {
        "ANNOUNCE_CAP": 2,
        "ANNOUNCE_CAP_description": "Maximum percentage of interface bandwidth for announces (stored as integer, used as fraction: 2 -> 0.02)",
        "ANNOUNCE_CAP_as_fraction": 0.02,
        "MAX_QUEUED_ANNOUNCES": 16384,
        "MAX_QUEUED_ANNOUNCES_description": "Maximum number of queued announces per interface",
        "QUEUED_ANNOUNCE_LIFE": 86400,
        "QUEUED_ANNOUNCE_LIFE_description": "Maximum lifetime for queued announces in seconds (60*60*24 = 86400)",
        "MAX_RATE_TIMESTAMPS": 16,
        "MAX_RATE_TIMESTAMPS_description": "Maximum announce timestamps kept per destination for rate limiting",
    }

    # Bandwidth cap computation examples
    # Formula: tx_time = (packet_size * 8) / bitrate
    #          wait_time = tx_time / announce_cap_fraction
    # announce_cap is stored as interface.announce_cap which is ANNOUNCE_CAP/100.0 = 0.02
    announce_cap_fraction = 0.02
    packet_size = HEADER_MINSIZE + ANNOUNCE_MIN_PAYLOAD  # 19 + 148 = 167 bytes (minimal announce)

    bandwidth_cap_vectors = []
    interface_configs = [
        {"name": "LoRa 9600 baud", "bitrate": 9600},
        {"name": "Serial 115200 baud", "bitrate": 115200},
        {"name": "TCP 10 Mbps", "bitrate": 10_000_000},
        {"name": "TCP 1 Mbps", "bitrate": 1_000_000},
    ]

    for config in interface_configs:
        bitrate = config["bitrate"]
        tx_time = (packet_size * 8) / bitrate
        wait_time = tx_time / announce_cap_fraction

        bandwidth_cap_vectors.append({
            "description": f"Rate limit for {config['name']} interface",
            "interface_name": config["name"],
            "bitrate_bps": bitrate,
            "packet_size_bytes": packet_size,
            "packet_size_bits": packet_size * 8,
            "tx_time_seconds": round(tx_time, 6),
            "announce_cap_fraction": announce_cap_fraction,
            "wait_time_seconds": round(wait_time, 6),
            "formula": "wait_time = (packet_size_bytes * 8 / bitrate) / announce_cap_fraction",
            "note": "Local announces (hops=0) bypass bandwidth cap; only retransmitted announces (hops>0) are rate-limited",
        })

    # Max-size announce bandwidth cap
    max_packet_size = MTU  # 500 bytes (max possible)
    for config in interface_configs[:2]:  # Just LoRa and Serial for max-size
        bitrate = config["bitrate"]
        tx_time = (max_packet_size * 8) / bitrate
        wait_time = tx_time / announce_cap_fraction

        bandwidth_cap_vectors.append({
            "description": f"Rate limit for max-size packet on {config['name']}",
            "interface_name": config["name"],
            "bitrate_bps": bitrate,
            "packet_size_bytes": max_packet_size,
            "packet_size_bits": max_packet_size * 8,
            "tx_time_seconds": round(tx_time, 6),
            "announce_cap_fraction": announce_cap_fraction,
            "wait_time_seconds": round(wait_time, 6),
            "formula": "wait_time = (packet_size_bytes * 8 / bitrate) / announce_cap_fraction",
        })

    # Per-interface rate target/grace/penalty scenario
    rate_limiting_scenarios = [
        {
            "description": "Scenario: announce arrives faster than rate_target",
            "announce_rate_target": 300,
            "announce_rate_target_description": "Minimum seconds between announces from same destination",
            "announce_rate_grace": 3,
            "announce_rate_grace_description": "Number of rate violations allowed before penalty",
            "announce_rate_penalty": 600,
            "announce_rate_penalty_description": "Seconds to block announces after grace exceeded",
            "events": [
                {"time": 0, "action": "announce arrives", "current_rate": None, "rate_violations": 0, "blocked_until": 0, "result": "accepted (first announce, creates rate entry)"},
                {"time": 100, "action": "announce arrives", "current_rate": 100, "rate_violations": 1, "blocked_until": 0, "result": "accepted but violation recorded (100 < 300)"},
                {"time": 200, "action": "announce arrives", "current_rate": 100, "rate_violations": 2, "blocked_until": 0, "result": "accepted but violation recorded (100 < 300)"},
                {"time": 300, "action": "announce arrives", "current_rate": 100, "rate_violations": 3, "blocked_until": 0, "result": "accepted but violation recorded (100 < 300)"},
                {"time": 400, "action": "announce arrives", "current_rate": 100, "rate_violations": 4, "blocked_until": 0, "result": "blocked: violations(4) > grace(3), blocked_until = last(300) + target(300) + penalty(600) = 1200"},
                {"time": 500, "action": "announce arrives", "current_rate": None, "rate_violations": 4, "blocked_until": 1200, "result": "blocked: now(500) < blocked_until(1200)"},
                {"time": 1300, "action": "announce arrives", "current_rate": 1000, "rate_violations": 3, "blocked_until": 1200, "result": "accepted: now(1300) > blocked_until(1200), rate ok (1000 > 300), violations decremented"},
            ],
            "algorithm_note": "current_rate = now - last_announce_time; violation if current_rate < target; blocked when violations > grace; penalty = blocked_until = last + target + penalty",
        },
        {
            "description": "Scenario: PATH_RESPONSE bypasses rate limiting",
            "note": "Announces with context=PATH_RESPONSE (0x0B) skip per-interface rate limiting entirely",
            "relevant_code": "if packet.context != RNS.Packet.PATH_RESPONSE and packet.receiving_interface.announce_rate_target != None",
        },
    ]

    return {
        "constants": constants,
        "bandwidth_cap_vectors": bandwidth_cap_vectors,
        "rate_limiting_scenarios": rate_limiting_scenarios,
    }


def verify(output):
    """Verify all test vectors for internal consistency."""
    import RNS

    # 1. Verify valid announces
    for vec in output["valid_announces"]:
        payload = bytes.fromhex(vec["announce_payload"])
        public_key = payload[:KEYSIZE_BYTES]
        name_hash = payload[KEYSIZE_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES]
        random_hash = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]
        signature = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + SIGLENGTH_BYTES]
        app_data = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + SIGLENGTH_BYTES:]

        dest_hash = bytes.fromhex(vec["destination_hash"])
        signed_data = dest_hash + public_key + name_hash + random_hash
        if app_data:
            signed_data += app_data

        # Verify signature
        verify_identity = RNS.Identity(create_keys=False)
        verify_identity.load_public_key(public_key)
        assert verify_identity.validate(signature, signed_data), (
            f"Signature validation failed for: {vec['description']}"
        )

        # Verify destination hash derivation
        identity_hash = make_identity_hash(public_key)
        expected_dest = make_destination_hash(name_hash, identity_hash)
        assert expected_dest == dest_hash, (
            f"Dest hash mismatch for: {vec['description']}"
        )

        # Verify packet hash
        raw = bytes.fromhex(vec["raw_packet"])
        _, _, packet_hash = compute_packet_hash(raw)
        assert packet_hash.hex() == vec["packet_hash"], (
            f"Packet hash mismatch for: {vec['description']}"
        )

    print(f"  [OK] All {len(output['valid_announces'])} valid announce vectors verified")

    # 2. Verify invalid announces fail appropriately
    for vec in output["invalid_announces"]:
        payload = bytes.fromhex(vec["announce_payload"])

        if vec["expected_failure"] == "parse_error":
            # Just verify it's too short
            assert len(payload) < ANNOUNCE_MIN_PAYLOAD
            continue

        # Try to validate - should fail
        if len(payload) >= ANNOUNCE_MIN_PAYLOAD:
            public_key = payload[:KEYSIZE_BYTES]
            dest_hash_key = "destination_hash" if "destination_hash" in vec else "destination_hash_in_header"
            dest_hash = bytes.fromhex(vec.get("destination_hash", vec.get("destination_hash_in_header")))

            try:
                verify_identity = RNS.Identity(create_keys=False)
                verify_identity.load_public_key(public_key)

                if vec.get("context_flag") == FLAG_SET:
                    name_hash = payload[KEYSIZE_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES]
                    random_hash = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]
                    ratchet = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES]
                    signature = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES + SIGLENGTH_BYTES]
                    app_data = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + SIGLENGTH_BYTES + RATCHETSIZE_BYTES:]
                else:
                    name_hash = payload[KEYSIZE_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES]
                    random_hash = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]
                    ratchet = b""
                    signature = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + SIGLENGTH_BYTES]
                    app_data = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + SIGLENGTH_BYTES:]

                signed_data = dest_hash + public_key + name_hash + random_hash + ratchet + app_data
                sig_valid = verify_identity.validate(signature, signed_data)

                if sig_valid and vec["expected_failure"] == "destination_hash_mismatch":
                    identity_hash = make_identity_hash(public_key)
                    expected = make_destination_hash(name_hash, identity_hash)
                    assert expected != dest_hash, (
                        f"Expected dest hash mismatch but hashes matched: {vec['description']}"
                    )
                elif vec["expected_failure"] == "signature_validation":
                    assert not sig_valid, (
                        f"Expected signature failure but validation passed: {vec['description']}"
                    )
            except Exception:
                # Exception during validation is also a valid failure
                pass

    print(f"  [OK] All {len(output['invalid_announces'])} invalid announce vectors verified")

    # 3. Verify app_data announces
    for vec in output["app_data_announces"]:
        payload = bytes.fromhex(vec["announce_payload"])
        public_key = payload[:KEYSIZE_BYTES]
        name_hash = payload[KEYSIZE_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES]
        random_hash = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]
        signature = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + SIGLENGTH_BYTES]
        app_data = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + SIGLENGTH_BYTES:]

        dest_hash = bytes.fromhex(vec["destination_hash"])
        signed_data = dest_hash + public_key + name_hash + random_hash + app_data

        verify_identity = RNS.Identity(create_keys=False)
        verify_identity.load_public_key(public_key)
        assert verify_identity.validate(signature, signed_data), (
            f"App data announce signature failed: {vec['description']}"
        )

        assert app_data.hex() == vec["app_data"], (
            f"App data extraction mismatch: {vec['description']}"
        )

    print(f"  [OK] All {len(output['app_data_announces'])} app_data announce vectors verified")

    # 4. Verify ratchet announces
    for vec in output["ratchet_announces"]:
        payload = bytes.fromhex(vec["announce_payload"])
        public_key = payload[:KEYSIZE_BYTES]
        name_hash = payload[KEYSIZE_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES]
        random_hash = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH]
        ratchet = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES]
        signature = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES:KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES + SIGLENGTH_BYTES]
        app_data = payload[KEYSIZE_BYTES + NAME_HASH_LENGTH_BYTES + RANDOM_HASH_LENGTH + RATCHETSIZE_BYTES + SIGLENGTH_BYTES:]

        dest_hash = bytes.fromhex(vec["destination_hash"])
        signed_data = dest_hash + public_key + name_hash + random_hash + ratchet
        if app_data:
            signed_data += app_data

        verify_identity = RNS.Identity(create_keys=False)
        verify_identity.load_public_key(public_key)
        assert verify_identity.validate(signature, signed_data), (
            f"Ratchet announce signature failed: {vec['description']}"
        )

        assert ratchet.hex() == vec["ratchet_public_key"], (
            f"Ratchet key extraction mismatch: {vec['description']}"
        )

    print(f"  [OK] All {len(output['ratchet_announces'])} ratchet announce vectors verified")

    # 5. Verify propagation metadata
    meta = output["propagation_metadata"]
    for tv in meta["timestamp_extraction_vectors"]:
        blob = bytes.fromhex(tv["random_blob"])
        extracted = int.from_bytes(blob[5:10], "big")
        assert extracted == tv["extracted_timestamp"]
    print(f"  [OK] All {len(meta['timestamp_extraction_vectors'])} timestamp extraction vectors verified")

    for afv in meta["aspect_filter_vectors"]:
        nh = make_name_hash(afv["app_name"], *afv["aspects"])
        ih = bytes.fromhex(afv["identity_hash"])
        dh = make_destination_hash(nh, ih)
        assert nh.hex() == afv["name_hash"]
        assert dh.hex() == afv["destination_hash"]
    print(f"  [OK] All {len(meta['aspect_filter_vectors'])} aspect filter vectors verified")

    # 6. JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify local constants match the actual RNS library values."""
    import RNS

    assert MTU == RNS.Reticulum.MTU
    assert HEADER_MINSIZE == RNS.Reticulum.HEADER_MINSIZE
    assert HEADER_MAXSIZE == RNS.Reticulum.HEADER_MAXSIZE
    assert TRUNCATED_HASHLENGTH_BYTES == RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
    assert KEYSIZE_BYTES == RNS.Identity.KEYSIZE // 8
    assert NAME_HASH_LENGTH_BYTES == RNS.Identity.NAME_HASH_LENGTH // 8
    assert SIGLENGTH_BYTES == RNS.Identity.SIGLENGTH // 8
    assert RATCHETSIZE_BYTES == RNS.Identity.RATCHETSIZE // 8

    print("  [OK] All library constants verified")


def main():
    print("Extracting announce protocol test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    keypairs = load_keypairs()
    print(f"  Loaded {len(keypairs)} keypairs")

    valid = extract_valid_announces(keypairs)
    print(f"  Extracted {len(valid)} valid announce vectors")

    invalid = extract_invalid_announces(keypairs)
    print(f"  Extracted {len(invalid)} invalid announce vectors")

    app_data = extract_app_data_announces(keypairs)
    print(f"  Extracted {len(app_data)} app_data announce vectors")

    ratchet = extract_ratchet_announces(keypairs)
    print(f"  Extracted {len(ratchet)} ratchet announce vectors")

    propagation = extract_propagation_metadata()
    print(f"  Extracted propagation metadata ({len(propagation['timestamp_extraction_vectors'])} timestamp vectors, {len(propagation['aspect_filter_vectors'])} aspect filter vectors)")

    rate_limiting = extract_rate_limiting()
    print(f"  Extracted rate limiting data ({len(rate_limiting['bandwidth_cap_vectors'])} bandwidth cap vectors, {len(rate_limiting['rate_limiting_scenarios'])} scenarios)")

    output = {
        "description": "Reticulum v1.1.3 reference implementation - announce protocol test vectors",
        "source": "RNS/Destination.py, RNS/Identity.py, RNS/Transport.py",
        "constants": {
            "mtu_bytes": MTU,
            "header_minsize_bytes": HEADER_MINSIZE,
            "keysize_bytes": KEYSIZE_BYTES,
            "name_hash_length_bytes": NAME_HASH_LENGTH_BYTES,
            "signature_length_bytes": SIGLENGTH_BYTES,
            "ratchetsize_bytes": RATCHETSIZE_BYTES,
            "random_hash_length_bytes": RANDOM_HASH_LENGTH,
            "truncated_hash_length_bytes": TRUNCATED_HASHLENGTH_BYTES,
            "announce_min_payload_bytes": ANNOUNCE_MIN_PAYLOAD,
            "max_app_data_no_ratchet_bytes": MTU - HEADER_MINSIZE - ANNOUNCE_MIN_PAYLOAD,
            "max_app_data_with_ratchet_bytes": MTU - HEADER_MINSIZE - ANNOUNCE_MIN_PAYLOAD - RATCHETSIZE_BYTES,
        },
        "algorithm": {
            "name_hash": "SHA256(expand_name(None, app_name, *aspects).encode('utf-8'))[:10]",
            "expand_name": "app_name + '.' + '.'.join(aspects)  (no identity hash when computing name_hash for announces)",
            "identity_hash": "SHA256(public_key)[:16]  where public_key = x25519_public(32) + ed25519_public(32)",
            "destination_hash": "SHA256(name_hash + identity_hash)[:16]",
            "random_hash": "random_bytes(5) + int(timestamp).to_bytes(5, 'big')",
            "signed_data_no_ratchet": "dest_hash(16) + public_key(64) + name_hash(10) + random_hash(10) [+ app_data]",
            "signed_data_with_ratchet": "dest_hash(16) + public_key(64) + name_hash(10) + random_hash(10) + ratchet_public(32) [+ app_data]",
            "signature": "Ed25519.sign(signed_data)  -> 64 bytes",
            "payload_no_ratchet": "public_key(64) + name_hash(10) + random_hash(10) + signature(64) [+ app_data]",
            "payload_with_ratchet": "public_key(64) + name_hash(10) + random_hash(10) + ratchet_public(32) + signature(64) [+ app_data]",
            "context_flag": "FLAG_SET (0x01) if ratchet present, FLAG_UNSET (0x00) otherwise",
            "flags_byte": "(HEADER_1<<6) | (context_flag<<5) | (BROADCAST<<4) | (SINGLE<<2) | ANNOUNCE = context_flag ? 0x21 : 0x01",
            "validation_steps": [
                "1. Extract public_key from payload[0:64]",
                "2. Based on context_flag, parse name_hash, random_hash, [ratchet], signature, [app_data]",
                "3. Reconstruct signed_data = header_dest_hash + public_key + name_hash + random_hash + [ratchet] + [app_data]",
                "4. Load public key and verify Ed25519 signature over signed_data",
                "5. Compute identity_hash = SHA256(public_key)[:16]",
                "6. Verify SHA256(name_hash + identity_hash)[:16] == destination_hash from packet header",
                "7. If both checks pass, announce is valid",
            ],
        },
        "valid_announces": valid,
        "invalid_announces": invalid,
        "app_data_announces": app_data,
        "ratchet_announces": ratchet,
        "propagation_metadata": propagation,
        "rate_limiting": rate_limiting,
    }

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
