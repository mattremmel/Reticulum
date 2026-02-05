#!/usr/bin/env python3
"""
Extract packet header test vectors from the Reticulum reference implementation
into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Packet objects) to avoid Transport init.

Usage:
    python3 test_vectors/extract_packets.py

Output:
    test_vectors/packet_headers.json
"""

import hashlib
import json
import math
import os
import struct
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packet_headers.json")

# Constants from Packet.py and Reticulum.py (reproduced to avoid Transport init)
HEADER_1 = 0x00
HEADER_2 = 0x01

DATA = 0x00
ANNOUNCE = 0x01
LINKREQUEST = 0x02
PROOF = 0x03

NONE_CONTEXT = 0x00

BROADCAST = 0x00
TRANSPORT = 0x01

# Destination types
SINGLE = 0x00
GROUP = 0x01
PLAIN = 0x02
LINK = 0x03

FLAG_SET = 0x01
FLAG_UNSET = 0x00

TRUNCATED_HASHLENGTH_BYTES = 16

# Size constants (verified against library in main())
MTU = 500
HEADER_MINSIZE = 2 + 1 + TRUNCATED_HASHLENGTH_BYTES * 1   # 19
HEADER_MAXSIZE = 2 + 1 + TRUNCATED_HASHLENGTH_BYTES * 2   # 35
IFAC_MIN_SIZE = 1
MDU = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE                # 464
TOKEN_OVERHEAD = 48
AES128_BLOCKSIZE = 16
KEYSIZE_BITS = 512
ENCRYPTED_MDU = math.floor((MDU - TOKEN_OVERHEAD - KEYSIZE_BITS // 16) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1  # 383
PLAIN_MDU = MDU                                            # 464

# Context type constants from Packet.py
CONTEXT_TYPES = {
    "NONE":           0x00,
    "RESOURCE":       0x01,
    "RESOURCE_ADV":   0x02,
    "RESOURCE_REQ":   0x03,
    "RESOURCE_HMU":   0x04,
    "RESOURCE_PRF":   0x05,
    "RESOURCE_ICL":   0x06,
    "RESOURCE_RCL":   0x07,
    "CACHE_REQUEST":  0x08,
    "REQUEST":        0x09,
    "RESPONSE":       0x0A,
    "PATH_RESPONSE":  0x0B,
    "COMMAND":        0x0C,
    "COMMAND_STATUS": 0x0D,
    "CHANNEL":        0x0E,
    "KEEPALIVE":      0xFA,
    "LINKIDENTIFY":   0xFB,
    "LINKCLOSE":      0xFC,
    "LINKPROOF":      0xFD,
    "LRRTT":          0xFE,
    "LRPROOF":        0xFF,
}

# Name mappings for human-readable descriptions
HEADER_TYPE_NAMES = {0: "HEADER_1", 1: "HEADER_2"}
TRANSPORT_TYPE_NAMES = {0: "BROADCAST", 1: "TRANSPORT"}
DEST_TYPE_NAMES = {0: "SINGLE", 1: "GROUP", 2: "PLAIN", 3: "LINK"}
PACKET_TYPE_NAMES = {0: "DATA", 1: "ANNOUNCE", 2: "LINKREQUEST", 3: "PROOF"}


def pack_flags(header_type, context_flag, transport_type, dest_type, packet_type):
    """Pack header fields into a single flag byte, matching Packet.get_packed_flags()."""
    return (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | packet_type


def unpack_flags(flags_byte):
    """Unpack a flag byte into its component fields, matching Packet.unpack()."""
    return {
        "header_type": (flags_byte & 0b01000000) >> 6,
        "context_flag": (flags_byte & 0b00100000) >> 5,
        "transport_type": (flags_byte & 0b00010000) >> 4,
        "destination_type": (flags_byte & 0b00001100) >> 2,
        "packet_type": (flags_byte & 0b00000011),
    }


def extract_flag_packing_vectors():
    """Enumerate meaningful flag byte combinations."""
    vectors = []

    combos = [
        # (description, header_type, context_flag, transport_type, dest_type, packet_type)
        ("HEADER_1 | no_context | BROADCAST | SINGLE | DATA",
         HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA),
        ("HEADER_1 | no_context | BROADCAST | SINGLE | ANNOUNCE",
         HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, ANNOUNCE),
        ("HEADER_1 | no_context | BROADCAST | SINGLE | LINKREQUEST",
         HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST),
        ("HEADER_1 | no_context | BROADCAST | SINGLE | PROOF",
         HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, PROOF),
        ("HEADER_1 | no_context | BROADCAST | GROUP | DATA",
         HEADER_1, FLAG_UNSET, BROADCAST, GROUP, DATA),
        ("HEADER_1 | no_context | BROADCAST | PLAIN | DATA",
         HEADER_1, FLAG_UNSET, BROADCAST, PLAIN, DATA),
        ("HEADER_1 | no_context | BROADCAST | LINK | DATA",
         HEADER_1, FLAG_UNSET, BROADCAST, LINK, DATA),
        ("HEADER_1 | context_set | BROADCAST | SINGLE | DATA",
         HEADER_1, FLAG_SET, BROADCAST, SINGLE, DATA),
        ("HEADER_1 | no_context | TRANSPORT | SINGLE | DATA",
         HEADER_1, FLAG_UNSET, TRANSPORT, SINGLE, DATA),
        ("HEADER_2 | no_context | TRANSPORT | SINGLE | DATA",
         HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, DATA),
        ("HEADER_2 | no_context | TRANSPORT | SINGLE | ANNOUNCE",
         HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, ANNOUNCE),
        ("HEADER_2 | context_set | TRANSPORT | LINK | PROOF",
         HEADER_2, FLAG_SET, TRANSPORT, LINK, PROOF),
    ]

    for desc, ht, cf, tt, dt, pt in combos:
        flags = pack_flags(ht, cf, tt, dt, pt)
        unpacked = unpack_flags(flags)
        # Verify round-trip
        assert unpacked["header_type"] == ht
        assert unpacked["context_flag"] == cf
        assert unpacked["transport_type"] == tt
        assert unpacked["destination_type"] == dt
        assert unpacked["packet_type"] == pt

        vectors.append({
            "description": desc,
            "header_type": ht,
            "context_flag": cf,
            "transport_type": tt,
            "destination_type": dt,
            "packet_type": pt,
            "flags_byte": f"{flags:02x}",
            "flags_binary": f"{flags:08b}",
        })

    return vectors


def extract_flag_unpacking_vectors():
    """Given specific flag bytes, decompose to fields."""
    vectors = []

    test_bytes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x08, 0x0c, 0x10, 0x20, 0x40, 0x41, 0x51, 0x7f]

    for b in test_bytes:
        unpacked = unpack_flags(b)
        vectors.append({
            "flags_byte": f"{b:02x}",
            "flags_binary": f"{b:08b}",
            **unpacked,
        })

    return vectors


def extract_exhaustive_flag_vectors():
    """Enumerate all 128 valid flag byte combinations (bit 7 always 0)."""
    vectors = []

    for flags_byte in range(128):
        unpacked = unpack_flags(flags_byte)
        ht = unpacked["header_type"]
        cf = unpacked["context_flag"]
        tt = unpacked["transport_type"]
        dt = unpacked["destination_type"]
        pt = unpacked["packet_type"]

        desc = (
            f"{HEADER_TYPE_NAMES[ht]} | "
            f"{'context_set' if cf else 'no_context'} | "
            f"{TRANSPORT_TYPE_NAMES[tt]} | "
            f"{DEST_TYPE_NAMES[dt]} | "
            f"{PACKET_TYPE_NAMES[pt]}"
        )

        # Verify round-trip
        repacked = pack_flags(ht, cf, tt, dt, pt)
        assert repacked == flags_byte, f"Round-trip failed for 0x{flags_byte:02x}"

        vectors.append({
            "description": desc,
            "header_type": ht,
            "context_flag": cf,
            "transport_type": tt,
            "destination_type": dt,
            "packet_type": pt,
            "flags_byte": f"{flags_byte:02x}",
            "flags_binary": f"{flags_byte:08b}",
        })

    return vectors


def build_header_1(flags_byte, hops, dest_hash, context_byte):
    """Build a HEADER_1 packet header manually."""
    header = struct.pack("!B", flags_byte)
    header += struct.pack("!B", hops)
    header += dest_hash
    header += bytes([context_byte])
    return header


def build_header_2(flags_byte, hops, transport_id, dest_hash, context_byte):
    """Build a HEADER_2 packet header manually."""
    header = struct.pack("!B", flags_byte)
    header += struct.pack("!B", hops)
    header += transport_id
    header += dest_hash
    header += bytes([context_byte])
    return header


def compute_packet_hash(raw_packet):
    """
    Compute packet hash matching Packet.get_hashable_part() + Identity.full_hash().

    hashable_part = (raw[0] & 0x0F) as single byte, then raw[2:] for HEADER_1
    For HEADER_2: (raw[0] & 0x0F) as byte, then raw[TRUNCATED_HASHLENGTH_BYTES + 2:]
    """
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


def make_deterministic_payload(length):
    """Generate a deterministic payload of the given length using repeating byte pattern."""
    if length == 0:
        return b""
    full_cycles = length // 256
    remainder = length % 256
    return bytes(range(256)) * full_cycles + bytes(range(remainder))


def make_header_vector(description, header_type_name, flags_byte, hops, dest_hash,
                       context, payload, transport_id=None):
    """Build a complete header vector dict."""
    if transport_id is not None:
        header = build_header_2(flags_byte, hops, transport_id, dest_hash, context)
    else:
        header = build_header_1(flags_byte, hops, dest_hash, context)

    raw = header + payload
    hashable, full_hash, trunc_hash = compute_packet_hash(raw)

    vec = {
        "description": description,
        "header_type": header_type_name,
        "flags_byte": f"{flags_byte:02x}",
        "hops": hops,
    }
    if transport_id is not None:
        vec["transport_id"] = transport_id.hex()
    vec["destination_hash"] = dest_hash.hex()
    vec["context"] = f"{context:02x}"
    vec["header"] = header.hex()
    vec["header_length"] = len(header)
    vec["payload"] = payload.hex()
    vec["raw_packet"] = raw.hex()
    vec["hashable_part"] = hashable.hex()
    if transport_id is not None:
        vec["hashable_part_note"] = "flags_masked(1 byte, raw[0] & 0x0F) + raw[TRUNCATED_HASHLENGTH_BYTES + 2:] (skips transport_id)"
    else:
        vec["hashable_part_note"] = "flags_masked(1 byte, raw[0] & 0x0F) + raw[2:]"
    vec["packet_hash_full"] = full_hash.hex()
    vec["packet_hash"] = trunc_hash.hex()
    vec["expected_header_length"] = 35 if transport_id is not None else 19

    return vec


def extract_header_layout_vectors():
    """Build example packet headers and compute their hashes."""
    vectors = []

    # Example destination hash and payload
    dest_hash = bytes.fromhex("fb48da0e82e6e01ba0c014513f74540d")  # keypair 0's dest hash
    transport_id = bytes.fromhex("650b5d76b6bec0390d1f8cfca5bd33f9")  # keypair 0's identity hash
    payload = b"Hello, Reticulum!"

    # HEADER_1: DATA packet to SINGLE destination
    flags_h1 = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)
    hops = 0
    context = NONE_CONTEXT
    header_h1 = build_header_1(flags_h1, hops, dest_hash, context)
    raw_h1 = header_h1 + payload
    hashable_h1, full_hash_h1, trunc_hash_h1 = compute_packet_hash(raw_h1)

    vectors.append({
        "description": "HEADER_1: DATA to SINGLE destination via BROADCAST",
        "header_type": "HEADER_1",
        "flags_byte": f"{flags_h1:02x}",
        "hops": hops,
        "destination_hash": dest_hash.hex(),
        "context": f"{context:02x}",
        "header": header_h1.hex(),
        "header_length": len(header_h1),
        "payload": payload.hex(),
        "raw_packet": raw_h1.hex(),
        "hashable_part": hashable_h1.hex(),
        "hashable_part_note": "flags_masked(1 byte, raw[0] & 0x0F) + raw[2:]",
        "packet_hash_full": full_hash_h1.hex(),
        "packet_hash": trunc_hash_h1.hex(),
        "expected_header_length": 19,
    })

    # HEADER_1: ANNOUNCE packet
    flags_ann = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, ANNOUNCE)
    header_ann = build_header_1(flags_ann, 0, dest_hash, NONE_CONTEXT)
    raw_ann = header_ann + payload
    hashable_ann, full_hash_ann, trunc_hash_ann = compute_packet_hash(raw_ann)

    vectors.append({
        "description": "HEADER_1: ANNOUNCE to SINGLE destination via BROADCAST",
        "header_type": "HEADER_1",
        "flags_byte": f"{flags_ann:02x}",
        "hops": 0,
        "destination_hash": dest_hash.hex(),
        "context": f"{NONE_CONTEXT:02x}",
        "header": header_ann.hex(),
        "header_length": len(header_ann),
        "payload": payload.hex(),
        "raw_packet": raw_ann.hex(),
        "hashable_part": hashable_ann.hex(),
        "hashable_part_note": "flags_masked(1 byte, raw[0] & 0x0F) + raw[2:]",
        "packet_hash_full": full_hash_ann.hex(),
        "packet_hash": trunc_hash_ann.hex(),
        "expected_header_length": 19,
    })

    # HEADER_1: LINKREQUEST packet
    flags_lr = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST)
    header_lr = build_header_1(flags_lr, 0, dest_hash, NONE_CONTEXT)
    raw_lr = header_lr + payload
    hashable_lr, full_hash_lr, trunc_hash_lr = compute_packet_hash(raw_lr)

    vectors.append({
        "description": "HEADER_1: LINKREQUEST to SINGLE destination via BROADCAST",
        "header_type": "HEADER_1",
        "flags_byte": f"{flags_lr:02x}",
        "hops": 0,
        "destination_hash": dest_hash.hex(),
        "context": f"{NONE_CONTEXT:02x}",
        "header": header_lr.hex(),
        "header_length": len(header_lr),
        "payload": payload.hex(),
        "raw_packet": raw_lr.hex(),
        "hashable_part": hashable_lr.hex(),
        "hashable_part_note": "flags_masked(1 byte, raw[0] & 0x0F) + raw[2:]",
        "packet_hash_full": full_hash_lr.hex(),
        "packet_hash": trunc_hash_lr.hex(),
        "expected_header_length": 19,
    })

    # HEADER_2: DATA in TRANSPORT
    flags_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, DATA)
    header_h2 = build_header_2(flags_h2, 3, transport_id, dest_hash, NONE_CONTEXT)
    raw_h2 = header_h2 + payload
    hashable_h2, full_hash_h2, trunc_hash_h2 = compute_packet_hash(raw_h2)

    vectors.append({
        "description": "HEADER_2: DATA to SINGLE destination via TRANSPORT (3 hops)",
        "header_type": "HEADER_2",
        "flags_byte": f"{flags_h2:02x}",
        "hops": 3,
        "transport_id": transport_id.hex(),
        "destination_hash": dest_hash.hex(),
        "context": f"{NONE_CONTEXT:02x}",
        "header": header_h2.hex(),
        "header_length": len(header_h2),
        "payload": payload.hex(),
        "raw_packet": raw_h2.hex(),
        "hashable_part": hashable_h2.hex(),
        "hashable_part_note": "flags_masked(1 byte, raw[0] & 0x0F) + raw[TRUNCATED_HASHLENGTH_BYTES + 2:] (skips transport_id)",
        "packet_hash_full": full_hash_h2.hex(),
        "packet_hash": trunc_hash_h2.hex(),
        "expected_header_length": 35,
    })

    # HEADER_2: ANNOUNCE in TRANSPORT
    flags_h2a = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, ANNOUNCE)
    header_h2a = build_header_2(flags_h2a, 1, transport_id, dest_hash, NONE_CONTEXT)
    raw_h2a = header_h2a + payload
    hashable_h2a, full_hash_h2a, trunc_hash_h2a = compute_packet_hash(raw_h2a)

    vectors.append({
        "description": "HEADER_2: ANNOUNCE to SINGLE destination via TRANSPORT (1 hop)",
        "header_type": "HEADER_2",
        "flags_byte": f"{flags_h2a:02x}",
        "hops": 1,
        "transport_id": transport_id.hex(),
        "destination_hash": dest_hash.hex(),
        "context": f"{NONE_CONTEXT:02x}",
        "header": header_h2a.hex(),
        "header_length": len(header_h2a),
        "payload": payload.hex(),
        "raw_packet": raw_h2a.hex(),
        "hashable_part": hashable_h2a.hex(),
        "hashable_part_note": "flags_masked(1 byte, raw[0] & 0x0F) + raw[TRUNCATED_HASHLENGTH_BYTES + 2:] (skips transport_id)",
        "packet_hash_full": full_hash_h2a.hex(),
        "packet_hash": trunc_hash_h2a.hex(),
        "expected_header_length": 35,
    })

    return vectors


def extract_extended_header_vectors():
    """Build additional header vectors covering edge cases."""
    vectors = []

    dest_hash = bytes.fromhex("fb48da0e82e6e01ba0c014513f74540d")
    transport_id = bytes.fromhex("650b5d76b6bec0390d1f8cfca5bd33f9")
    payload = b"Hello, Reticulum!"

    # --- HEADER_1 additions ---

    # 1. PROOF/SINGLE/BROADCAST, hops=0
    vectors.append(make_header_vector(
        "HEADER_1: PROOF to SINGLE destination via BROADCAST",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, PROOF),
        0, dest_hash, NONE_CONTEXT, payload))

    # 2. DATA/GROUP/BROADCAST, hops=0
    vectors.append(make_header_vector(
        "HEADER_1: DATA to GROUP destination via BROADCAST",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, GROUP, DATA),
        0, dest_hash, NONE_CONTEXT, payload))

    # 3. DATA/PLAIN/BROADCAST, hops=0
    vectors.append(make_header_vector(
        "HEADER_1: DATA to PLAIN destination via BROADCAST",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, PLAIN, DATA),
        0, dest_hash, NONE_CONTEXT, payload))

    # 4. DATA/LINK/BROADCAST, hops=0
    vectors.append(make_header_vector(
        "HEADER_1: DATA to LINK destination via BROADCAST",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, DATA),
        0, dest_hash, NONE_CONTEXT, payload))

    # 5. DATA/SINGLE with context_flag=1, context=0x00
    vectors.append(make_header_vector(
        "HEADER_1: DATA to SINGLE with context_flag set, context=NONE",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_SET, BROADCAST, SINGLE, DATA),
        0, dest_hash, NONE_CONTEXT, payload))

    # 6. DATA/SINGLE with context=0x0E (CHANNEL), context_flag=1
    vectors.append(make_header_vector(
        "HEADER_1: DATA to SINGLE with context=CHANNEL",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_SET, BROADCAST, SINGLE, DATA),
        0, dest_hash, CONTEXT_TYPES["CHANNEL"], payload))

    # 7. DATA/SINGLE, hops=1
    vectors.append(make_header_vector(
        "HEADER_1: DATA to SINGLE destination, hops=1",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA),
        1, dest_hash, NONE_CONTEXT, payload))

    # 8. DATA/SINGLE, hops=127
    vectors.append(make_header_vector(
        "HEADER_1: DATA to SINGLE destination, hops=127",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA),
        127, dest_hash, NONE_CONTEXT, payload))

    # 9. DATA/SINGLE, hops=255
    vectors.append(make_header_vector(
        "HEADER_1: DATA to SINGLE destination, hops=255",
        "HEADER_1",
        pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA),
        255, dest_hash, NONE_CONTEXT, payload))

    # --- HEADER_2 additions ---

    # 10. LINKREQUEST/SINGLE/TRANSPORT, hops=2
    vectors.append(make_header_vector(
        "HEADER_2: LINKREQUEST to SINGLE destination via TRANSPORT (2 hops)",
        "HEADER_2",
        pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, LINKREQUEST),
        2, dest_hash, NONE_CONTEXT, payload, transport_id=transport_id))

    # 11. PROOF/SINGLE/TRANSPORT, hops=0
    vectors.append(make_header_vector(
        "HEADER_2: PROOF to SINGLE destination via TRANSPORT",
        "HEADER_2",
        pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, PROOF),
        0, dest_hash, NONE_CONTEXT, payload, transport_id=transport_id))

    # 12. DATA/GROUP/TRANSPORT, hops=1
    vectors.append(make_header_vector(
        "HEADER_2: DATA to GROUP destination via TRANSPORT (1 hop)",
        "HEADER_2",
        pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, GROUP, DATA),
        1, dest_hash, NONE_CONTEXT, payload, transport_id=transport_id))

    # 13. DATA/SINGLE/TRANSPORT, context_flag=1, context=RESOURCE
    vectors.append(make_header_vector(
        "HEADER_2: DATA to SINGLE via TRANSPORT with context=RESOURCE",
        "HEADER_2",
        pack_flags(HEADER_2, FLAG_SET, TRANSPORT, SINGLE, DATA),
        0, dest_hash, CONTEXT_TYPES["RESOURCE"], payload, transport_id=transport_id))

    return vectors


def extract_hash_vectors():
    """Extract packet hash test vectors including equivalence pairs and edge cases."""
    dest_hash = bytes.fromhex("fb48da0e82e6e01ba0c014513f74540d")
    transport_id = bytes.fromhex("650b5d76b6bec0390d1f8cfca5bd33f9")
    payload = b"Hello, Reticulum!"

    hash_properties = {
        "description": "Packet hash is computed from a 'hashable part' that strips routing-specific fields",
        "algorithm": "SHA-256(hashable_part)[:16]",
        "mask": "0x0F",
        "mask_effect": "Strips header_type (bit 6), context_flag (bit 5), transport_type (bit 4) from flags byte",
        "fields_stripped": ["header_type", "context_flag", "transport_type", "hops", "transport_id"],
        "fields_kept": ["destination_type", "packet_type", "destination_hash", "context", "payload"],
        "hashable_part_header_1": "bytes([raw[0] & 0x0F]) + raw[2:]  (skips flags high bits and hops)",
        "hashable_part_header_2": "bytes([raw[0] & 0x0F]) + raw[TRUNCATED_HASHLENGTH_BYTES + 2:]  (also skips transport_id)",
    }

    # Equivalence pairs: HEADER_1 + HEADER_2 packets with same logical content
    # should produce identical packet hashes
    equivalence_pairs = []

    # Pair 1: DATA/SINGLE
    flags_h1 = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)
    flags_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, DATA)
    h1_raw = build_header_1(flags_h1, 0, dest_hash, NONE_CONTEXT) + payload
    h2_raw = build_header_2(flags_h2, 5, transport_id, dest_hash, NONE_CONTEXT) + payload
    h1_hashable, _, h1_trunc = compute_packet_hash(h1_raw)
    h2_hashable, _, h2_trunc = compute_packet_hash(h2_raw)
    assert h1_trunc == h2_trunc, "DATA/SINGLE equivalence failed"

    equivalence_pairs.append({
        "description": "DATA/SINGLE: HEADER_1 (BROADCAST, 0 hops) == HEADER_2 (TRANSPORT, 5 hops)",
        "header_1": {
            "flags_byte": f"{flags_h1:02x}",
            "hops": 0,
            "raw_packet": h1_raw.hex(),
            "hashable_part": h1_hashable.hex(),
            "packet_hash": h1_trunc.hex(),
        },
        "header_2": {
            "flags_byte": f"{flags_h2:02x}",
            "hops": 5,
            "transport_id": transport_id.hex(),
            "raw_packet": h2_raw.hex(),
            "hashable_part": h2_hashable.hex(),
            "packet_hash": h2_trunc.hex(),
        },
    })

    # Pair 2: ANNOUNCE/SINGLE
    flags_h1_ann = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, ANNOUNCE)
    flags_h2_ann = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, ANNOUNCE)
    h1_ann_raw = build_header_1(flags_h1_ann, 0, dest_hash, NONE_CONTEXT) + payload
    h2_ann_raw = build_header_2(flags_h2_ann, 3, transport_id, dest_hash, NONE_CONTEXT) + payload
    h1_ann_hashable, _, h1_ann_trunc = compute_packet_hash(h1_ann_raw)
    h2_ann_hashable, _, h2_ann_trunc = compute_packet_hash(h2_ann_raw)
    assert h1_ann_trunc == h2_ann_trunc, "ANNOUNCE/SINGLE equivalence failed"

    equivalence_pairs.append({
        "description": "ANNOUNCE/SINGLE: HEADER_1 (BROADCAST, 0 hops) == HEADER_2 (TRANSPORT, 3 hops)",
        "header_1": {
            "flags_byte": f"{flags_h1_ann:02x}",
            "hops": 0,
            "raw_packet": h1_ann_raw.hex(),
            "hashable_part": h1_ann_hashable.hex(),
            "packet_hash": h1_ann_trunc.hex(),
        },
        "header_2": {
            "flags_byte": f"{flags_h2_ann:02x}",
            "hops": 3,
            "transport_id": transport_id.hex(),
            "raw_packet": h2_ann_raw.hex(),
            "hashable_part": h2_ann_hashable.hex(),
            "packet_hash": h2_ann_trunc.hex(),
        },
    })

    # Pair 3: PROOF/LINK
    flags_h1_proof = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, PROOF)
    flags_h2_proof = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, LINK, PROOF)
    h1_proof_raw = build_header_1(flags_h1_proof, 0, dest_hash, NONE_CONTEXT) + payload
    h2_proof_raw = build_header_2(flags_h2_proof, 2, transport_id, dest_hash, NONE_CONTEXT) + payload
    h1_proof_hashable, _, h1_proof_trunc = compute_packet_hash(h1_proof_raw)
    h2_proof_hashable, _, h2_proof_trunc = compute_packet_hash(h2_proof_raw)
    assert h1_proof_trunc == h2_proof_trunc, "PROOF/LINK equivalence failed"

    equivalence_pairs.append({
        "description": "PROOF/LINK: HEADER_1 (BROADCAST, 0 hops) == HEADER_2 (TRANSPORT, 2 hops)",
        "header_1": {
            "flags_byte": f"{flags_h1_proof:02x}",
            "hops": 0,
            "raw_packet": h1_proof_raw.hex(),
            "hashable_part": h1_proof_hashable.hex(),
            "packet_hash": h1_proof_trunc.hex(),
        },
        "header_2": {
            "flags_byte": f"{flags_h2_proof:02x}",
            "hops": 2,
            "transport_id": transport_id.hex(),
            "raw_packet": h2_proof_raw.hex(),
            "hashable_part": h2_proof_hashable.hex(),
            "packet_hash": h2_proof_trunc.hex(),
        },
    })

    # Edge cases
    edge_cases = []

    # 1. Empty payload (header only)
    flags_empty = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)
    raw_empty = build_header_1(flags_empty, 0, dest_hash, NONE_CONTEXT)
    hashable_empty, full_empty, trunc_empty = compute_packet_hash(raw_empty)
    edge_cases.append({
        "description": "Empty payload - header only, no data bytes",
        "flags_byte": f"{flags_empty:02x}",
        "hops": 0,
        "destination_hash": dest_hash.hex(),
        "context": f"{NONE_CONTEXT:02x}",
        "payload": "",
        "raw_packet": raw_empty.hex(),
        "hashable_part": hashable_empty.hex(),
        "packet_hash": trunc_empty.hex(),
    })

    # 2. Single-byte payload
    flags_1b = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)
    raw_1b = build_header_1(flags_1b, 0, dest_hash, NONE_CONTEXT) + b"\x42"
    hashable_1b, full_1b, trunc_1b = compute_packet_hash(raw_1b)
    edge_cases.append({
        "description": "Single-byte payload (0x42)",
        "flags_byte": f"{flags_1b:02x}",
        "hops": 0,
        "destination_hash": dest_hash.hex(),
        "context": f"{NONE_CONTEXT:02x}",
        "payload": "42",
        "raw_packet": raw_1b.hex(),
        "hashable_part": hashable_1b.hex(),
        "packet_hash": trunc_1b.hex(),
    })

    # 3. Same flags+dest+payload but different context -> different hash
    flags_ctx_a = pack_flags(HEADER_1, FLAG_SET, BROADCAST, SINGLE, DATA)
    ctx_a = CONTEXT_TYPES["NONE"]       # 0x00
    ctx_b = CONTEXT_TYPES["CHANNEL"]    # 0x0E
    raw_ctx_a = build_header_1(flags_ctx_a, 0, dest_hash, ctx_a) + payload
    raw_ctx_b = build_header_1(flags_ctx_a, 0, dest_hash, ctx_b) + payload
    _, _, trunc_ctx_a = compute_packet_hash(raw_ctx_a)
    _, _, trunc_ctx_b = compute_packet_hash(raw_ctx_b)
    assert trunc_ctx_a != trunc_ctx_b, "Different context should produce different hash"
    hashable_ctx_a, _, _ = compute_packet_hash(raw_ctx_a)
    hashable_ctx_b, _, _ = compute_packet_hash(raw_ctx_b)

    edge_cases.append({
        "description": "Same flags+dest+payload, different context (NONE vs CHANNEL) -> different hash",
        "packet_a": {
            "context": f"{ctx_a:02x}",
            "context_name": "NONE",
            "raw_packet": raw_ctx_a.hex(),
            "hashable_part": hashable_ctx_a.hex(),
            "packet_hash": trunc_ctx_a.hex(),
        },
        "packet_b": {
            "context": f"{ctx_b:02x}",
            "context_name": "CHANNEL",
            "raw_packet": raw_ctx_b.hex(),
            "hashable_part": hashable_ctx_b.hex(),
            "packet_hash": trunc_ctx_b.hex(),
        },
        "hashes_equal": False,
    })

    # 4. Same flags+dest+payload but different hops -> same hash (hops excluded)
    flags_hops = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)
    raw_hops_0 = build_header_1(flags_hops, 0, dest_hash, NONE_CONTEXT) + payload
    raw_hops_42 = build_header_1(flags_hops, 42, dest_hash, NONE_CONTEXT) + payload
    hashable_hops_0, _, trunc_hops_0 = compute_packet_hash(raw_hops_0)
    hashable_hops_42, _, trunc_hops_42 = compute_packet_hash(raw_hops_42)
    assert trunc_hops_0 == trunc_hops_42, "Different hops should produce same hash"

    edge_cases.append({
        "description": "Same flags+dest+payload, different hops (0 vs 42) -> same hash (hops excluded from hash)",
        "packet_a": {
            "hops": 0,
            "raw_packet": raw_hops_0.hex(),
            "hashable_part": hashable_hops_0.hex(),
            "packet_hash": trunc_hops_0.hex(),
        },
        "packet_b": {
            "hops": 42,
            "raw_packet": raw_hops_42.hex(),
            "hashable_part": hashable_hops_42.hex(),
            "packet_hash": trunc_hops_42.hex(),
        },
        "hashes_equal": True,
    })

    return {
        "hash_properties": hash_properties,
        "equivalence_pairs": equivalence_pairs,
        "edge_cases": edge_cases,
    }


def extract_size_limit_vectors():
    """Extract size limit test vectors with boundary packets."""
    dest_hash = bytes.fromhex("fb48da0e82e6e01ba0c014513f74540d")
    transport_id = bytes.fromhex("650b5d76b6bec0390d1f8cfca5bd33f9")

    constants = {
        "mtu_bytes": MTU,
        "header_minsize_bytes": HEADER_MINSIZE,
        "header_maxsize_bytes": HEADER_MAXSIZE,
        "ifac_min_size_bytes": IFAC_MIN_SIZE,
        "mdu_bytes": MDU,
        "encrypted_mdu_bytes": ENCRYPTED_MDU,
        "plain_mdu_bytes": PLAIN_MDU,
        "token_overhead_bytes": TOKEN_OVERHEAD,
        "aes128_blocksize_bytes": AES128_BLOCKSIZE,
        "derivations": {
            "header_minsize": f"2 + 1 + ({TRUNCATED_HASHLENGTH_BYTES * 8} // 8) * 1 = {HEADER_MINSIZE}",
            "header_maxsize": f"2 + 1 + ({TRUNCATED_HASHLENGTH_BYTES * 8} // 8) * 2 = {HEADER_MAXSIZE}",
            "mdu": f"MTU({MTU}) - HEADER_MAXSIZE({HEADER_MAXSIZE}) - IFAC_MIN_SIZE({IFAC_MIN_SIZE}) = {MDU}",
            "encrypted_mdu": f"floor((MDU({MDU}) - TOKEN_OVERHEAD({TOKEN_OVERHEAD}) - KEYSIZE//16({KEYSIZE_BITS // 16})) / AES128_BLOCKSIZE({AES128_BLOCKSIZE})) * AES128_BLOCKSIZE({AES128_BLOCKSIZE}) - 1 = {ENCRYPTED_MDU}",
            "plain_mdu": f"MDU = {PLAIN_MDU}",
        },
    }

    boundary_vectors = []

    # 1. Minimum HEADER_1 packet (19 bytes, empty payload)
    flags_h1 = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, DATA)
    header_min_h1 = build_header_1(flags_h1, 0, dest_hash, NONE_CONTEXT)
    raw_min_h1 = header_min_h1
    hashable_min_h1, _, trunc_min_h1 = compute_packet_hash(raw_min_h1)
    boundary_vectors.append({
        "description": "Minimum HEADER_1 packet: header only, no payload",
        "header_type": "HEADER_1",
        "payload_length": 0,
        "total_length": len(raw_min_h1),
        "expected_total_length": HEADER_MINSIZE,
        "raw_packet": raw_min_h1.hex(),
        "packet_hash": trunc_min_h1.hex(),
    })

    # 2. Minimum HEADER_2 packet (35 bytes, empty payload)
    flags_h2 = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT, SINGLE, DATA)
    header_min_h2 = build_header_2(flags_h2, 0, transport_id, dest_hash, NONE_CONTEXT)
    raw_min_h2 = header_min_h2
    hashable_min_h2, _, trunc_min_h2 = compute_packet_hash(raw_min_h2)
    boundary_vectors.append({
        "description": "Minimum HEADER_2 packet: header only, no payload",
        "header_type": "HEADER_2",
        "payload_length": 0,
        "total_length": len(raw_min_h2),
        "expected_total_length": HEADER_MAXSIZE,
        "raw_packet": raw_min_h2.hex(),
        "packet_hash": trunc_min_h2.hex(),
    })

    # 3. Maximum HEADER_1 at MTU (500 bytes, 481-byte payload)
    max_payload_h1 = MTU - HEADER_MINSIZE  # 481
    payload_max_h1 = make_deterministic_payload(max_payload_h1)
    raw_max_h1 = build_header_1(flags_h1, 0, dest_hash, NONE_CONTEXT) + payload_max_h1
    _, _, trunc_max_h1 = compute_packet_hash(raw_max_h1)
    boundary_vectors.append({
        "description": f"Maximum HEADER_1 at MTU: {max_payload_h1}-byte payload fills to {MTU} bytes",
        "header_type": "HEADER_1",
        "payload_length": max_payload_h1,
        "total_length": len(raw_max_h1),
        "expected_total_length": MTU,
        "raw_packet": raw_max_h1.hex(),
        "packet_hash": trunc_max_h1.hex(),
    })

    # 4. Maximum HEADER_2 at MTU (500 bytes, 465-byte payload)
    max_payload_h2 = MTU - HEADER_MAXSIZE  # 465
    payload_max_h2 = make_deterministic_payload(max_payload_h2)
    raw_max_h2 = build_header_2(flags_h2, 0, transport_id, dest_hash, NONE_CONTEXT) + payload_max_h2
    _, _, trunc_max_h2 = compute_packet_hash(raw_max_h2)
    boundary_vectors.append({
        "description": f"Maximum HEADER_2 at MTU: {max_payload_h2}-byte payload fills to {MTU} bytes",
        "header_type": "HEADER_2",
        "payload_length": max_payload_h2,
        "total_length": len(raw_max_h2),
        "expected_total_length": MTU,
        "raw_packet": raw_max_h2.hex(),
        "packet_hash": trunc_max_h2.hex(),
    })

    # 5. HEADER_1 with MDU payload (464 bytes payload)
    payload_mdu = make_deterministic_payload(MDU)
    raw_mdu = build_header_1(flags_h1, 0, dest_hash, NONE_CONTEXT) + payload_mdu
    _, _, trunc_mdu = compute_packet_hash(raw_mdu)
    boundary_vectors.append({
        "description": f"HEADER_1 with MDU payload: {MDU}-byte payload, {HEADER_MINSIZE + MDU} total",
        "header_type": "HEADER_1",
        "payload_length": MDU,
        "total_length": len(raw_mdu),
        "expected_total_length": HEADER_MINSIZE + MDU,
        "raw_packet": raw_mdu.hex(),
        "packet_hash": trunc_mdu.hex(),
    })

    # 6. HEADER_1 with ENCRYPTED_MDU payload (383 bytes payload)
    payload_enc = make_deterministic_payload(ENCRYPTED_MDU)
    raw_enc = build_header_1(flags_h1, 0, dest_hash, NONE_CONTEXT) + payload_enc
    _, _, trunc_enc = compute_packet_hash(raw_enc)
    boundary_vectors.append({
        "description": f"HEADER_1 with ENCRYPTED_MDU payload: {ENCRYPTED_MDU}-byte payload, {HEADER_MINSIZE + ENCRYPTED_MDU} total",
        "header_type": "HEADER_1",
        "payload_length": ENCRYPTED_MDU,
        "total_length": len(raw_enc),
        "expected_total_length": HEADER_MINSIZE + ENCRYPTED_MDU,
        "raw_packet": raw_enc.hex(),
        "packet_hash": trunc_enc.hex(),
    })

    return {
        "constants": constants,
        "boundary_vectors": boundary_vectors,
    }


def build_output(flag_packing, flag_unpacking, header_layouts, exhaustive_flags,
                 extended_headers, hash_vectors, size_limits):
    all_headers = header_layouts + extended_headers
    return {
        "description": "Reticulum v1.1.3 reference implementation - packet header test vectors",
        "source": "RNS/Packet.py",
        "constants": {
            "mtu_bytes": MTU,
            "header_1_size_bytes": HEADER_MINSIZE,
            "header_2_size_bytes": HEADER_MAXSIZE,
            "truncated_hash_length_bytes": TRUNCATED_HASHLENGTH_BYTES,
            "max_data_unit_bytes": MDU,
            "encrypted_mdu_bytes": ENCRYPTED_MDU,
            "plain_mdu_bytes": PLAIN_MDU,
            "header_maxsize_bytes": HEADER_MAXSIZE,
        },
        "flag_byte_layout": {
            "description": "Single byte encoding packet metadata",
            "bits": "HH_C_T_DD_PP",
            "bit_fields": {
                "header_type": {"bits": "7-6", "mask": "0b01000000", "shift": 6, "note": "Bit 7 unused/reserved"},
                "context_flag": {"bits": "5", "mask": "0b00100000", "shift": 5},
                "transport_type": {"bits": "4", "mask": "0b00010000", "shift": 4},
                "destination_type": {"bits": "3-2", "mask": "0b00001100", "shift": 2},
                "packet_type": {"bits": "1-0", "mask": "0b00000011", "shift": 0},
            },
            "packing_formula": "(header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | packet_type",
        },
        "packet_type_values": {
            "DATA": 0, "ANNOUNCE": 1, "LINKREQUEST": 2, "PROOF": 3,
        },
        "destination_type_values": {
            "SINGLE": 0, "GROUP": 1, "PLAIN": 2, "LINK": 3,
        },
        "header_type_values": {
            "HEADER_1": 0, "HEADER_2": 1,
        },
        "transport_type_values": {
            "BROADCAST": 0, "TRANSPORT": 1,
        },
        "context_type_values": {k: v for k, v in CONTEXT_TYPES.items()},
        "header_1_layout": {
            "description": "Standard header: flags(1) + hops(1) + dest_hash(16) + context(1) = 19 bytes",
            "fields": [
                {"name": "flags", "offset": 0, "length": 1},
                {"name": "hops", "offset": 1, "length": 1},
                {"name": "destination_hash", "offset": 2, "length": 16},
                {"name": "context", "offset": 18, "length": 1},
            ],
        },
        "header_2_layout": {
            "description": "Transport header: flags(1) + hops(1) + transport_id(16) + dest_hash(16) + context(1) = 35 bytes",
            "fields": [
                {"name": "flags", "offset": 0, "length": 1},
                {"name": "hops", "offset": 1, "length": 1},
                {"name": "transport_id", "offset": 2, "length": 16},
                {"name": "destination_hash", "offset": 18, "length": 16},
                {"name": "context", "offset": 34, "length": 1},
            ],
        },
        "packet_hash_algorithm": {
            "description": "Packet hash = SHA-256(hashable_part)[:16]",
            "hashable_part_header_1": "bytes([raw[0] & 0x0F]) + raw[2:]",
            "hashable_part_header_2": "bytes([raw[0] & 0x0F]) + raw[TRUNCATED_HASHLENGTH_BYTES + 2:]",
            "note": "Masking raw[0] with 0x0F strips header_type, context_flag, and transport_type, keeping only dest_type + packet_type",
        },
        "flag_packing_vectors": flag_packing,
        "flag_unpacking_vectors": flag_unpacking,
        "exhaustive_flag_vectors": exhaustive_flags,
        "header_vectors": all_headers,
        "packet_hash_vectors": hash_vectors,
        "size_limits": size_limits,
    }


def verify(output):
    # Verify flag packing round-trips
    for vec in output["flag_packing_vectors"]:
        flags = int(vec["flags_byte"], 16)
        unpacked = unpack_flags(flags)
        assert unpacked["header_type"] == vec["header_type"]
        assert unpacked["context_flag"] == vec["context_flag"]
        assert unpacked["transport_type"] == vec["transport_type"]
        assert unpacked["destination_type"] == vec["destination_type"]
        assert unpacked["packet_type"] == vec["packet_type"]
    print(f"  [OK] All {len(output['flag_packing_vectors'])} flag packing vectors round-trip verified")

    # Verify flag unpacking consistency
    for vec in output["flag_unpacking_vectors"]:
        flags = int(vec["flags_byte"], 16)
        repacked = pack_flags(
            vec["header_type"], vec["context_flag"], vec["transport_type"],
            vec["destination_type"], vec["packet_type"],
        )
        assert repacked == flags, f"Flag unpack/repack mismatch for 0x{flags:02x}"
    print(f"  [OK] All {len(output['flag_unpacking_vectors'])} flag unpacking vectors verified")

    # Verify exhaustive flag vectors
    for vec in output["exhaustive_flag_vectors"]:
        flags = int(vec["flags_byte"], 16)
        unpacked = unpack_flags(flags)
        assert unpacked["header_type"] == vec["header_type"]
        assert unpacked["context_flag"] == vec["context_flag"]
        assert unpacked["transport_type"] == vec["transport_type"]
        assert unpacked["destination_type"] == vec["destination_type"]
        assert unpacked["packet_type"] == vec["packet_type"]
        repacked = pack_flags(
            vec["header_type"], vec["context_flag"], vec["transport_type"],
            vec["destination_type"], vec["packet_type"],
        )
        assert repacked == flags, f"Exhaustive flag round-trip failed for 0x{flags:02x}"
    assert len(output["exhaustive_flag_vectors"]) == 128
    print(f"  [OK] All {len(output['exhaustive_flag_vectors'])} exhaustive flag vectors round-trip verified")

    # Verify header layouts
    for vec in output["header_vectors"]:
        assert len(bytes.fromhex(vec["header"])) == vec["header_length"]
        assert vec["header_length"] == vec["expected_header_length"], (
            f"Header length {vec['header_length']} != expected {vec['expected_header_length']}"
        )

        # Recompute packet hash
        raw = bytes.fromhex(vec["raw_packet"])
        _, _, trunc_hash = compute_packet_hash(raw)
        assert trunc_hash.hex() == vec["packet_hash"], (
            f"Packet hash mismatch for: {vec['description']}"
        )
    print(f"  [OK] All {len(output['header_vectors'])} header layout vectors verified")

    # Verify hash equivalence pairs
    hash_vecs = output["packet_hash_vectors"]
    for pair in hash_vecs["equivalence_pairs"]:
        h1_hash = pair["header_1"]["packet_hash"]
        h2_hash = pair["header_2"]["packet_hash"]
        assert h1_hash == h2_hash, f"Equivalence pair failed: {pair['description']}"

        # Recompute from raw
        h1_raw = bytes.fromhex(pair["header_1"]["raw_packet"])
        h2_raw = bytes.fromhex(pair["header_2"]["raw_packet"])
        _, _, h1_trunc = compute_packet_hash(h1_raw)
        _, _, h2_trunc = compute_packet_hash(h2_raw)
        assert h1_trunc == h2_trunc
    print(f"  [OK] All {len(hash_vecs['equivalence_pairs'])} hash equivalence pairs verified")

    # Verify hash edge cases
    for ec in hash_vecs["edge_cases"]:
        if "hashes_equal" in ec:
            if "packet_a" in ec and "packet_b" in ec:
                raw_a = bytes.fromhex(ec["packet_a"]["raw_packet"])
                raw_b = bytes.fromhex(ec["packet_b"]["raw_packet"])
                _, _, trunc_a = compute_packet_hash(raw_a)
                _, _, trunc_b = compute_packet_hash(raw_b)
                if ec["hashes_equal"]:
                    assert trunc_a == trunc_b, f"Expected equal hashes: {ec['description']}"
                else:
                    assert trunc_a != trunc_b, f"Expected different hashes: {ec['description']}"
        elif "raw_packet" in ec:
            raw = bytes.fromhex(ec["raw_packet"])
            _, _, trunc = compute_packet_hash(raw)
            assert trunc.hex() == ec["packet_hash"], f"Hash mismatch: {ec['description']}"
    print(f"  [OK] All {len(hash_vecs['edge_cases'])} hash edge cases verified")

    # Verify size limit vectors
    size_vecs = output["size_limits"]
    for bv in size_vecs["boundary_vectors"]:
        raw = bytes.fromhex(bv["raw_packet"])
        assert len(raw) == bv["total_length"], f"Size mismatch: {bv['description']}"
        assert bv["total_length"] == bv["expected_total_length"], (
            f"Expected total {bv['expected_total_length']}, got {bv['total_length']}: {bv['description']}"
        )
    print(f"  [OK] All {len(size_vecs['boundary_vectors'])} size boundary vectors verified")

    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify our local constants match the actual RNS library values."""
    import RNS
    assert MTU == RNS.Reticulum.MTU, f"MTU mismatch: {MTU} != {RNS.Reticulum.MTU}"
    assert HEADER_MAXSIZE == RNS.Reticulum.HEADER_MAXSIZE, f"HEADER_MAXSIZE mismatch: {HEADER_MAXSIZE} != {RNS.Reticulum.HEADER_MAXSIZE}"
    assert HEADER_MINSIZE == RNS.Reticulum.HEADER_MINSIZE, f"HEADER_MINSIZE mismatch: {HEADER_MINSIZE} != {RNS.Reticulum.HEADER_MINSIZE}"
    assert MDU == RNS.Reticulum.MDU, f"MDU mismatch: {MDU} != {RNS.Reticulum.MDU}"
    assert TRUNCATED_HASHLENGTH_BYTES == RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
    assert TOKEN_OVERHEAD == RNS.Identity.TOKEN_OVERHEAD
    assert AES128_BLOCKSIZE == RNS.Identity.AES128_BLOCKSIZE
    assert KEYSIZE_BITS == RNS.Identity.KEYSIZE
    from RNS.Packet import Packet
    assert ENCRYPTED_MDU == Packet.ENCRYPTED_MDU, f"ENCRYPTED_MDU mismatch: {ENCRYPTED_MDU} != {Packet.ENCRYPTED_MDU}"
    assert PLAIN_MDU == Packet.PLAIN_MDU, f"PLAIN_MDU mismatch: {PLAIN_MDU} != {Packet.PLAIN_MDU}"

    # Verify context type constants
    for name, value in CONTEXT_TYPES.items():
        assert getattr(Packet, name) == value, f"Context {name} mismatch: {value} != {getattr(Packet, name)}"

    print("  [OK] All library constants verified")


def main():
    print("Extracting packet header vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    flag_packing = extract_flag_packing_vectors()
    print(f"  Extracted {len(flag_packing)} flag packing vectors")

    flag_unpacking = extract_flag_unpacking_vectors()
    print(f"  Extracted {len(flag_unpacking)} flag unpacking vectors")

    exhaustive_flags = extract_exhaustive_flag_vectors()
    print(f"  Extracted {len(exhaustive_flags)} exhaustive flag vectors")

    header_layouts = extract_header_layout_vectors()
    print(f"  Extracted {len(header_layouts)} base header layout vectors")

    extended_headers = extract_extended_header_vectors()
    print(f"  Extracted {len(extended_headers)} extended header vectors")

    hash_vectors = extract_hash_vectors()
    print(f"  Extracted {len(hash_vectors['equivalence_pairs'])} hash equivalence pairs")
    print(f"  Extracted {len(hash_vectors['edge_cases'])} hash edge cases")

    size_limits = extract_size_limit_vectors()
    print(f"  Extracted {len(size_limits['boundary_vectors'])} size boundary vectors")

    print("Building output...")
    output = build_output(flag_packing, flag_unpacking, header_layouts,
                          exhaustive_flags, extended_headers, hash_vectors, size_limits)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
