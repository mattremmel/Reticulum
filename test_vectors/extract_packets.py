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


def build_output(flag_packing, flag_unpacking, header_layouts):
    return {
        "description": "Reticulum v1.1.3 reference implementation - packet header test vectors",
        "source": "RNS/Packet.py",
        "constants": {
            "mtu_bytes": 500,
            "header_1_size_bytes": 19,
            "header_2_size_bytes": 35,
            "truncated_hash_length_bytes": 16,
            "max_data_unit_bytes": 462,
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
        "header_vectors": header_layouts,
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

    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("  [OK] JSON round-trip integrity verified")


def main():
    print("Extracting packet header vectors...")

    flag_packing = extract_flag_packing_vectors()
    print(f"  Extracted {len(flag_packing)} flag packing vectors")

    flag_unpacking = extract_flag_unpacking_vectors()
    print(f"  Extracted {len(flag_unpacking)} flag unpacking vectors")

    header_layouts = extract_header_layout_vectors()
    print(f"  Extracted {len(header_layouts)} header layout vectors")

    print("Building output...")
    output = build_output(flag_packing, flag_unpacking, header_layouts)

    print("Verifying...")
    verify(output)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
