#!/usr/bin/env python3
"""
Extract resource transfer protocol test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Link/Transport/Resource objects) to
avoid Transport init. Real RNS crypto primitives are used for encryption,
hashing, and serialization.

Covers:
  - Packet context constants (RESOURCE through RESOURCE_RCL)
  - Resource state codes and hashmap exhaustion flags
  - Micro resource (128B) single-part transfer sequence:
    1. Sender prepares advertisement
    2. Receiver accepts and requests parts
    3. Sender sends part data
    4. Receiver assembles and proves
    5. Sender validates proof
  - Mini resource (256KB) multi-part transfer sequence:
    552 parts, 8 hashmap segments, 7 HMU packets, 62 transfer rounds
    with windowed request/response and hashmap exhaustion handling
  - Small resource (1MB) multi-part transfer sequence:
    2156 parts, 30 hashmap segments, 29 HMU packets, ~235 transfer rounds
    validating windowing at scale
  - Medium resource (5MB) multi-segment (5 segments) transfer sequence:
    ~10,777 total parts across 5 segments with segment chaining
    (split=True, flags 0x05)
  - Large resource (50MB) multi-segment (48 segments) transfer sequence:
    ~107,766 total parts across 48 segments for sustained throughput
    stress testing (split=True, flags 0x05)
  - Micro resource (128B) with metadata transfer (flags 0x21)
  - Compressible resource (2KB) with compression transfer (flags 0x03)
  - Compressible resource (2KB) with metadata + compression transfer (flags 0x23)
  - Data integrity verification
  - Callback and state machine sequence
  - Cancellation payload vectors (ICL, RCL)

Usage:
    python3 test_vectors/extract_resource_transfers.py

Output:
    test_vectors/resource_transfers.json
"""

import bz2
import hashlib
import json
import math
import os
import struct
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource_transfers.json")
LINKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "links.json")
RESOURCES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources.json")

# --- Constants (reproduced to avoid Transport init) ---

MTU = 500
HEADER_MINSIZE = 19
HEADER_MAXSIZE = 35
IFAC_MIN_SIZE = 1
TOKEN_OVERHEAD = 48
AES128_BLOCKSIZE = 16
HASHLENGTH_BYTES = 32
TRUNCATED_HASHLENGTH_BYTES = 16

# Link MDU (encrypted payload capacity for link data packets)
LINK_MDU = math.floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1

# Resource SDU: size of each encrypted part = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE
RESOURCE_SDU = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE

# Resource constants (from Resource class)
WINDOW = 4
WINDOW_MIN = 2
WINDOW_MAX_SLOW = 10
WINDOW_MAX_VERY_SLOW = 4
WINDOW_MAX_FAST = 75
WINDOW_MAX = WINDOW_MAX_FAST
FAST_RATE_THRESHOLD = WINDOW_MAX_SLOW - WINDOW - 2
VERY_SLOW_RATE_THRESHOLD = 2
RATE_FAST = (50 * 1000) / 8
RATE_VERY_SLOW = (2 * 1000) / 8
WINDOW_FLEXIBILITY = 4
MAPHASH_LEN = 4
RANDOM_HASH_SIZE = 4
MAX_EFFICIENT_SIZE = 1 * 1024 * 1024 - 1
RESPONSE_MAX_GRACE_TIME = 10
METADATA_MAX_SIZE = 16 * 1024 * 1024 - 1
AUTO_COMPRESS_MAX_SIZE = 64 * 1024 * 1024
PART_TIMEOUT_FACTOR = 4
PART_TIMEOUT_FACTOR_AFTER_RTT = 2
PROOF_TIMEOUT_FACTOR = 3
MAX_RETRIES = 16
MAX_ADV_RETRIES = 4
SENDER_GRACE_TIME = 10.0
PROCESSING_GRACE = 1.0
RETRY_GRACE_TIME = 0.25
PER_RETRY_DELAY = 0.5
WATCHDOG_MAX_SLEEP = 1
HASHMAP_IS_NOT_EXHAUSTED = 0x00
HASHMAP_IS_EXHAUSTED = 0xFF

# Status constants
STATUS_NONE = 0x00
STATUS_QUEUED = 0x01
STATUS_ADVERTISED = 0x02
STATUS_TRANSFERRING = 0x03
STATUS_AWAITING_PROOF = 0x04
STATUS_ASSEMBLING = 0x05
STATUS_COMPLETE = 0x06
STATUS_FAILED = 0x07
STATUS_CORRUPT = 0x08
STATUS_REJECTED = 0x00

# ResourceAdvertisement constants
OVERHEAD = 134
HASHMAP_MAX_LEN = math.floor((LINK_MDU - OVERHEAD) / MAPHASH_LEN)
COLLISION_GUARD_SIZE = 2 * WINDOW_MAX + HASHMAP_MAX_LEN

# Packet context constants (from Packet.py)
CONTEXT_NONE = 0x00
CONTEXT_RESOURCE = 0x01
CONTEXT_RESOURCE_ADV = 0x02
CONTEXT_RESOURCE_REQ = 0x03
CONTEXT_RESOURCE_HMU = 0x04
CONTEXT_RESOURCE_PRF = 0x05
CONTEXT_RESOURCE_ICL = 0x06
CONTEXT_RESOURCE_RCL = 0x07


# --- Helper functions ---

def load_links_json():
    with open(LINKS_PATH, "r") as f:
        return json.load(f)


def load_resources_json():
    with open(RESOURCES_PATH, "r") as f:
        return json.load(f)


def full_hash(data):
    return hashlib.sha256(data).digest()


def truncated_hash(data):
    return hashlib.sha256(data).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def deterministic_data(index, length):
    """Generate deterministic data of given length via SHA-256 expansion."""
    seed = hashlib.sha256(b"reticulum_test_resource_data_" + str(index).encode()).digest()
    result = bytearray()
    counter = 0
    while len(result) < length:
        result += hashlib.sha256(seed + struct.pack(">I", counter)).digest()
        counter += 1
    return bytes(result[:length])


def deterministic_iv(index):
    """Generate deterministic 16-byte IV."""
    return hashlib.sha256(b"reticulum_test_resource_iv_" + str(index).encode()).digest()[:16]


def deterministic_random_hash(index):
    """Generate deterministic 4-byte random hash."""
    return hashlib.sha256(b"reticulum_test_resource_random_hash_" + str(index).encode()).digest()[:RANDOM_HASH_SIZE]


def token_encrypt_deterministic(plaintext, derived_key, iv):
    """Encrypt using Token format with a deterministic IV.

    Token format: IV(16) + AES-256-CBC(PKCS7(plaintext)) + HMAC-SHA256(32)
    Key split: signing_key = derived_key[:32], encryption_key = derived_key[32:]
    """
    from RNS.Cryptography import HMAC, PKCS7
    from RNS.Cryptography.AES import AES_256_CBC

    signing_key = derived_key[:32]
    encryption_key = derived_key[32:]

    padded = PKCS7.pad(plaintext)
    ciphertext = AES_256_CBC.encrypt(plaintext=padded, key=encryption_key, iv=iv)
    signed_parts = iv + ciphertext
    hmac_val = HMAC.new(signing_key, signed_parts).digest()
    return signed_parts + hmac_val


def token_decrypt(token_data, derived_key):
    """Decrypt Token-encrypted data."""
    from RNS.Cryptography.Token import Token
    token = Token(key=derived_key)
    return token.decrypt(token_data)


def get_map_hash(data, random_hash):
    """Compute map hash: SHA256(data + random_hash)[:MAPHASH_LEN]."""
    return full_hash(data + random_hash)[:MAPHASH_LEN]


def hex_prefix(data, max_bytes=64):
    """Return hex string, truncated with note if longer than max_bytes."""
    if len(data) <= max_bytes:
        return data.hex()
    return data[:max_bytes].hex() + f"... ({len(data)} bytes total)"


# ============================================================
# Extraction functions
# ============================================================

def extract_constants():
    """Extract packet context and transfer protocol constants."""
    return {
        "packet_contexts": {
            "NONE": CONTEXT_NONE,
            "RESOURCE": CONTEXT_RESOURCE,
            "RESOURCE_ADV": CONTEXT_RESOURCE_ADV,
            "RESOURCE_REQ": CONTEXT_RESOURCE_REQ,
            "RESOURCE_HMU": CONTEXT_RESOURCE_HMU,
            "RESOURCE_PRF": CONTEXT_RESOURCE_PRF,
            "RESOURCE_ICL": CONTEXT_RESOURCE_ICL,
            "RESOURCE_RCL": CONTEXT_RESOURCE_RCL,
        },
        "resource_states": {
            "NONE": STATUS_NONE,
            "QUEUED": STATUS_QUEUED,
            "ADVERTISED": STATUS_ADVERTISED,
            "TRANSFERRING": STATUS_TRANSFERRING,
            "AWAITING_PROOF": STATUS_AWAITING_PROOF,
            "ASSEMBLING": STATUS_ASSEMBLING,
            "COMPLETE": STATUS_COMPLETE,
            "FAILED": STATUS_FAILED,
            "CORRUPT": STATUS_CORRUPT,
            "REJECTED": STATUS_REJECTED,
        },
        "hashmap_flags": {
            "HASHMAP_IS_NOT_EXHAUSTED": HASHMAP_IS_NOT_EXHAUSTED,
            "HASHMAP_IS_EXHAUSTED": HASHMAP_IS_EXHAUSTED,
        },
    }


def build_transfer_sequence(derived_key):
    """Build the complete 128B micro resource transfer sequence.

    Simulates the 5-step exchange between sender and receiver:
      1. Sender prepares advertisement
      2. Receiver accepts & requests parts
      3. Sender sends part
      4. Receiver assembles & proves
      5. Sender validates proof
    """
    from RNS.vendor import umsgpack

    idx = 0  # Case 0: micro resource, 128B, no metadata, no compression

    # --- Input data ---
    input_data = deterministic_data(idx, 128)
    input_sha256 = full_hash(input_data).hex()

    # --- Step 1: Sender prepares advertisement ---
    random_hash = deterministic_random_hash(idx)
    iv = deterministic_iv(idx)

    # No metadata, no compression for case 0
    data_with_metadata = input_data

    # Pre-encryption data: random_hash(4) + payload
    pre_encryption_data = random_hash + data_with_metadata

    # Encrypt
    encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, iv)
    encrypted_size = len(encrypted_data)

    # Segment into parts
    sdu = RESOURCE_SDU
    num_parts = int(math.ceil(encrypted_size / float(sdu)))
    assert num_parts == 1, f"Expected 1 part for 128B resource, got {num_parts}"

    # Single part
    part_data = encrypted_data  # fits within SDU (192 < 464)

    # Compute hashes
    resource_hash = full_hash(data_with_metadata + random_hash)
    original_hash = resource_hash  # first segment
    expected_proof = full_hash(data_with_metadata + resource_hash)

    # Hashmap
    map_hash = get_map_hash(part_data, random_hash)
    hashmap = map_hash

    # Flags: encrypted=True, compressed=False, split=False, is_request=False, is_response=False, has_metadata=False
    flags = 0x01

    # Build advertisement dict
    adv_dict = {
        "t": encrypted_size,
        "d": len(data_with_metadata),
        "n": num_parts,
        "h": resource_hash,
        "r": random_hash,
        "o": original_hash,
        "i": 1,
        "l": 1,
        "q": None,
        "f": flags,
        "m": hashmap,
    }
    adv_packed = umsgpack.packb(adv_dict)

    step_1 = {
        "step": 1,
        "name": "sender_prepare_advertisement",
        "advertisement_packed_hex": adv_packed.hex(),
        "advertisement_packed_length": len(adv_packed),
        "advertisement_dict": {
            "t": encrypted_size,
            "d": len(data_with_metadata),
            "n": num_parts,
            "h": resource_hash.hex(),
            "r": random_hash.hex(),
            "o": original_hash.hex(),
            "i": 1,
            "l": 1,
            "q": None,
            "f": flags,
            "m": hashmap.hex(),
        },
        "resource_hash_hex": resource_hash.hex(),
        "random_hash_hex": random_hash.hex(),
        "hashmap_hex": hashmap.hex(),
        "num_parts": num_parts,
        "encrypted_data_length": encrypted_size,
        "flags": flags,
        "flags_hex": f"0x{flags:02x}",
        "expected_proof_hex": expected_proof.hex(),
        "sender_state_before": "QUEUED",
        "sender_state_after": "ADVERTISED",
        "packet_context": f"RESOURCE_ADV (0x{CONTEXT_RESOURCE_ADV:02x})",
    }

    # --- Step 2: Receiver accepts & requests parts ---
    # Receiver parses advertisement, extracts hashmap, builds request
    # request_data format (from request_next() line 954):
    #   hmu_part(1) + resource_hash(32) + requested_hashes(N*4)
    # hmu_part = bytes([hashmap_exhausted])
    # For single-part, hashmap is NOT exhausted (all hashes available)

    hashmap_exhausted_flag = bytes([HASHMAP_IS_NOT_EXHAUSTED])
    request_payload = hashmap_exhausted_flag + resource_hash + map_hash
    request_payload_length = len(request_payload)

    step_2 = {
        "step": 2,
        "name": "receiver_request_parts",
        "request_payload_hex": request_payload.hex(),
        "request_payload_length": request_payload_length,
        "request_breakdown": {
            "hashmap_exhausted_flag": f"0x{HASHMAP_IS_NOT_EXHAUSTED:02x}",
            "resource_hash_hex": resource_hash.hex(),
            "requested_hashes_hex": map_hash.hex(),
            "requested_hashes_count": 1,
        },
        "request_layout": f"exhausted_flag(1) + resource_hash({HASHLENGTH_BYTES}) + map_hashes({MAPHASH_LEN}*1) = {request_payload_length}",
        "receiver_state": "TRANSFERRING",
        "callbacks_fired": ["resource_started"],
        "packet_context": f"RESOURCE_REQ (0x{CONTEXT_RESOURCE_REQ:02x})",
    }

    # --- Step 3: Sender sends part ---
    # Sender parses request (from request() line 970):
    #   wants_more_hashmap = request_data[0] == HASHMAP_IS_EXHAUSTED → False
    #   pad = 1 (no extra hashmap bytes)
    #   requested_hashes = request_data[1 + HASHLENGTH_BYTES:]
    # Sender finds matching part and sends it as RESOURCE packet

    step_3 = {
        "step": 3,
        "name": "sender_send_part",
        "part_index": 0,
        "part_data_hex": hex_prefix(part_data, 64),
        "part_data_length": len(part_data),
        "map_hash_hex": map_hash.hex(),
        "sender_state": "TRANSFERRING",
        "packet_context": f"RESOURCE (0x{CONTEXT_RESOURCE:02x})",
    }

    # --- Step 4: Receiver assembles & proves ---
    # receive_part() matches part_hash to hashmap
    # received_count == total_parts → assemble()
    # assemble() (line 668):
    #   1. Join parts: stream = b"".join(parts)
    #   2. Decrypt: data = link.decrypt(stream)  [Token.decrypt]
    #   3. Strip random hash: data = data[RANDOM_HASH_SIZE:]
    #   4. Decompress if flagged (not for case 0)
    #   5. Verify: SHA256(data + random_hash) == resource_hash
    #   6. prove(): proof = SHA256(data + resource_hash)
    #              proof_data = resource_hash + proof

    joined_parts = part_data  # single part
    decrypted = token_decrypt(joined_parts, derived_key)
    stripped_data = decrypted[RANDOM_HASH_SIZE:]

    # Verify hash
    calculated_hash = full_hash(stripped_data + random_hash)
    hash_verified = calculated_hash == resource_hash
    assert hash_verified, "Assembly hash verification failed"

    # Verify data matches original
    assert stripped_data == input_data, "Assembled data doesn't match input"

    # Build proof
    proof = full_hash(stripped_data + resource_hash)
    proof_data = resource_hash + proof
    assert proof == expected_proof, "Proof doesn't match expected"

    step_4 = {
        "step": 4,
        "name": "receiver_assemble_and_prove",
        "assembly": {
            "joined_parts_hex": hex_prefix(joined_parts, 64),
            "joined_parts_length": len(joined_parts),
            "decrypted_hex": hex_prefix(decrypted, 64),
            "decrypted_length": len(decrypted),
            "stripped_data_hex": hex_prefix(stripped_data, 64),
            "stripped_data_length": len(stripped_data),
            "hash_verified": hash_verified,
            "calculated_hash_hex": calculated_hash.hex(),
        },
        "proof_payload_hex": proof_data.hex(),
        "proof_payload_length": len(proof_data),
        "proof_breakdown": {
            "resource_hash_hex": resource_hash.hex(),
            "proof_hex": proof.hex(),
        },
        "proof_layout": f"resource_hash({HASHLENGTH_BYTES}) + proof({HASHLENGTH_BYTES}) = {len(proof_data)}",
        "receiver_state_sequence": ["TRANSFERRING", "ASSEMBLING", "COMPLETE"],
        "callbacks_fired": ["progress_callback", "resource_concluded"],
        "progress_at_callback": {"received": 1, "total": 1},
        "packet_context": f"RESOURCE_PRF (0x{CONTEXT_RESOURCE_PRF:02x})",
    }

    # --- Step 5: Sender validates proof ---
    # validate_proof() (line 771):
    #   len(proof_data) == HASHLENGTH//8 * 2 = 64
    #   proof_data[32:] == expected_proof
    proof_valid = (
        len(proof_data) == HASHLENGTH_BYTES * 2
        and proof_data[HASHLENGTH_BYTES:] == expected_proof
    )
    assert proof_valid, "Proof validation failed"

    step_5 = {
        "step": 5,
        "name": "sender_validate_proof",
        "proof_valid": proof_valid,
        "validation": {
            "proof_data_length_check": f"len({len(proof_data)}) == HASHLENGTH_BYTES*2({HASHLENGTH_BYTES * 2})",
            "proof_hash_check": f"proof_data[{HASHLENGTH_BYTES}:] == expected_proof",
        },
        "sender_state": "COMPLETE",
        "callbacks_fired": ["completion_callback"],
    }

    # --- Build the transfer sequence vector ---
    reconstructed_sha256 = full_hash(stripped_data).hex()

    vector = {
        "index": 0,
        "description": "Micro resource (128B) single-part transfer, no metadata",
        "input_data_hex": hex_prefix(input_data, 64),
        "input_data_length": 128,
        "input_sha256": input_sha256,
        "derived_key_hex": derived_key.hex(),
        "deterministic_iv_hex": iv.hex(),
        "random_hash_hex": random_hash.hex(),
        "steps": [step_1, step_2, step_3, step_4, step_5],
        "data_integrity": {
            "original_sha256": input_sha256,
            "reconstructed_sha256": reconstructed_sha256,
            "match": input_sha256 == reconstructed_sha256,
        },
        "state_machine_sequence": [
            {"side": "sender",   "event": "prepare_advertisement", "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "receiver", "event": "accept_advertisement",  "state_before": "NONE",         "state_after": "TRANSFERRING", "callback": "resource_started"},
            {"side": "receiver", "event": "request_parts",         "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": None},
            {"side": "sender",   "event": "send_part",             "state_before": "ADVERTISED",   "state_after": "TRANSFERRING", "callback": None},
            {"side": "receiver", "event": "receive_part",          "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback"},
            {"side": "receiver", "event": "assemble",              "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "verify_and_prove",      "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": "resource_concluded"},
            {"side": "sender",   "event": "validate_proof",        "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "completion_callback"},
        ],
    }

    micro_vector = vector
    mini_vector = build_mini_transfer_sequence(derived_key)
    small_vector = build_small_transfer_sequence(derived_key)
    medium_vector = build_medium_transfer_sequence(derived_key)
    large_vector = build_large_transfer_sequence(derived_key)
    return [micro_vector, mini_vector, small_vector, medium_vector, large_vector]


def build_mini_transfer_sequence(derived_key):
    """Build the 256KB multi-part resource transfer sequence.

    Simulates the full windowed transfer protocol:
      - 552 parts, 8 hashmap segments, 7 HMU packets
      - 62 transfer rounds with window growing from 4 to 10
      - Full assembly, proof, and validation
    """
    from RNS.vendor import umsgpack

    idx = 1  # Case 1: mini resource, 256KB

    # --- Phase A: Prepare & encrypt ---
    input_data = deterministic_data(idx, 256000)
    input_sha256 = full_hash(input_data).hex()

    # Attempt compression (SHA-256 expanded data is incompressible)
    compressed_data = bz2.compress(input_data)
    compression_helps = len(compressed_data) < len(input_data)
    assert not compression_helps, "Expected incompressible data"

    random_hash = deterministic_random_hash(idx)
    iv = deterministic_iv(idx)

    data_with_metadata = input_data  # no metadata

    # Pre-encryption data: random_hash(4) + payload
    pre_encryption_data = random_hash + data_with_metadata

    # Encrypt
    encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, iv)
    encrypted_size = len(encrypted_data)
    encrypted_sha256 = full_hash(encrypted_data).hex()

    # --- Phase B: Segment into parts & compute hashmap ---
    sdu = RESOURCE_SDU
    num_parts = int(math.ceil(encrypted_size / float(sdu)))
    assert num_parts == 552, f"Expected 552 parts, got {num_parts}"

    parts = []
    hashmap_raw = b""
    for i in range(num_parts):
        part_data = encrypted_data[i * sdu:(i + 1) * sdu]
        parts.append(part_data)
        map_hash = get_map_hash(part_data, random_hash)
        hashmap_raw += map_hash

    total_hashmap_bytes = len(hashmap_raw)
    assert total_hashmap_bytes == num_parts * MAPHASH_LEN

    # Verify last part size
    last_part_size = len(parts[-1])
    assert last_part_size == 400, f"Expected last part 400 bytes, got {last_part_size}"

    # Organize hashmap by segment
    num_segments = int(math.ceil(num_parts / HASHMAP_MAX_LEN))
    assert num_segments == 8

    hashmap_by_segment = []
    for seg in range(num_segments):
        seg_start = seg * HASHMAP_MAX_LEN
        seg_end = min((seg + 1) * HASHMAP_MAX_LEN, num_parts)
        seg_hash_count = seg_end - seg_start
        seg_hashmap = hashmap_raw[seg_start * MAPHASH_LEN:seg_end * MAPHASH_LEN]
        hashmap_by_segment.append({
            "segment": seg,
            "hash_count": seg_hash_count,
            "hashmap_hex": seg_hashmap.hex(),
        })

    # --- Phase C: Compute resource hash & expected proof ---
    resource_hash = full_hash(data_with_metadata + random_hash)
    original_hash = resource_hash
    expected_proof = full_hash(data_with_metadata + resource_hash)

    # --- Phase D: Build 5-step transfer vector ---

    # Flags: encrypted=True, compressed=False, split=False, no request/response, no metadata
    flags = 0x01

    # Step 1: Advertisement
    adv_hashmap = hashmap_raw[:HASHMAP_MAX_LEN * MAPHASH_LEN]
    adv_dict = {
        "t": encrypted_size,
        "d": len(data_with_metadata),
        "n": num_parts,
        "h": resource_hash,
        "r": random_hash,
        "o": original_hash,
        "i": 1,
        "l": 1,
        "q": None,
        "f": flags,
        "m": adv_hashmap,
    }
    adv_packed = umsgpack.packb(adv_dict)

    step_1 = {
        "step": 1,
        "name": "sender_prepare_advertisement",
        "advertisement_packed_hex": adv_packed.hex(),
        "advertisement_packed_length": len(adv_packed),
        "advertisement_dict": {
            "t": encrypted_size,
            "d": len(data_with_metadata),
            "n": num_parts,
            "h": resource_hash.hex(),
            "r": random_hash.hex(),
            "o": original_hash.hex(),
            "i": 1,
            "l": 1,
            "q": None,
            "f": flags,
            "m": adv_hashmap.hex(),
        },
        "resource_hash_hex": resource_hash.hex(),
        "random_hash_hex": random_hash.hex(),
        "hashmap_hex": adv_hashmap.hex(),
        "num_parts": num_parts,
        "encrypted_data_length": encrypted_size,
        "flags": flags,
        "flags_hex": f"0x{flags:02x}",
        "expected_proof_hex": expected_proof.hex(),
        "sender_state_before": "QUEUED",
        "sender_state_after": "ADVERTISED",
        "packet_context": f"RESOURCE_ADV (0x{CONTEXT_RESOURCE_ADV:02x})",
    }

    # Step 2: Simulate windowed transfer protocol (62 rounds)
    window = WINDOW  # 4
    window_max = WINDOW_MAX_SLOW  # 10
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY  # 4
    hashmap_height = HASHMAP_MAX_LEN  # 74 hashes from advertisement
    received_count = 0
    consecutive_completed = -1
    receiver_parts = [None] * num_parts

    rounds_summary = []
    representative_round_indices = set()
    hmu_packets = []
    total_rounds = 0

    while received_count < num_parts:
        total_rounds += 1

        # --- Request phase (request_next logic) ---
        search_start = consecutive_completed + 1
        hashmap_exhausted = False
        requested_hashes = b""
        requested_indices = []
        outstanding = 0

        pn = search_start
        for _ in range(window):
            if pn >= num_parts:
                break
            if pn < hashmap_height:
                part_hash = hashmap_raw[pn * MAPHASH_LEN:(pn + 1) * MAPHASH_LEN]
                requested_hashes += part_hash
                requested_indices.append(pn)
                outstanding += 1
            else:
                hashmap_exhausted = True
                break
            pn += 1

        # Build request payload
        if hashmap_exhausted:
            hmu_flag = bytes([HASHMAP_IS_EXHAUSTED])
            last_map_hash = hashmap_raw[(hashmap_height - 1) * MAPHASH_LEN:hashmap_height * MAPHASH_LEN]
            hmu_part = hmu_flag + last_map_hash
        else:
            hmu_part = bytes([HASHMAP_IS_NOT_EXHAUSTED])

        request_payload = hmu_part + resource_hash + requested_hashes

        # --- Receive phase (sender sends parts) ---
        for pi in requested_indices:
            receiver_parts[pi] = parts[pi]
            received_count += 1
            # Update consecutive completed height
            if pi == consecutive_completed + 1:
                consecutive_completed = pi
            cp = consecutive_completed + 1
            while cp < num_parts and receiver_parts[cp] is not None:
                consecutive_completed = cp
                cp += 1

        # Build round summary
        round_info = {
            "round": total_rounds,
            "window": window,
            "parts_requested": len(requested_indices),
            "parts_requested_indices_first": requested_indices[0] if requested_indices else None,
            "parts_requested_indices_last": requested_indices[-1] if requested_indices else None,
            "received_total": received_count,
            "consecutive_completed": consecutive_completed,
            "hashmap_exhausted": hashmap_exhausted,
            "hashmap_height": hashmap_height,
        }

        # Handle HMU if hashmap exhausted
        if hashmap_exhausted:
            segment = hashmap_height // HASHMAP_MAX_LEN
            seg_start = segment * HASHMAP_MAX_LEN
            seg_end = min((segment + 1) * HASHMAP_MAX_LEN, num_parts)
            seg_hashmap = hashmap_raw[seg_start * MAPHASH_LEN:seg_end * MAPHASH_LEN]
            hmu_payload = resource_hash + umsgpack.packb([segment, seg_hashmap])

            hmu_packets.append({
                "hmu_index": len(hmu_packets),
                "triggered_at_round": total_rounds,
                "segment": segment,
                "hash_count": seg_end - seg_start,
                "payload_hex": hmu_payload.hex(),
                "payload_length": len(hmu_payload),
                "format": f"resource_hash({HASHLENGTH_BYTES}) + msgpack([segment, hashmap])",
                "packet_context": f"RESOURCE_HMU (0x{CONTEXT_RESOURCE_HMU:02x})",
            })

            round_info["hmu_segment"] = segment
            hashmap_height += (seg_end - seg_start)

        rounds_summary.append(round_info)

        # Window growth (when outstanding == 0 after receiving all requested)
        if window < window_max:
            window += 1
            if (window - window_min) > (window_flexibility - 1):
                window_min += 1

    assert total_rounds == 62, f"Expected 62 rounds, got {total_rounds}"
    assert len(hmu_packets) == 7, f"Expected 7 HMU packets, got {len(hmu_packets)}"
    assert received_count == num_parts

    # Representative rounds: 1, 10, 18, 62
    rep_round_numbers = [1, 10, 18, 62]
    representative_rounds = []
    for rn in rep_round_numbers:
        r = rounds_summary[rn - 1]
        # Build full detail for representative rounds
        ri_first = r["parts_requested_indices_first"]
        ri_last = r["parts_requested_indices_last"]
        rep = dict(r)
        if ri_first is not None:
            rep["first_part_hex"] = hex_prefix(parts[ri_first], 32)
            rep["first_part_length"] = len(parts[ri_first])
            rep["last_part_hex"] = hex_prefix(parts[ri_last], 32)
            rep["last_part_length"] = len(parts[ri_last])
        representative_rounds.append(rep)

    step_2 = {
        "step": 2,
        "name": "transfer_protocol_simulation",
        "total_rounds": total_rounds,
        "final_window": window,
        "initial_window": WINDOW,
        "window_max": WINDOW_MAX_SLOW,
        "receiver_state": "TRANSFERRING",
        "packet_context_req": f"RESOURCE_REQ (0x{CONTEXT_RESOURCE_REQ:02x})",
        "packet_context_data": f"RESOURCE (0x{CONTEXT_RESOURCE:02x})",
    }

    transfer_protocol = {
        "total_rounds": total_rounds,
        "initial_window": WINDOW,
        "final_window": window,
        "window_max": WINDOW_MAX_SLOW,
        "rounds_summary": rounds_summary,
        "representative_rounds": representative_rounds,
        "hmu_packets": hmu_packets,
    }

    # Step 3: Assembly
    joined_parts = b"".join(receiver_parts)
    assert len(joined_parts) == encrypted_size

    decrypted = token_decrypt(joined_parts, derived_key)
    stripped_data = decrypted[RANDOM_HASH_SIZE:]

    calculated_hash = full_hash(stripped_data + random_hash)
    hash_verified = calculated_hash == resource_hash
    assert hash_verified, "Assembly hash verification failed"
    assert stripped_data == input_data, "Assembled data doesn't match input"

    step_3 = {
        "step": 3,
        "name": "receiver_assemble",
        "assembly": {
            "joined_parts_length": len(joined_parts),
            "joined_parts_sha256": full_hash(joined_parts).hex(),
            "decrypted_length": len(decrypted),
            "stripped_data_length": len(stripped_data),
            "stripped_data_sha256": full_hash(stripped_data).hex(),
            "hash_verified": hash_verified,
            "calculated_hash_hex": calculated_hash.hex(),
        },
        "receiver_state_sequence": ["TRANSFERRING", "ASSEMBLING", "COMPLETE"],
    }

    # Step 4: Proof
    proof = full_hash(stripped_data + resource_hash)
    proof_data = resource_hash + proof
    assert proof == expected_proof, "Proof doesn't match expected"

    step_4 = {
        "step": 4,
        "name": "receiver_prove",
        "proof_payload_hex": proof_data.hex(),
        "proof_payload_length": len(proof_data),
        "proof_breakdown": {
            "resource_hash_hex": resource_hash.hex(),
            "proof_hex": proof.hex(),
        },
        "proof_layout": f"resource_hash({HASHLENGTH_BYTES}) + proof({HASHLENGTH_BYTES}) = {len(proof_data)}",
        "packet_context": f"RESOURCE_PRF (0x{CONTEXT_RESOURCE_PRF:02x})",
    }

    # Step 5: Validation
    proof_valid = (
        len(proof_data) == HASHLENGTH_BYTES * 2
        and proof_data[HASHLENGTH_BYTES:] == expected_proof
    )
    assert proof_valid, "Proof validation failed"

    step_5 = {
        "step": 5,
        "name": "sender_validate_proof",
        "proof_valid": proof_valid,
        "validation": {
            "proof_data_length_check": f"len({len(proof_data)}) == HASHLENGTH_BYTES*2({HASHLENGTH_BYTES * 2})",
            "proof_hash_check": f"proof_data[{HASHLENGTH_BYTES}:] == expected_proof",
        },
        "sender_state": "COMPLETE",
        "callbacks_fired": ["completion_callback"],
    }

    # Representative parts: 0, 73, 74, 551
    rep_part_indices = [0, 73, 74, 551]
    representative_parts = []
    for pi in rep_part_indices:
        representative_parts.append({
            "part_index": pi,
            "part_data_hex": hex_prefix(parts[pi], 64),
            "part_data_length": len(parts[pi]),
            "map_hash_hex": hashmap_raw[pi * MAPHASH_LEN:(pi + 1) * MAPHASH_LEN].hex(),
        })

    reconstructed_sha256 = full_hash(stripped_data).hex()

    vector = {
        "index": 1,
        "description": "Mini resource (256KB) multi-part transfer with windowed request/response and hashmap updates",
        "input_data_length": 256000,
        "input_sha256": input_sha256,
        "encrypted_data_length": encrypted_size,
        "encrypted_data_sha256": encrypted_sha256,
        "num_parts": num_parts,
        "sdu": sdu,
        "last_part_size": last_part_size,
        "compression_attempted": True,
        "compression_used": False,
        "hashmap_by_segment": hashmap_by_segment,
        "total_hashmap_hex": hashmap_raw.hex(),
        "representative_parts": representative_parts,
        "derived_key_hex": derived_key.hex(),
        "deterministic_iv_hex": iv.hex(),
        "random_hash_hex": random_hash.hex(),
        "resource_hash_hex": resource_hash.hex(),
        "expected_proof_hex": expected_proof.hex(),
        "steps": [step_1, step_2, step_3, step_4, step_5],
        "transfer_protocol": transfer_protocol,
        "data_integrity": {
            "original_sha256": input_sha256,
            "reconstructed_sha256": reconstructed_sha256,
            "match": input_sha256 == reconstructed_sha256,
        },
        "state_machine_sequence": [
            {"side": "sender",   "event": "prepare_advertisement", "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "receiver", "event": "accept_advertisement",  "state_before": "NONE",         "state_after": "TRANSFERRING", "callback": "resource_started"},
            {"side": "receiver", "event": "request_parts",         "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": None},
            {"side": "sender",   "event": "send_parts",            "state_before": "ADVERTISED",   "state_after": "TRANSFERRING", "callback": None},
            {"side": "both",     "event": "transfer_rounds",       "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback",
             "details": f"{total_rounds} rounds, {len(hmu_packets)} HMU updates"},
            {"side": "receiver", "event": "assemble",              "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "verify_and_prove",      "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": "resource_concluded"},
            {"side": "sender",   "event": "validate_proof",        "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "completion_callback"},
        ],
    }

    return vector


def build_small_transfer_sequence(derived_key):
    """Build the 1MB (1,000,000 bytes) single-segment resource transfer sequence.

    Simulates the full windowed transfer protocol at scale:
      - 2156 parts, 30 hashmap segments, 29 HMU packets
      - ~235 transfer rounds with window growing from 4 to 10
      - Full assembly, proof, and validation
    """
    from RNS.vendor import umsgpack

    idx = 2  # Case 2: small resource, 1MB

    # --- Phase A: Prepare & encrypt ---
    print("    Generating 1MB deterministic data...")
    input_data = deterministic_data(idx, 1_000_000)
    input_sha256 = full_hash(input_data).hex()

    # Attempt compression (SHA-256 expanded data is incompressible)
    compressed_data = bz2.compress(input_data)
    compression_helps = len(compressed_data) < len(input_data)
    assert not compression_helps, "Expected incompressible data"

    random_hash = deterministic_random_hash(idx)
    iv = deterministic_iv(idx)

    data_with_metadata = input_data  # no metadata

    # Pre-encryption data: random_hash(4) + payload
    pre_encryption_data = random_hash + data_with_metadata

    # Encrypt
    print("    Encrypting 1MB data...")
    encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, iv)
    encrypted_size = len(encrypted_data)
    encrypted_sha256 = full_hash(encrypted_data).hex()

    # --- Phase B: Segment into parts & compute hashmap ---
    sdu = RESOURCE_SDU
    num_parts = int(math.ceil(encrypted_size / float(sdu)))
    assert num_parts == 2156, f"Expected 2156 parts, got {num_parts}"

    parts = []
    hashmap_raw = b""
    for i in range(num_parts):
        part_data = encrypted_data[i * sdu:(i + 1) * sdu]
        parts.append(part_data)
        map_hash = get_map_hash(part_data, random_hash)
        hashmap_raw += map_hash

    total_hashmap_bytes = len(hashmap_raw)
    assert total_hashmap_bytes == num_parts * MAPHASH_LEN

    # Verify last part size
    last_part_size = len(parts[-1])
    assert last_part_size == 144, f"Expected last part 144 bytes, got {last_part_size}"

    # Organize hashmap by segment
    num_segments = int(math.ceil(num_parts / HASHMAP_MAX_LEN))
    assert num_segments == 30, f"Expected 30 hashmap segments, got {num_segments}"

    hashmap_by_segment = []
    for seg in range(num_segments):
        seg_start = seg * HASHMAP_MAX_LEN
        seg_end = min((seg + 1) * HASHMAP_MAX_LEN, num_parts)
        seg_hash_count = seg_end - seg_start
        seg_hashmap = hashmap_raw[seg_start * MAPHASH_LEN:seg_end * MAPHASH_LEN]
        entry = {
            "segment": seg,
            "hash_count": seg_hash_count,
        }
        # Full hex for first and last segment, SHA256 for middle segments
        if seg == 0 or seg == num_segments - 1:
            entry["hashmap_hex"] = seg_hashmap.hex()
        else:
            entry["hashmap_sha256"] = full_hash(seg_hashmap).hex()
        hashmap_by_segment.append(entry)

    # --- Phase C: Compute resource hash & expected proof ---
    resource_hash = full_hash(data_with_metadata + random_hash)
    original_hash = resource_hash
    expected_proof = full_hash(data_with_metadata + resource_hash)

    # --- Phase D: Build 5-step transfer vector ---

    # Flags: encrypted=True, compressed=False, split=False
    flags = 0x01

    # Step 1: Advertisement
    adv_hashmap = hashmap_raw[:HASHMAP_MAX_LEN * MAPHASH_LEN]
    adv_dict = {
        "t": encrypted_size,
        "d": len(data_with_metadata),
        "n": num_parts,
        "h": resource_hash,
        "r": random_hash,
        "o": original_hash,
        "i": 1,
        "l": 1,
        "q": None,
        "f": flags,
        "m": adv_hashmap,
    }
    adv_packed = umsgpack.packb(adv_dict)

    step_1 = {
        "step": 1,
        "name": "sender_prepare_advertisement",
        "advertisement_packed_hex": adv_packed.hex(),
        "advertisement_packed_length": len(adv_packed),
        "advertisement_dict": {
            "t": encrypted_size,
            "d": len(data_with_metadata),
            "n": num_parts,
            "h": resource_hash.hex(),
            "r": random_hash.hex(),
            "o": original_hash.hex(),
            "i": 1,
            "l": 1,
            "q": None,
            "f": flags,
            "m": adv_hashmap.hex(),
        },
        "resource_hash_hex": resource_hash.hex(),
        "random_hash_hex": random_hash.hex(),
        "hashmap_hex": adv_hashmap.hex(),
        "num_parts": num_parts,
        "encrypted_data_length": encrypted_size,
        "flags": flags,
        "flags_hex": f"0x{flags:02x}",
        "expected_proof_hex": expected_proof.hex(),
        "sender_state_before": "QUEUED",
        "sender_state_after": "ADVERTISED",
        "packet_context": f"RESOURCE_ADV (0x{CONTEXT_RESOURCE_ADV:02x})",
    }

    # Step 2: Simulate windowed transfer protocol
    print("    Simulating 1MB transfer protocol...")
    window = WINDOW  # 4
    window_max = WINDOW_MAX_SLOW  # 10
    window_min = WINDOW_MIN  # 2
    window_flexibility = WINDOW_FLEXIBILITY  # 4
    hashmap_height = HASHMAP_MAX_LEN  # 74 hashes from advertisement
    received_count = 0
    consecutive_completed = -1
    receiver_parts = [None] * num_parts

    rounds_summary = []
    hmu_packets = []
    total_rounds = 0

    while received_count < num_parts:
        total_rounds += 1

        # --- Request phase (request_next logic) ---
        search_start = consecutive_completed + 1
        hashmap_exhausted = False
        requested_hashes = b""
        requested_indices = []
        outstanding = 0

        pn = search_start
        for _ in range(window):
            if pn >= num_parts:
                break
            if pn < hashmap_height:
                part_hash = hashmap_raw[pn * MAPHASH_LEN:(pn + 1) * MAPHASH_LEN]
                requested_hashes += part_hash
                requested_indices.append(pn)
                outstanding += 1
            else:
                hashmap_exhausted = True
                break
            pn += 1

        # Build request payload
        if hashmap_exhausted:
            hmu_flag = bytes([HASHMAP_IS_EXHAUSTED])
            last_map_hash = hashmap_raw[(hashmap_height - 1) * MAPHASH_LEN:hashmap_height * MAPHASH_LEN]
            hmu_part = hmu_flag + last_map_hash
        else:
            hmu_part = bytes([HASHMAP_IS_NOT_EXHAUSTED])

        request_payload = hmu_part + resource_hash + requested_hashes

        # --- Receive phase (sender sends parts) ---
        for pi in requested_indices:
            receiver_parts[pi] = parts[pi]
            received_count += 1
            if pi == consecutive_completed + 1:
                consecutive_completed = pi
            cp = consecutive_completed + 1
            while cp < num_parts and receiver_parts[cp] is not None:
                consecutive_completed = cp
                cp += 1

        # Build round summary
        round_info = {
            "round": total_rounds,
            "window": window,
            "parts_requested": len(requested_indices),
            "parts_requested_indices_first": requested_indices[0] if requested_indices else None,
            "parts_requested_indices_last": requested_indices[-1] if requested_indices else None,
            "received_total": received_count,
            "consecutive_completed": consecutive_completed,
            "hashmap_exhausted": hashmap_exhausted,
            "hashmap_height": hashmap_height,
        }

        # Handle HMU if hashmap exhausted
        if hashmap_exhausted:
            segment = hashmap_height // HASHMAP_MAX_LEN
            seg_start = segment * HASHMAP_MAX_LEN
            seg_end = min((segment + 1) * HASHMAP_MAX_LEN, num_parts)
            seg_hashmap = hashmap_raw[seg_start * MAPHASH_LEN:seg_end * MAPHASH_LEN]
            hmu_payload = resource_hash + umsgpack.packb([segment, seg_hashmap])

            hmu_packets.append({
                "hmu_index": len(hmu_packets),
                "triggered_at_round": total_rounds,
                "segment": segment,
                "hash_count": seg_end - seg_start,
                "payload_hex": hmu_payload.hex(),
                "payload_length": len(hmu_payload),
                "format": f"resource_hash({HASHLENGTH_BYTES}) + msgpack([segment, hashmap])",
                "packet_context": f"RESOURCE_HMU (0x{CONTEXT_RESOURCE_HMU:02x})",
            })

            round_info["hmu_segment"] = segment
            hashmap_height += (seg_end - seg_start)

        rounds_summary.append(round_info)

        # Window growth
        if window < window_max:
            window += 1
            if (window - window_min) > (window_flexibility - 1):
                window_min += 1

    assert len(hmu_packets) == 29, f"Expected 29 HMU packets, got {len(hmu_packets)}"
    assert received_count == num_parts
    print(f"    1MB transfer: {total_rounds} rounds, {len(hmu_packets)} HMU packets")

    # Representative rounds: 1, 10, 50, 100, 200, last
    rep_round_numbers = [1, 10, 50, 100, 200, total_rounds]
    representative_rounds = []
    for rn in rep_round_numbers:
        r = rounds_summary[rn - 1]
        ri_first = r["parts_requested_indices_first"]
        ri_last = r["parts_requested_indices_last"]
        rep = dict(r)
        if ri_first is not None:
            rep["first_part_hex"] = hex_prefix(parts[ri_first], 32)
            rep["first_part_length"] = len(parts[ri_first])
            rep["last_part_hex"] = hex_prefix(parts[ri_last], 32)
            rep["last_part_length"] = len(parts[ri_last])
        representative_rounds.append(rep)

    step_2 = {
        "step": 2,
        "name": "transfer_protocol_simulation",
        "total_rounds": total_rounds,
        "final_window": window,
        "initial_window": WINDOW,
        "window_max": WINDOW_MAX_SLOW,
        "receiver_state": "TRANSFERRING",
        "packet_context_req": f"RESOURCE_REQ (0x{CONTEXT_RESOURCE_REQ:02x})",
        "packet_context_data": f"RESOURCE (0x{CONTEXT_RESOURCE:02x})",
    }

    transfer_protocol = {
        "total_rounds": total_rounds,
        "initial_window": WINDOW,
        "final_window": window,
        "window_max": WINDOW_MAX_SLOW,
        "rounds_summary": rounds_summary,
        "representative_rounds": representative_rounds,
        "hmu_packets": hmu_packets,
    }

    # Step 3: Assembly
    print("    Assembling and verifying 1MB transfer...")
    joined_parts = b"".join(receiver_parts)
    assert len(joined_parts) == encrypted_size

    decrypted = token_decrypt(joined_parts, derived_key)
    stripped_data = decrypted[RANDOM_HASH_SIZE:]

    calculated_hash = full_hash(stripped_data + random_hash)
    hash_verified = calculated_hash == resource_hash
    assert hash_verified, "Assembly hash verification failed"
    assert stripped_data == input_data, "Assembled data doesn't match input"

    step_3 = {
        "step": 3,
        "name": "receiver_assemble",
        "assembly": {
            "joined_parts_length": len(joined_parts),
            "joined_parts_sha256": full_hash(joined_parts).hex(),
            "decrypted_length": len(decrypted),
            "stripped_data_length": len(stripped_data),
            "stripped_data_sha256": full_hash(stripped_data).hex(),
            "hash_verified": hash_verified,
            "calculated_hash_hex": calculated_hash.hex(),
        },
        "receiver_state_sequence": ["TRANSFERRING", "ASSEMBLING", "COMPLETE"],
    }

    # Step 4: Proof
    proof = full_hash(stripped_data + resource_hash)
    proof_data = resource_hash + proof
    assert proof == expected_proof, "Proof doesn't match expected"

    step_4 = {
        "step": 4,
        "name": "receiver_prove",
        "proof_payload_hex": proof_data.hex(),
        "proof_payload_length": len(proof_data),
        "proof_breakdown": {
            "resource_hash_hex": resource_hash.hex(),
            "proof_hex": proof.hex(),
        },
        "proof_layout": f"resource_hash({HASHLENGTH_BYTES}) + proof({HASHLENGTH_BYTES}) = {len(proof_data)}",
        "packet_context": f"RESOURCE_PRF (0x{CONTEXT_RESOURCE_PRF:02x})",
    }

    # Step 5: Validation
    proof_valid = (
        len(proof_data) == HASHLENGTH_BYTES * 2
        and proof_data[HASHLENGTH_BYTES:] == expected_proof
    )
    assert proof_valid, "Proof validation failed"

    step_5 = {
        "step": 5,
        "name": "sender_validate_proof",
        "proof_valid": proof_valid,
        "validation": {
            "proof_data_length_check": f"len({len(proof_data)}) == HASHLENGTH_BYTES*2({HASHLENGTH_BYTES * 2})",
            "proof_hash_check": f"proof_data[{HASHLENGTH_BYTES}:] == expected_proof",
        },
        "sender_state": "COMPLETE",
        "callbacks_fired": ["completion_callback"],
    }

    # Representative parts: 0, 73, 74, 1000, 2000, 2155
    rep_part_indices = [0, 73, 74, 1000, 2000, 2155]
    representative_parts = []
    for pi in rep_part_indices:
        representative_parts.append({
            "part_index": pi,
            "part_data_hex": hex_prefix(parts[pi], 64),
            "part_data_length": len(parts[pi]),
            "map_hash_hex": hashmap_raw[pi * MAPHASH_LEN:(pi + 1) * MAPHASH_LEN].hex(),
        })

    reconstructed_sha256 = full_hash(stripped_data).hex()

    vector = {
        "index": 2,
        "description": "Small resource (1MB) multi-part transfer with windowed request/response and hashmap updates",
        "input_data_length": 1_000_000,
        "input_sha256": input_sha256,
        "encrypted_data_length": encrypted_size,
        "encrypted_data_sha256": encrypted_sha256,
        "num_parts": num_parts,
        "sdu": sdu,
        "last_part_size": last_part_size,
        "compression_attempted": True,
        "compression_used": False,
        "hashmap_by_segment": hashmap_by_segment,
        "total_hashmap_sha256": full_hash(hashmap_raw).hex(),
        "representative_parts": representative_parts,
        "derived_key_hex": derived_key.hex(),
        "deterministic_iv_hex": iv.hex(),
        "random_hash_hex": random_hash.hex(),
        "resource_hash_hex": resource_hash.hex(),
        "expected_proof_hex": expected_proof.hex(),
        "steps": [step_1, step_2, step_3, step_4, step_5],
        "transfer_protocol": transfer_protocol,
        "data_integrity": {
            "original_sha256": input_sha256,
            "reconstructed_sha256": reconstructed_sha256,
            "match": input_sha256 == reconstructed_sha256,
        },
        "state_machine_sequence": [
            {"side": "sender",   "event": "prepare_advertisement", "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "receiver", "event": "accept_advertisement",  "state_before": "NONE",         "state_after": "TRANSFERRING", "callback": "resource_started"},
            {"side": "receiver", "event": "request_parts",         "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": None},
            {"side": "sender",   "event": "send_parts",            "state_before": "ADVERTISED",   "state_after": "TRANSFERRING", "callback": None},
            {"side": "both",     "event": "transfer_rounds",       "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback",
             "details": f"{total_rounds} rounds, {len(hmu_packets)} HMU updates"},
            {"side": "receiver", "event": "assemble",              "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "verify_and_prove",      "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": "resource_concluded"},
            {"side": "sender",   "event": "validate_proof",        "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "completion_callback"},
        ],
    }

    return vector


def build_medium_transfer_sequence(derived_key):
    """Build the 5MB (5,000,000 bytes) multi-segment (5 segments) resource transfer sequence.

    Simulates the full segment chaining mechanism:
      - 5 segments, each transferred independently
      - Segments 1-4: 1,048,575 bytes each, 2260 parts
      - Segment 5: 805,700 bytes, 1737 parts
      - Total: 10,777 parts across all segments
      - Each segment gets its own encryption, hashmap, resource_hash, proof
      - original_hash from segment 1 propagated to all segments
    """
    from RNS.vendor import umsgpack

    idx = 3  # Case 3: medium resource, 5MB

    # --- Phase A: Generate all 5MB of input data ---
    print("    Generating 5MB deterministic data...")
    total_data_size = 5_000_000
    input_data = deterministic_data(idx, total_data_size)
    input_sha256 = full_hash(input_data).hex()

    # --- Phase B: Compute segmentation ---
    metadata_size = 0
    total_size = total_data_size + metadata_size  # 5,000,000
    total_segments = ((total_size - 1) // MAX_EFFICIENT_SIZE) + 1
    assert total_segments == 5, f"Expected 5 segments, got {total_segments}"

    first_read_size = MAX_EFFICIENT_SIZE - metadata_size  # 1,048,575

    # Compute segment boundaries (matching Resource.py lines 297-311)
    segment_data = []
    segment_sizes = []
    for seg_idx in range(1, total_segments + 1):
        if seg_idx == 1:
            seek_position = 0
            segment_read_size = first_read_size
        else:
            seek_position = first_read_size + ((seg_idx - 2) * MAX_EFFICIENT_SIZE)
            segment_read_size = MAX_EFFICIENT_SIZE

        seg_data = input_data[seek_position:seek_position + segment_read_size]
        # Last segment may be shorter
        if seg_idx == total_segments:
            seg_data = input_data[seek_position:]
        segment_data.append(seg_data)
        segment_sizes.append(len(seg_data))

    # Verify segmentation
    assert sum(segment_sizes) == total_data_size, \
        f"Segment sizes sum {sum(segment_sizes)} != {total_data_size}"
    assert segment_sizes == [1_048_575, 1_048_575, 1_048_575, 1_048_575, 805_700], \
        f"Unexpected segment sizes: {segment_sizes}"
    assert b"".join(segment_data) == input_data, "Segmented data doesn't reconstruct input"

    # --- Phase C: Process each segment ---
    print("    Processing 5 segments...")
    segments_output = []
    original_hash = None  # Set from segment 1
    split = True
    flags = 0x05  # encrypted=True, split=True

    for seg_idx in range(1, total_segments + 1):
        seg_data_bytes = segment_data[seg_idx - 1]
        data_with_metadata = seg_data_bytes  # no metadata

        # Per-segment deterministic crypto
        seg_random_hash = deterministic_random_hash(300 + seg_idx - 1)
        seg_iv = deterministic_iv(300 + seg_idx - 1)

        # Pre-encryption data: random_hash(4) + payload
        pre_encryption_data = seg_random_hash + data_with_metadata

        # Encrypt
        print(f"      Encrypting segment {seg_idx} ({len(seg_data_bytes)} bytes)...")
        encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, seg_iv)
        encrypted_size = len(encrypted_data)
        encrypted_sha256 = full_hash(encrypted_data).hex()

        # Segment into parts
        sdu = RESOURCE_SDU
        num_parts = int(math.ceil(encrypted_size / float(sdu)))

        parts = []
        hashmap_raw = b""
        for i in range(num_parts):
            part_data = encrypted_data[i * sdu:(i + 1) * sdu]
            parts.append(part_data)
            map_hash = get_map_hash(part_data, seg_random_hash)
            hashmap_raw += map_hash

        last_part_size = len(parts[-1])

        # Hashmap segments
        num_hashmap_segments = int(math.ceil(num_parts / HASHMAP_MAX_LEN))

        hashmap_summary = {
            "total_hashmap_sha256": full_hash(hashmap_raw).hex(),
            "num_hashmap_segments": num_hashmap_segments,
        }
        if num_hashmap_segments > 0:
            # First segment hashmap detail
            first_seg_end = min(HASHMAP_MAX_LEN, num_parts)
            first_seg_hashmap = hashmap_raw[:first_seg_end * MAPHASH_LEN]
            hashmap_summary["first_segment_hash_count"] = first_seg_end
            # Last segment hashmap detail
            last_seg_start = (num_hashmap_segments - 1) * HASHMAP_MAX_LEN
            last_seg_end = num_parts
            last_seg_hash_count = last_seg_end - last_seg_start
            hashmap_summary["last_segment_hash_count"] = last_seg_hash_count

        # Compute resource hash & expected proof
        resource_hash = full_hash(data_with_metadata + seg_random_hash)
        expected_proof = full_hash(data_with_metadata + resource_hash)

        # Set original_hash from segment 1
        if seg_idx == 1:
            original_hash = resource_hash

        # Build advertisement dict for this segment
        adv_hashmap = hashmap_raw[:HASHMAP_MAX_LEN * MAPHASH_LEN]
        adv_dict = {
            "t": encrypted_size,
            "d": total_size,  # Always the full file size
            "n": num_parts,
            "h": resource_hash,
            "r": seg_random_hash,
            "o": original_hash,
            "i": seg_idx,
            "l": total_segments,
            "q": None,
            "f": flags,
            "m": adv_hashmap,
        }

        # --- Transfer simulation ---
        print(f"      Simulating segment {seg_idx} transfer ({num_parts} parts)...")
        window = WINDOW  # 4, cold-start each segment
        window_max = WINDOW_MAX_SLOW  # 10
        window_min = WINDOW_MIN  # 2
        window_flexibility = WINDOW_FLEXIBILITY  # 4
        hashmap_height = HASHMAP_MAX_LEN
        received_count = 0
        consecutive_completed = -1
        receiver_parts = [None] * num_parts

        rounds_summary = []
        hmu_packets_seg = []
        seg_total_rounds = 0

        while received_count < num_parts:
            seg_total_rounds += 1

            # Request phase
            search_start = consecutive_completed + 1
            hashmap_exhausted = False
            requested_hashes = b""
            requested_indices = []

            pn = search_start
            for _ in range(window):
                if pn >= num_parts:
                    break
                if pn < hashmap_height:
                    part_hash = hashmap_raw[pn * MAPHASH_LEN:(pn + 1) * MAPHASH_LEN]
                    requested_hashes += part_hash
                    requested_indices.append(pn)
                else:
                    hashmap_exhausted = True
                    break
                pn += 1

            # Receive phase
            for pi in requested_indices:
                receiver_parts[pi] = parts[pi]
                received_count += 1
                if pi == consecutive_completed + 1:
                    consecutive_completed = pi
                cp = consecutive_completed + 1
                while cp < num_parts and receiver_parts[cp] is not None:
                    consecutive_completed = cp
                    cp += 1

            round_info = {
                "round": seg_total_rounds,
                "window": window,
                "parts_requested": len(requested_indices),
                "parts_requested_indices_first": requested_indices[0] if requested_indices else None,
                "parts_requested_indices_last": requested_indices[-1] if requested_indices else None,
                "received_total": received_count,
                "consecutive_completed": consecutive_completed,
                "hashmap_exhausted": hashmap_exhausted,
                "hashmap_height": hashmap_height,
            }

            # Handle HMU
            if hashmap_exhausted:
                hm_segment = hashmap_height // HASHMAP_MAX_LEN
                hm_seg_start = hm_segment * HASHMAP_MAX_LEN
                hm_seg_end = min((hm_segment + 1) * HASHMAP_MAX_LEN, num_parts)
                seg_hashmap_data = hashmap_raw[hm_seg_start * MAPHASH_LEN:hm_seg_end * MAPHASH_LEN]
                hmu_payload = resource_hash + umsgpack.packb([hm_segment, seg_hashmap_data])

                hmu_packets_seg.append({
                    "hmu_index": len(hmu_packets_seg),
                    "triggered_at_round": seg_total_rounds,
                    "segment": hm_segment,
                    "hash_count": hm_seg_end - hm_seg_start,
                    "payload_length": len(hmu_payload),
                    "packet_context": f"RESOURCE_HMU (0x{CONTEXT_RESOURCE_HMU:02x})",
                })

                round_info["hmu_segment"] = hm_segment
                hashmap_height += (hm_seg_end - hm_seg_start)

            rounds_summary.append(round_info)

            # Window growth
            if window < window_max:
                window += 1
                if (window - window_min) > (window_flexibility - 1):
                    window_min += 1

        assert received_count == num_parts
        print(f"      Segment {seg_idx}: {seg_total_rounds} rounds, {len(hmu_packets_seg)} HMU packets")

        # Assembly verification
        joined_parts = b"".join(receiver_parts)
        assert len(joined_parts) == encrypted_size

        decrypted = token_decrypt(joined_parts, derived_key)
        stripped_data = decrypted[RANDOM_HASH_SIZE:]

        calculated_hash = full_hash(stripped_data + seg_random_hash)
        hash_verified = calculated_hash == resource_hash
        assert hash_verified, f"Segment {seg_idx}: assembly hash verification failed"
        assert stripped_data == data_with_metadata, f"Segment {seg_idx}: assembled data doesn't match"

        # Proof
        proof = full_hash(stripped_data + resource_hash)
        proof_data = resource_hash + proof
        assert proof == expected_proof, f"Segment {seg_idx}: proof doesn't match expected"

        proof_valid = (
            len(proof_data) == HASHLENGTH_BYTES * 2
            and proof_data[HASHLENGTH_BYTES:] == expected_proof
        )
        assert proof_valid, f"Segment {seg_idx}: proof validation failed"

        # Build segment output
        is_detail_segment = (seg_idx == 1 or seg_idx == total_segments)

        # Representative rounds for detail segments
        if is_detail_segment:
            rep_round_numbers = [1, 10, 50, 100, min(200, seg_total_rounds), seg_total_rounds]
            # Deduplicate while preserving order
            seen = set()
            rep_round_numbers = [x for x in rep_round_numbers if not (x in seen or seen.add(x))]
            rep_rounds = []
            for rn in rep_round_numbers:
                r = rounds_summary[rn - 1]
                ri_first = r["parts_requested_indices_first"]
                ri_last = r["parts_requested_indices_last"]
                rep = dict(r)
                if ri_first is not None:
                    rep["first_part_hex"] = hex_prefix(parts[ri_first], 32)
                    rep["first_part_length"] = len(parts[ri_first])
                    rep["last_part_hex"] = hex_prefix(parts[ri_last], 32)
                    rep["last_part_length"] = len(parts[ri_last])
                rep_rounds.append(rep)

        seg_output = {
            "segment_index": seg_idx,
            "segment_data_length": len(seg_data_bytes),
            "segment_data_sha256": full_hash(seg_data_bytes).hex(),
            "encrypted_data_length": encrypted_size,
            "encrypted_data_sha256": encrypted_sha256,
            "num_parts": num_parts,
            "last_part_size": last_part_size,
            "random_hash_hex": seg_random_hash.hex(),
            "deterministic_iv_hex": seg_iv.hex(),
            "resource_hash_hex": resource_hash.hex(),
            "expected_proof_hex": expected_proof.hex(),
            "hashmap_summary": hashmap_summary,
            "transfer_protocol": {
                "total_rounds": seg_total_rounds,
                "initial_window": WINDOW,
                "final_window": window,
                "window_max": WINDOW_MAX_SLOW,
                "hmu_count": len(hmu_packets_seg),
            },
            "assembly": {
                "joined_parts_length": len(joined_parts),
                "joined_parts_sha256": full_hash(joined_parts).hex(),
                "decrypted_length": len(decrypted),
                "stripped_data_length": len(stripped_data),
                "stripped_data_sha256": full_hash(stripped_data).hex(),
                "hash_verified": hash_verified,
            },
            "proof": {
                "proof_payload_hex": proof_data.hex(),
                "proof_valid": proof_valid,
            },
            "advertisement_dict": {
                "t": encrypted_size,
                "d": total_size,
                "n": num_parts,
                "h": resource_hash.hex(),
                "r": seg_random_hash.hex(),
                "o": original_hash.hex(),
                "i": seg_idx,
                "l": total_segments,
                "q": None,
                "f": flags,
            },
        }

        # Add detail for segments 1 and 5
        if is_detail_segment:
            seg_output["transfer_protocol"]["rounds_summary"] = rounds_summary
            seg_output["transfer_protocol"]["representative_rounds"] = rep_rounds
            seg_output["transfer_protocol"]["hmu_packets"] = hmu_packets_seg

        segments_output.append(seg_output)

    # --- Phase D: Cross-segment verification ---
    reconstructed_data = b"".join(segment_data)
    assert reconstructed_data == input_data, "Cross-segment reconstruction failed"

    vector = {
        "index": 3,
        "description": "Medium resource (5MB) multi-segment (5 segments) transfer with segment chaining",
        "input_data_length": total_data_size,
        "input_sha256": input_sha256,
        "total_segments": total_segments,
        "split": split,
        "flags": flags,
        "flags_hex": f"0x{flags:02x}",
        "original_hash_hex": original_hash.hex(),
        "derived_key_hex": derived_key.hex(),
        "segment_sizes": segment_sizes,
        "segments": segments_output,
        "cross_segment_verification": {
            "reconstructed_input_sha256": full_hash(reconstructed_data).hex(),
            "match": full_hash(reconstructed_data).hex() == input_sha256,
        },
        "state_machine_sequence": [
            {"side": "sender",   "event": "prepare_segment_1",     "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "receiver", "event": "accept_advertisement",  "state_before": "NONE",         "state_after": "TRANSFERRING", "callback": "resource_started"},
            {"side": "both",     "event": "transfer_segment_1",    "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback"},
            {"side": "receiver", "event": "assemble_segment_1",    "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "prove_segment_1",       "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": None},
            {"side": "sender",   "event": "validate_proof_1",      "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": None,
             "details": "Triggers next segment advertisement"},
            {"side": "sender",   "event": "advertise_segment_2",   "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "both",     "event": "transfer_segments_2_4", "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "progress_callback",
             "details": "Segments 2-4 follow same pattern as segment 1"},
            {"side": "sender",   "event": "advertise_segment_5",   "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "both",     "event": "transfer_segment_5",    "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback"},
            {"side": "receiver", "event": "assemble_segment_5",    "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "prove_segment_5",       "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": None},
            {"side": "sender",   "event": "validate_proof_5",      "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "completion_callback",
             "details": "Last segment, triggers completion_callback"},
        ],
    }

    return vector


def build_large_transfer_sequence(derived_key):
    """Build the 50MB (50,000,000 bytes) multi-segment (48 segments) resource transfer sequence.

    Simulates a sustained large transfer to stress-test windowing, memory management,
    and throughput:
      - 48 segments, each transferred independently
      - Segments 1-47: 1,048,575 bytes each, 2260 parts
      - Segment 48: 716,975 bytes, 1546 parts
      - Total: ~107,766 parts across all segments
      - Each segment gets its own encryption, hashmap, resource_hash, proof
      - original_hash from segment 1 propagated to all segments
      - Detail segments: 1, 24, 48 (start, midpoint, end)
    """
    import time
    from RNS.vendor import umsgpack

    idx = 4  # Case 4: large resource, 50MB

    # --- Phase A: Generate all 50MB of input data ---
    print("    Generating 50MB deterministic data...")
    t0 = time.time()
    total_data_size = 50_000_000
    input_data = deterministic_data(idx, total_data_size)
    input_sha256 = full_hash(input_data).hex()
    print(f"    Data generated in {time.time() - t0:.1f}s")

    # --- Phase B: Compute segmentation ---
    metadata_size = 0
    total_size = total_data_size + metadata_size  # 50,000,000
    total_segments = ((total_size - 1) // MAX_EFFICIENT_SIZE) + 1
    assert total_segments == 48, f"Expected 48 segments, got {total_segments}"

    first_read_size = MAX_EFFICIENT_SIZE - metadata_size  # 1,048,575

    # Compute segment boundaries (matching Resource.py lines 297-311)
    segment_data = []
    segment_sizes = []
    for seg_idx in range(1, total_segments + 1):
        if seg_idx == 1:
            seek_position = 0
            segment_read_size = first_read_size
        else:
            seek_position = first_read_size + ((seg_idx - 2) * MAX_EFFICIENT_SIZE)
            segment_read_size = MAX_EFFICIENT_SIZE

        seg_data = input_data[seek_position:seek_position + segment_read_size]
        # Last segment may be shorter
        if seg_idx == total_segments:
            seg_data = input_data[seek_position:]
        segment_data.append(seg_data)
        segment_sizes.append(len(seg_data))

    # Verify segmentation
    assert sum(segment_sizes) == total_data_size, \
        f"Segment sizes sum {sum(segment_sizes)} != {total_data_size}"
    expected_sizes = [1_048_575] * 47 + [716_975]
    assert segment_sizes == expected_sizes, \
        f"Unexpected segment sizes: first={segment_sizes[0]}, last={segment_sizes[-1]}"
    assert b"".join(segment_data) == input_data, "Segmented data doesn't reconstruct input"

    # --- Phase C: Process each segment ---
    print(f"    Processing {total_segments} segments...")
    segments_output = []
    original_hash = None  # Set from segment 1
    split = True
    flags = 0x05  # encrypted=True, split=True
    detail_segments = {1, 24, 48}

    total_parts_all = 0
    total_rounds_all = 0

    for seg_idx in range(1, total_segments + 1):
        seg_t0 = time.time()
        seg_data_bytes = segment_data[seg_idx - 1]
        data_with_metadata = seg_data_bytes  # no metadata

        # Per-segment deterministic crypto
        seg_random_hash = deterministic_random_hash(400 + seg_idx - 1)
        seg_iv = deterministic_iv(400 + seg_idx - 1)

        # Pre-encryption data: random_hash(4) + payload
        pre_encryption_data = seg_random_hash + data_with_metadata

        # Encrypt
        encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, seg_iv)
        encrypted_size = len(encrypted_data)
        encrypted_sha256 = full_hash(encrypted_data).hex()

        # Segment into parts
        sdu = RESOURCE_SDU
        num_parts = int(math.ceil(encrypted_size / float(sdu)))

        parts = []
        hashmap_raw = b""
        for i in range(num_parts):
            part_data = encrypted_data[i * sdu:(i + 1) * sdu]
            parts.append(part_data)
            map_hash = get_map_hash(part_data, seg_random_hash)
            hashmap_raw += map_hash

        last_part_size = len(parts[-1])

        # Hashmap segments
        num_hashmap_segments = int(math.ceil(num_parts / HASHMAP_MAX_LEN))

        hashmap_summary = {
            "total_hashmap_sha256": full_hash(hashmap_raw).hex(),
            "num_hashmap_segments": num_hashmap_segments,
        }
        if num_hashmap_segments > 0:
            # First segment hashmap detail
            first_seg_end = min(HASHMAP_MAX_LEN, num_parts)
            first_seg_hashmap = hashmap_raw[:first_seg_end * MAPHASH_LEN]
            hashmap_summary["first_segment_hash_count"] = first_seg_end
            # Last segment hashmap detail
            last_seg_start = (num_hashmap_segments - 1) * HASHMAP_MAX_LEN
            last_seg_end = num_parts
            last_seg_hash_count = last_seg_end - last_seg_start
            hashmap_summary["last_segment_hash_count"] = last_seg_hash_count

        # Compute resource hash & expected proof
        resource_hash = full_hash(data_with_metadata + seg_random_hash)
        expected_proof = full_hash(data_with_metadata + resource_hash)

        # Set original_hash from segment 1
        if seg_idx == 1:
            original_hash = resource_hash

        # Build advertisement dict for this segment
        adv_hashmap = hashmap_raw[:HASHMAP_MAX_LEN * MAPHASH_LEN]
        adv_dict = {
            "t": encrypted_size,
            "d": total_size,  # Always the full file size
            "n": num_parts,
            "h": resource_hash,
            "r": seg_random_hash,
            "o": original_hash,
            "i": seg_idx,
            "l": total_segments,
            "q": None,
            "f": flags,
            "m": adv_hashmap,
        }

        # --- Transfer simulation ---
        window = WINDOW  # 4, cold-start each segment
        window_max = WINDOW_MAX_SLOW  # 10
        window_min = WINDOW_MIN  # 2
        window_flexibility = WINDOW_FLEXIBILITY  # 4
        hashmap_height = HASHMAP_MAX_LEN
        received_count = 0
        consecutive_completed = -1
        receiver_parts = [None] * num_parts

        rounds_summary = []
        hmu_packets_seg = []
        seg_total_rounds = 0

        while received_count < num_parts:
            seg_total_rounds += 1

            # Request phase
            search_start = consecutive_completed + 1
            hashmap_exhausted = False
            requested_hashes = b""
            requested_indices = []

            pn = search_start
            for _ in range(window):
                if pn >= num_parts:
                    break
                if pn < hashmap_height:
                    part_hash = hashmap_raw[pn * MAPHASH_LEN:(pn + 1) * MAPHASH_LEN]
                    requested_hashes += part_hash
                    requested_indices.append(pn)
                else:
                    hashmap_exhausted = True
                    break
                pn += 1

            # Receive phase
            for pi in requested_indices:
                receiver_parts[pi] = parts[pi]
                received_count += 1
                if pi == consecutive_completed + 1:
                    consecutive_completed = pi
                cp = consecutive_completed + 1
                while cp < num_parts and receiver_parts[cp] is not None:
                    consecutive_completed = cp
                    cp += 1

            round_info = {
                "round": seg_total_rounds,
                "window": window,
                "parts_requested": len(requested_indices),
                "parts_requested_indices_first": requested_indices[0] if requested_indices else None,
                "parts_requested_indices_last": requested_indices[-1] if requested_indices else None,
                "received_total": received_count,
                "consecutive_completed": consecutive_completed,
                "hashmap_exhausted": hashmap_exhausted,
                "hashmap_height": hashmap_height,
            }

            # Handle HMU
            if hashmap_exhausted:
                hm_segment = hashmap_height // HASHMAP_MAX_LEN
                hm_seg_start = hm_segment * HASHMAP_MAX_LEN
                hm_seg_end = min((hm_segment + 1) * HASHMAP_MAX_LEN, num_parts)
                seg_hashmap_data = hashmap_raw[hm_seg_start * MAPHASH_LEN:hm_seg_end * MAPHASH_LEN]
                hmu_payload = resource_hash + umsgpack.packb([hm_segment, seg_hashmap_data])

                hmu_packets_seg.append({
                    "hmu_index": len(hmu_packets_seg),
                    "triggered_at_round": seg_total_rounds,
                    "segment": hm_segment,
                    "hash_count": hm_seg_end - hm_seg_start,
                    "payload_length": len(hmu_payload),
                    "packet_context": f"RESOURCE_HMU (0x{CONTEXT_RESOURCE_HMU:02x})",
                })

                round_info["hmu_segment"] = hm_segment
                hashmap_height += (hm_seg_end - hm_seg_start)

            rounds_summary.append(round_info)

            # Window growth
            if window < window_max:
                window += 1
                if (window - window_min) > (window_flexibility - 1):
                    window_min += 1

        assert received_count == num_parts
        total_parts_all += num_parts
        total_rounds_all += seg_total_rounds
        seg_elapsed = time.time() - seg_t0
        print(f"      Segment {seg_idx}/{total_segments}: {num_parts} parts, "
              f"{seg_total_rounds} rounds, {len(hmu_packets_seg)} HMU — {seg_elapsed:.1f}s")

        # Assembly verification
        joined_parts = b"".join(receiver_parts)
        assert len(joined_parts) == encrypted_size

        decrypted = token_decrypt(joined_parts, derived_key)
        stripped_data = decrypted[RANDOM_HASH_SIZE:]

        calculated_hash = full_hash(stripped_data + seg_random_hash)
        hash_verified = calculated_hash == resource_hash
        assert hash_verified, f"Segment {seg_idx}: assembly hash verification failed"
        assert stripped_data == data_with_metadata, f"Segment {seg_idx}: assembled data doesn't match"

        # Proof
        proof = full_hash(stripped_data + resource_hash)
        proof_data = resource_hash + proof
        assert proof == expected_proof, f"Segment {seg_idx}: proof doesn't match expected"

        proof_valid = (
            len(proof_data) == HASHLENGTH_BYTES * 2
            and proof_data[HASHLENGTH_BYTES:] == expected_proof
        )
        assert proof_valid, f"Segment {seg_idx}: proof validation failed"

        # Build segment output
        is_detail_segment = (seg_idx in detail_segments)

        # Representative rounds for detail segments
        if is_detail_segment:
            rep_round_numbers = [1, 10, 50, 100, min(200, seg_total_rounds), seg_total_rounds]
            # Deduplicate while preserving order
            seen = set()
            rep_round_numbers = [x for x in rep_round_numbers if not (x in seen or seen.add(x))]
            rep_rounds = []
            for rn in rep_round_numbers:
                r = rounds_summary[rn - 1]
                ri_first = r["parts_requested_indices_first"]
                ri_last = r["parts_requested_indices_last"]
                rep = dict(r)
                if ri_first is not None:
                    rep["first_part_hex"] = hex_prefix(parts[ri_first], 32)
                    rep["first_part_length"] = len(parts[ri_first])
                    rep["last_part_hex"] = hex_prefix(parts[ri_last], 32)
                    rep["last_part_length"] = len(parts[ri_last])
                rep_rounds.append(rep)

        seg_output = {
            "segment_index": seg_idx,
            "segment_data_length": len(seg_data_bytes),
            "segment_data_sha256": full_hash(seg_data_bytes).hex(),
            "encrypted_data_length": encrypted_size,
            "encrypted_data_sha256": encrypted_sha256,
            "num_parts": num_parts,
            "last_part_size": last_part_size,
            "random_hash_hex": seg_random_hash.hex(),
            "deterministic_iv_hex": seg_iv.hex(),
            "resource_hash_hex": resource_hash.hex(),
            "expected_proof_hex": expected_proof.hex(),
            "hashmap_summary": hashmap_summary,
            "transfer_protocol": {
                "total_rounds": seg_total_rounds,
                "initial_window": WINDOW,
                "final_window": window,
                "window_max": WINDOW_MAX_SLOW,
                "hmu_count": len(hmu_packets_seg),
            },
            "assembly": {
                "joined_parts_length": len(joined_parts),
                "joined_parts_sha256": full_hash(joined_parts).hex(),
                "decrypted_length": len(decrypted),
                "stripped_data_length": len(stripped_data),
                "stripped_data_sha256": full_hash(stripped_data).hex(),
                "hash_verified": hash_verified,
            },
            "proof": {
                "proof_payload_hex": proof_data.hex(),
                "proof_valid": proof_valid,
            },
            "advertisement_dict": {
                "t": encrypted_size,
                "d": total_size,
                "n": num_parts,
                "h": resource_hash.hex(),
                "r": seg_random_hash.hex(),
                "o": original_hash.hex(),
                "i": seg_idx,
                "l": total_segments,
                "q": None,
                "f": flags,
            },
        }

        # Add detail for segments 1, 24, and 48
        if is_detail_segment:
            seg_output["transfer_protocol"]["rounds_summary"] = rounds_summary
            seg_output["transfer_protocol"]["representative_rounds"] = rep_rounds
            seg_output["transfer_protocol"]["hmu_packets"] = hmu_packets_seg

        segments_output.append(seg_output)

    # --- Phase D: Cross-segment verification ---
    reconstructed_data = b"".join(segment_data)
    assert reconstructed_data == input_data, "Cross-segment reconstruction failed"

    print(f"    Total: {total_parts_all} parts, {total_rounds_all} rounds across {total_segments} segments")

    vector = {
        "index": 4,
        "description": "Large resource (50MB) multi-segment (48 segments) transfer with sustained windowing",
        "input_data_length": total_data_size,
        "input_sha256": input_sha256,
        "total_segments": total_segments,
        "split": split,
        "flags": flags,
        "flags_hex": f"0x{flags:02x}",
        "original_hash_hex": original_hash.hex(),
        "derived_key_hex": derived_key.hex(),
        "segment_sizes": segment_sizes,
        "aggregate_stats": {
            "total_parts": total_parts_all,
            "total_rounds": total_rounds_all,
            "detail_segments": sorted(detail_segments),
            "summary_segments": [i for i in range(1, total_segments + 1) if i not in detail_segments],
        },
        "segments": segments_output,
        "cross_segment_verification": {
            "reconstructed_input_sha256": full_hash(reconstructed_data).hex(),
            "match": full_hash(reconstructed_data).hex() == input_sha256,
        },
        "state_machine_sequence": [
            {"side": "sender",   "event": "prepare_segment_1",      "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "receiver", "event": "accept_advertisement",   "state_before": "NONE",         "state_after": "TRANSFERRING", "callback": "resource_started"},
            {"side": "both",     "event": "transfer_segment_1",     "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback"},
            {"side": "receiver", "event": "assemble_segment_1",     "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "prove_segment_1",        "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": None},
            {"side": "sender",   "event": "validate_proof_1",       "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": None,
             "details": "Triggers next segment advertisement"},
            {"side": "sender",   "event": "advertise_segment_2",    "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "both",     "event": "transfer_segments_2_47", "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "progress_callback",
             "details": "Segments 2-47 follow same pattern as segment 1"},
            {"side": "sender",   "event": "advertise_segment_48",   "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "both",     "event": "transfer_segment_48",    "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback"},
            {"side": "receiver", "event": "assemble_segment_48",    "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "prove_segment_48",       "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": None},
            {"side": "sender",   "event": "validate_proof_48",      "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "completion_callback",
             "details": "Last segment, triggers completion_callback"},
        ],
    }

    return vector


def deterministic_compressible_data(index, length):
    """Generate deterministic, highly compressible data of given length.

    Uses a repeating pattern seeded by index, matching the approach in
    extract_resources.py for compressible resource cases.
    """
    pattern = b"RETICULUM_TEST_PATTERN_" + str(index).encode() + b"_"
    return (pattern * ((length // len(pattern)) + 1))[:length]


def build_metadata_transfer_sequence(derived_key):
    """Build micro resource (128B) transfer with metadata (flags=0x21).

    Simulates the 5-step exchange with metadata encoding:
      1. Sender prepares advertisement (with metadata)
      2. Receiver accepts & requests parts
      3. Sender sends part
      4. Receiver assembles, verifies, extracts metadata, and proves
      5. Sender validates proof
    """
    from RNS.vendor import umsgpack

    idx = 100  # Avoids collisions with existing 0-4, 99, 300+, 400+

    # --- Input data ---
    input_data = deterministic_data(idx, 128)
    input_sha256 = full_hash(input_data).hex()

    # --- Metadata ---
    metadata_dict = {"filename": "test.bin", "size": 128}
    packed_metadata = umsgpack.packb(metadata_dict)
    metadata_size = len(packed_metadata)
    metadata_bytes = struct.pack(">I", metadata_size)[1:] + packed_metadata

    # --- Step 1: Sender prepares advertisement ---
    random_hash = deterministic_random_hash(idx)
    iv = deterministic_iv(idx)

    # Combine metadata + payload
    data_with_metadata = metadata_bytes + input_data
    total_size = len(data_with_metadata)

    # Attempt compression (incompressible data + small metadata = no benefit)
    compressed_data = bz2.compress(data_with_metadata)
    compressed = len(compressed_data) < len(data_with_metadata)
    if compressed:
        payload_after_compress = compressed_data
    else:
        payload_after_compress = data_with_metadata

    # Pre-encryption data: random_hash(4) + payload
    pre_encryption_data = random_hash + payload_after_compress

    # Encrypt
    encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, iv)
    encrypted_size = len(encrypted_data)

    # Segment into parts
    sdu = RESOURCE_SDU
    num_parts = int(math.ceil(encrypted_size / float(sdu)))

    # Build parts and hashmap
    parts = []
    hashmap = b""
    for i in range(num_parts):
        part_data = encrypted_data[i * sdu:(i + 1) * sdu]
        parts.append(part_data)
        map_hash = get_map_hash(part_data, random_hash)
        hashmap += map_hash

    # Compute hashes
    resource_hash = full_hash(data_with_metadata + random_hash)
    original_hash = resource_hash
    expected_proof = full_hash(data_with_metadata + resource_hash)

    # Flags: encrypted=True, compressed=compressed, has_metadata=True
    flags = (1 << 5) | (int(compressed) << 1) | 1  # 0x21 if not compressed, 0x23 if compressed

    # Build advertisement dict
    hashmap_for_adv = hashmap[:HASHMAP_MAX_LEN * MAPHASH_LEN]
    adv_dict = {
        "t": encrypted_size,
        "d": total_size,
        "n": num_parts,
        "h": resource_hash,
        "r": random_hash,
        "o": original_hash,
        "i": 1,
        "l": 1,
        "q": None,
        "f": flags,
        "m": hashmap_for_adv,
    }
    adv_packed = umsgpack.packb(adv_dict)

    step_1 = {
        "step": 1,
        "name": "sender_prepare_advertisement",
        "advertisement_packed_hex": adv_packed.hex(),
        "advertisement_packed_length": len(adv_packed),
        "advertisement_dict": {
            "t": encrypted_size,
            "d": total_size,
            "n": num_parts,
            "h": resource_hash.hex(),
            "r": random_hash.hex(),
            "o": original_hash.hex(),
            "i": 1,
            "l": 1,
            "q": None,
            "f": flags,
            "m": hashmap_for_adv.hex(),
        },
        "resource_hash_hex": resource_hash.hex(),
        "random_hash_hex": random_hash.hex(),
        "hashmap_hex": hashmap_for_adv.hex(),
        "num_parts": num_parts,
        "encrypted_data_length": encrypted_size,
        "flags": flags,
        "flags_hex": f"0x{flags:02x}",
        "expected_proof_hex": expected_proof.hex(),
        "metadata_dict": metadata_dict,
        "packed_metadata_hex": packed_metadata.hex(),
        "metadata_bytes_hex": metadata_bytes.hex(),
        "sender_state_before": "QUEUED",
        "sender_state_after": "ADVERTISED",
        "packet_context": f"RESOURCE_ADV (0x{CONTEXT_RESOURCE_ADV:02x})",
    }

    # --- Step 2: Receiver accepts & requests parts ---
    first_map_hash = hashmap[:MAPHASH_LEN]
    hashmap_exhausted_flag = bytes([HASHMAP_IS_NOT_EXHAUSTED])
    request_payload = hashmap_exhausted_flag + resource_hash
    for i in range(min(num_parts, WINDOW)):
        request_payload += hashmap[i * MAPHASH_LEN:(i + 1) * MAPHASH_LEN]

    step_2 = {
        "step": 2,
        "name": "receiver_request_parts",
        "request_payload_hex": request_payload.hex(),
        "request_payload_length": len(request_payload),
        "receiver_state": "TRANSFERRING",
        "callbacks_fired": ["resource_started"],
        "packet_context": f"RESOURCE_REQ (0x{CONTEXT_RESOURCE_REQ:02x})",
    }

    # --- Step 3: Sender sends parts ---
    step_3_parts = []
    for i in range(num_parts):
        step_3_parts.append({
            "part_index": i,
            "part_data_hex": hex_prefix(parts[i], 64),
            "part_data_length": len(parts[i]),
            "map_hash_hex": hashmap[i * MAPHASH_LEN:(i + 1) * MAPHASH_LEN].hex(),
        })

    step_3 = {
        "step": 3,
        "name": "sender_send_parts",
        "parts": step_3_parts,
        "sender_state": "TRANSFERRING",
        "packet_context": f"RESOURCE (0x{CONTEXT_RESOURCE:02x})",
    }

    # --- Step 4: Receiver assembles & proves ---
    joined_parts = b"".join(parts)
    decrypted = token_decrypt(joined_parts, derived_key)
    stripped_data = decrypted[RANDOM_HASH_SIZE:]

    # Decompress if flagged
    if compressed:
        decompressed_data = bz2.decompress(stripped_data)
    else:
        decompressed_data = stripped_data

    # Verify hash
    calculated_hash = full_hash(decompressed_data + random_hash)
    hash_verified = calculated_hash == resource_hash
    assert hash_verified, "Assembly hash verification failed for metadata transfer"

    # Extract metadata
    meta_size = decompressed_data[0] << 16 | decompressed_data[1] << 8 | decompressed_data[2]
    packed_meta_extracted = decompressed_data[3:3 + meta_size]
    extracted_metadata = umsgpack.unpackb(packed_meta_extracted)
    extracted_payload = decompressed_data[3 + meta_size:]

    assert extracted_payload == input_data, "Assembled payload doesn't match input"
    assert extracted_metadata == metadata_dict, "Extracted metadata doesn't match"

    # Build proof
    proof = full_hash(decompressed_data + resource_hash)
    proof_data = resource_hash + proof
    assert proof == expected_proof, "Proof doesn't match expected"

    step_4 = {
        "step": 4,
        "name": "receiver_assemble_and_prove",
        "assembly": {
            "joined_parts_hex": hex_prefix(joined_parts, 64),
            "joined_parts_length": len(joined_parts),
            "decrypted_hex": hex_prefix(decrypted, 64),
            "decrypted_length": len(decrypted),
            "stripped_data_hex": hex_prefix(stripped_data, 64),
            "stripped_data_length": len(stripped_data),
            "decompressed": compressed,
            "decompressed_data_length": len(decompressed_data) if compressed else None,
            "hash_verified": hash_verified,
            "calculated_hash_hex": calculated_hash.hex(),
        },
        "metadata_extraction": {
            "metadata_size": meta_size,
            "extracted_metadata": extracted_metadata,
            "extracted_payload_hex": hex_prefix(extracted_payload, 64),
            "extracted_payload_length": len(extracted_payload),
        },
        "proof_payload_hex": proof_data.hex(),
        "proof_payload_length": len(proof_data),
        "proof_breakdown": {
            "resource_hash_hex": resource_hash.hex(),
            "proof_hex": proof.hex(),
        },
        "receiver_state_sequence": ["TRANSFERRING", "ASSEMBLING", "COMPLETE"],
        "callbacks_fired": ["progress_callback", "resource_concluded"],
        "packet_context": f"RESOURCE_PRF (0x{CONTEXT_RESOURCE_PRF:02x})",
    }

    # --- Step 5: Sender validates proof ---
    proof_valid = (
        len(proof_data) == HASHLENGTH_BYTES * 2
        and proof_data[HASHLENGTH_BYTES:] == expected_proof
    )
    assert proof_valid, "Proof validation failed"

    step_5 = {
        "step": 5,
        "name": "sender_validate_proof",
        "proof_valid": proof_valid,
        "sender_state": "COMPLETE",
        "callbacks_fired": ["completion_callback"],
    }

    reconstructed_sha256 = full_hash(extracted_payload).hex()

    vector = {
        "index": 5,
        "description": "Micro resource (128B) with metadata, single-part transfer",
        "input_data_hex": hex_prefix(input_data, 64),
        "input_data_length": 128,
        "input_sha256": input_sha256,
        "metadata_dict": metadata_dict,
        "has_metadata": True,
        "compressed": compressed,
        "derived_key_hex": derived_key.hex(),
        "deterministic_iv_hex": iv.hex(),
        "random_hash_hex": random_hash.hex(),
        "steps": [step_1, step_2, step_3, step_4, step_5],
        "data_integrity": {
            "original_sha256": input_sha256,
            "reconstructed_sha256": reconstructed_sha256,
            "match": input_sha256 == reconstructed_sha256,
        },
        "state_machine_sequence": [
            {"side": "sender",   "event": "prepare_advertisement", "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "receiver", "event": "accept_advertisement",  "state_before": "NONE",         "state_after": "TRANSFERRING", "callback": "resource_started"},
            {"side": "receiver", "event": "request_parts",         "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": None},
            {"side": "sender",   "event": "send_part",             "state_before": "ADVERTISED",   "state_after": "TRANSFERRING", "callback": None},
            {"side": "receiver", "event": "receive_part",          "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback"},
            {"side": "receiver", "event": "assemble",              "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "extract_metadata",      "state_before": "ASSEMBLING",   "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "verify_and_prove",      "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": "resource_concluded"},
            {"side": "sender",   "event": "validate_proof",        "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "completion_callback"},
        ],
    }

    return vector


def build_compressed_transfer_sequence(derived_key):
    """Build compressible resource (2KB) transfer with compression (flags=0x03).

    Simulates the 5-step exchange with bz2 compression:
      1. Sender prepares advertisement (compressed)
      2. Receiver accepts & requests parts
      3. Sender sends part
      4. Receiver assembles, decompresses, verifies, and proves
      5. Sender validates proof
    """
    from RNS.vendor import umsgpack

    idx = 101  # iv and random_hash seed

    # --- Input data (compressible pattern) ---
    input_data = deterministic_compressible_data(idx, 2048)
    input_sha256 = full_hash(input_data).hex()

    # --- Step 1: Sender prepares advertisement ---
    random_hash = deterministic_random_hash(idx)
    iv = deterministic_iv(idx)

    # No metadata
    data_with_metadata = input_data
    total_size = len(data_with_metadata)

    # Compress
    compressed_data = bz2.compress(data_with_metadata)
    compressed = len(compressed_data) < len(data_with_metadata)
    assert compressed, "Expected data to be compressible"
    payload_after_compress = compressed_data

    # Pre-encryption data: random_hash(4) + compressed_payload
    pre_encryption_data = random_hash + payload_after_compress

    # Encrypt
    encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, iv)
    encrypted_size = len(encrypted_data)

    # Segment into parts
    sdu = RESOURCE_SDU
    num_parts = int(math.ceil(encrypted_size / float(sdu)))

    # Build parts and hashmap
    parts = []
    hashmap = b""
    for i in range(num_parts):
        part_data = encrypted_data[i * sdu:(i + 1) * sdu]
        parts.append(part_data)
        map_hash = get_map_hash(part_data, random_hash)
        hashmap += map_hash

    # Compute hashes
    resource_hash = full_hash(data_with_metadata + random_hash)
    original_hash = resource_hash
    expected_proof = full_hash(data_with_metadata + resource_hash)

    # Flags: encrypted=True, compressed=True
    flags = 0x03

    # Build advertisement dict
    hashmap_for_adv = hashmap[:HASHMAP_MAX_LEN * MAPHASH_LEN]
    adv_dict = {
        "t": encrypted_size,
        "d": total_size,
        "n": num_parts,
        "h": resource_hash,
        "r": random_hash,
        "o": original_hash,
        "i": 1,
        "l": 1,
        "q": None,
        "f": flags,
        "m": hashmap_for_adv,
    }
    adv_packed = umsgpack.packb(adv_dict)

    step_1 = {
        "step": 1,
        "name": "sender_prepare_advertisement",
        "advertisement_packed_hex": adv_packed.hex(),
        "advertisement_packed_length": len(adv_packed),
        "advertisement_dict": {
            "t": encrypted_size,
            "d": total_size,
            "n": num_parts,
            "h": resource_hash.hex(),
            "r": random_hash.hex(),
            "o": original_hash.hex(),
            "i": 1,
            "l": 1,
            "q": None,
            "f": flags,
            "m": hashmap_for_adv.hex(),
        },
        "resource_hash_hex": resource_hash.hex(),
        "random_hash_hex": random_hash.hex(),
        "hashmap_hex": hashmap_for_adv.hex(),
        "num_parts": num_parts,
        "encrypted_data_length": encrypted_size,
        "flags": flags,
        "flags_hex": f"0x{flags:02x}",
        "expected_proof_hex": expected_proof.hex(),
        "compression_info": {
            "original_size": total_size,
            "compressed_size": len(compressed_data),
            "savings": total_size - len(compressed_data),
        },
        "sender_state_before": "QUEUED",
        "sender_state_after": "ADVERTISED",
        "packet_context": f"RESOURCE_ADV (0x{CONTEXT_RESOURCE_ADV:02x})",
    }

    # --- Step 2: Receiver accepts & requests parts ---
    hashmap_exhausted_flag = bytes([HASHMAP_IS_NOT_EXHAUSTED])
    request_payload = hashmap_exhausted_flag + resource_hash
    for i in range(min(num_parts, WINDOW)):
        request_payload += hashmap[i * MAPHASH_LEN:(i + 1) * MAPHASH_LEN]

    step_2 = {
        "step": 2,
        "name": "receiver_request_parts",
        "request_payload_hex": request_payload.hex(),
        "request_payload_length": len(request_payload),
        "receiver_state": "TRANSFERRING",
        "callbacks_fired": ["resource_started"],
        "packet_context": f"RESOURCE_REQ (0x{CONTEXT_RESOURCE_REQ:02x})",
    }

    # --- Step 3: Sender sends parts ---
    step_3_parts = []
    for i in range(num_parts):
        step_3_parts.append({
            "part_index": i,
            "part_data_hex": hex_prefix(parts[i], 64),
            "part_data_length": len(parts[i]),
            "map_hash_hex": hashmap[i * MAPHASH_LEN:(i + 1) * MAPHASH_LEN].hex(),
        })

    step_3 = {
        "step": 3,
        "name": "sender_send_parts",
        "parts": step_3_parts,
        "sender_state": "TRANSFERRING",
        "packet_context": f"RESOURCE (0x{CONTEXT_RESOURCE:02x})",
    }

    # --- Step 4: Receiver assembles & proves ---
    joined_parts = b"".join(parts)
    decrypted = token_decrypt(joined_parts, derived_key)
    stripped_data = decrypted[RANDOM_HASH_SIZE:]

    # Decompress
    decompressed_data = bz2.decompress(stripped_data)

    # Verify hash
    calculated_hash = full_hash(decompressed_data + random_hash)
    hash_verified = calculated_hash == resource_hash
    assert hash_verified, "Assembly hash verification failed for compressed transfer"
    assert decompressed_data == input_data, "Decompressed data doesn't match input"

    # Build proof
    proof = full_hash(decompressed_data + resource_hash)
    proof_data = resource_hash + proof
    assert proof == expected_proof, "Proof doesn't match expected"

    step_4 = {
        "step": 4,
        "name": "receiver_assemble_and_prove",
        "assembly": {
            "joined_parts_hex": hex_prefix(joined_parts, 64),
            "joined_parts_length": len(joined_parts),
            "decrypted_hex": hex_prefix(decrypted, 64),
            "decrypted_length": len(decrypted),
            "stripped_data_hex": hex_prefix(stripped_data, 64),
            "stripped_data_length": len(stripped_data),
            "decompressed_data_hex": hex_prefix(decompressed_data, 64),
            "decompressed_data_length": len(decompressed_data),
            "hash_verified": hash_verified,
            "calculated_hash_hex": calculated_hash.hex(),
        },
        "proof_payload_hex": proof_data.hex(),
        "proof_payload_length": len(proof_data),
        "proof_breakdown": {
            "resource_hash_hex": resource_hash.hex(),
            "proof_hex": proof.hex(),
        },
        "receiver_state_sequence": ["TRANSFERRING", "ASSEMBLING", "COMPLETE"],
        "callbacks_fired": ["progress_callback", "resource_concluded"],
        "packet_context": f"RESOURCE_PRF (0x{CONTEXT_RESOURCE_PRF:02x})",
    }

    # --- Step 5: Sender validates proof ---
    proof_valid = (
        len(proof_data) == HASHLENGTH_BYTES * 2
        and proof_data[HASHLENGTH_BYTES:] == expected_proof
    )
    assert proof_valid, "Proof validation failed"

    step_5 = {
        "step": 5,
        "name": "sender_validate_proof",
        "proof_valid": proof_valid,
        "sender_state": "COMPLETE",
        "callbacks_fired": ["completion_callback"],
    }

    reconstructed_sha256 = full_hash(decompressed_data).hex()

    vector = {
        "index": 6,
        "description": "Compressible resource (2KB) with compression, single-part transfer",
        "input_data_hex": hex_prefix(input_data, 64),
        "input_data_length": 2048,
        "input_sha256": input_sha256,
        "has_metadata": False,
        "compressed": True,
        "derived_key_hex": derived_key.hex(),
        "deterministic_iv_hex": iv.hex(),
        "random_hash_hex": random_hash.hex(),
        "steps": [step_1, step_2, step_3, step_4, step_5],
        "data_integrity": {
            "original_sha256": input_sha256,
            "reconstructed_sha256": reconstructed_sha256,
            "match": input_sha256 == reconstructed_sha256,
        },
        "state_machine_sequence": [
            {"side": "sender",   "event": "prepare_advertisement", "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "receiver", "event": "accept_advertisement",  "state_before": "NONE",         "state_after": "TRANSFERRING", "callback": "resource_started"},
            {"side": "receiver", "event": "request_parts",         "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": None},
            {"side": "sender",   "event": "send_part",             "state_before": "ADVERTISED",   "state_after": "TRANSFERRING", "callback": None},
            {"side": "receiver", "event": "receive_part",          "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback"},
            {"side": "receiver", "event": "assemble",              "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "decompress",            "state_before": "ASSEMBLING",   "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "verify_and_prove",      "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": "resource_concluded"},
            {"side": "sender",   "event": "validate_proof",        "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "completion_callback"},
        ],
    }

    return vector


def build_metadata_compressed_transfer_sequence(derived_key):
    """Build compressible resource (2KB) transfer with metadata + compression (flags=0x23).

    The most complex single-segment case — exercises the complete pipeline:
      1. Sender prepares advertisement (metadata + compression)
      2. Receiver accepts & requests parts
      3. Sender sends part
      4. Receiver assembles, decompresses, verifies, extracts metadata, and proves
      5. Sender validates proof
    """
    from RNS.vendor import umsgpack

    idx = 102  # iv and random_hash seed

    # --- Input data (compressible pattern) ---
    input_data = deterministic_compressible_data(idx, 2048)
    input_sha256 = full_hash(input_data).hex()

    # --- Metadata ---
    metadata_dict = {"type": "compressed_with_meta", "version": 1}
    packed_metadata = umsgpack.packb(metadata_dict)
    metadata_size = len(packed_metadata)
    metadata_bytes = struct.pack(">I", metadata_size)[1:] + packed_metadata

    # --- Step 1: Sender prepares advertisement ---
    random_hash = deterministic_random_hash(idx)
    iv = deterministic_iv(idx)

    # Combine metadata + payload
    data_with_metadata = metadata_bytes + input_data
    total_size = len(data_with_metadata)

    # Compress the combined data
    compressed_data = bz2.compress(data_with_metadata)
    compressed = len(compressed_data) < len(data_with_metadata)
    assert compressed, "Expected metadata+pattern data to be compressible"
    payload_after_compress = compressed_data

    # Pre-encryption data: random_hash(4) + compressed_payload
    pre_encryption_data = random_hash + payload_after_compress

    # Encrypt
    encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, iv)
    encrypted_size = len(encrypted_data)

    # Segment into parts
    sdu = RESOURCE_SDU
    num_parts = int(math.ceil(encrypted_size / float(sdu)))

    # Build parts and hashmap
    parts = []
    hashmap = b""
    for i in range(num_parts):
        part_data = encrypted_data[i * sdu:(i + 1) * sdu]
        parts.append(part_data)
        map_hash = get_map_hash(part_data, random_hash)
        hashmap += map_hash

    # Compute hashes
    resource_hash = full_hash(data_with_metadata + random_hash)
    original_hash = resource_hash
    expected_proof = full_hash(data_with_metadata + resource_hash)

    # Flags: encrypted=True, compressed=True, has_metadata=True
    flags = 0x23

    # Build advertisement dict
    hashmap_for_adv = hashmap[:HASHMAP_MAX_LEN * MAPHASH_LEN]
    adv_dict = {
        "t": encrypted_size,
        "d": total_size,
        "n": num_parts,
        "h": resource_hash,
        "r": random_hash,
        "o": original_hash,
        "i": 1,
        "l": 1,
        "q": None,
        "f": flags,
        "m": hashmap_for_adv,
    }
    adv_packed = umsgpack.packb(adv_dict)

    step_1 = {
        "step": 1,
        "name": "sender_prepare_advertisement",
        "advertisement_packed_hex": adv_packed.hex(),
        "advertisement_packed_length": len(adv_packed),
        "advertisement_dict": {
            "t": encrypted_size,
            "d": total_size,
            "n": num_parts,
            "h": resource_hash.hex(),
            "r": random_hash.hex(),
            "o": original_hash.hex(),
            "i": 1,
            "l": 1,
            "q": None,
            "f": flags,
            "m": hashmap_for_adv.hex(),
        },
        "resource_hash_hex": resource_hash.hex(),
        "random_hash_hex": random_hash.hex(),
        "hashmap_hex": hashmap_for_adv.hex(),
        "num_parts": num_parts,
        "encrypted_data_length": encrypted_size,
        "flags": flags,
        "flags_hex": f"0x{flags:02x}",
        "expected_proof_hex": expected_proof.hex(),
        "metadata_dict": metadata_dict,
        "packed_metadata_hex": packed_metadata.hex(),
        "metadata_bytes_hex": metadata_bytes.hex(),
        "compression_info": {
            "original_size": total_size,
            "compressed_size": len(compressed_data),
            "savings": total_size - len(compressed_data),
        },
        "sender_state_before": "QUEUED",
        "sender_state_after": "ADVERTISED",
        "packet_context": f"RESOURCE_ADV (0x{CONTEXT_RESOURCE_ADV:02x})",
    }

    # --- Step 2: Receiver accepts & requests parts ---
    hashmap_exhausted_flag = bytes([HASHMAP_IS_NOT_EXHAUSTED])
    request_payload = hashmap_exhausted_flag + resource_hash
    for i in range(min(num_parts, WINDOW)):
        request_payload += hashmap[i * MAPHASH_LEN:(i + 1) * MAPHASH_LEN]

    step_2 = {
        "step": 2,
        "name": "receiver_request_parts",
        "request_payload_hex": request_payload.hex(),
        "request_payload_length": len(request_payload),
        "receiver_state": "TRANSFERRING",
        "callbacks_fired": ["resource_started"],
        "packet_context": f"RESOURCE_REQ (0x{CONTEXT_RESOURCE_REQ:02x})",
    }

    # --- Step 3: Sender sends parts ---
    step_3_parts = []
    for i in range(num_parts):
        step_3_parts.append({
            "part_index": i,
            "part_data_hex": hex_prefix(parts[i], 64),
            "part_data_length": len(parts[i]),
            "map_hash_hex": hashmap[i * MAPHASH_LEN:(i + 1) * MAPHASH_LEN].hex(),
        })

    step_3 = {
        "step": 3,
        "name": "sender_send_parts",
        "parts": step_3_parts,
        "sender_state": "TRANSFERRING",
        "packet_context": f"RESOURCE (0x{CONTEXT_RESOURCE:02x})",
    }

    # --- Step 4: Receiver assembles & proves ---
    joined_parts = b"".join(parts)
    decrypted = token_decrypt(joined_parts, derived_key)
    stripped_data = decrypted[RANDOM_HASH_SIZE:]

    # Decompress
    decompressed_data = bz2.decompress(stripped_data)

    # Verify hash
    calculated_hash = full_hash(decompressed_data + random_hash)
    hash_verified = calculated_hash == resource_hash
    assert hash_verified, "Assembly hash verification failed for metadata+compressed transfer"

    # Extract metadata
    meta_size = decompressed_data[0] << 16 | decompressed_data[1] << 8 | decompressed_data[2]
    packed_meta_extracted = decompressed_data[3:3 + meta_size]
    extracted_metadata = umsgpack.unpackb(packed_meta_extracted)
    extracted_payload = decompressed_data[3 + meta_size:]

    assert extracted_payload == input_data, "Assembled payload doesn't match input"
    assert extracted_metadata == metadata_dict, "Extracted metadata doesn't match"

    # Build proof
    proof = full_hash(decompressed_data + resource_hash)
    proof_data = resource_hash + proof
    assert proof == expected_proof, "Proof doesn't match expected"

    step_4 = {
        "step": 4,
        "name": "receiver_assemble_and_prove",
        "assembly": {
            "joined_parts_hex": hex_prefix(joined_parts, 64),
            "joined_parts_length": len(joined_parts),
            "decrypted_hex": hex_prefix(decrypted, 64),
            "decrypted_length": len(decrypted),
            "stripped_data_hex": hex_prefix(stripped_data, 64),
            "stripped_data_length": len(stripped_data),
            "decompressed_data_hex": hex_prefix(decompressed_data, 64),
            "decompressed_data_length": len(decompressed_data),
            "hash_verified": hash_verified,
            "calculated_hash_hex": calculated_hash.hex(),
        },
        "metadata_extraction": {
            "metadata_size": meta_size,
            "extracted_metadata": extracted_metadata,
            "extracted_payload_hex": hex_prefix(extracted_payload, 64),
            "extracted_payload_length": len(extracted_payload),
        },
        "proof_payload_hex": proof_data.hex(),
        "proof_payload_length": len(proof_data),
        "proof_breakdown": {
            "resource_hash_hex": resource_hash.hex(),
            "proof_hex": proof.hex(),
        },
        "receiver_state_sequence": ["TRANSFERRING", "ASSEMBLING", "COMPLETE"],
        "callbacks_fired": ["progress_callback", "resource_concluded"],
        "packet_context": f"RESOURCE_PRF (0x{CONTEXT_RESOURCE_PRF:02x})",
    }

    # --- Step 5: Sender validates proof ---
    proof_valid = (
        len(proof_data) == HASHLENGTH_BYTES * 2
        and proof_data[HASHLENGTH_BYTES:] == expected_proof
    )
    assert proof_valid, "Proof validation failed"

    step_5 = {
        "step": 5,
        "name": "sender_validate_proof",
        "proof_valid": proof_valid,
        "sender_state": "COMPLETE",
        "callbacks_fired": ["completion_callback"],
    }

    reconstructed_sha256 = full_hash(extracted_payload).hex()

    vector = {
        "index": 7,
        "description": "Compressible resource (2KB) with metadata + compression, single-part transfer",
        "input_data_hex": hex_prefix(input_data, 64),
        "input_data_length": 2048,
        "input_sha256": input_sha256,
        "metadata_dict": metadata_dict,
        "has_metadata": True,
        "compressed": True,
        "derived_key_hex": derived_key.hex(),
        "deterministic_iv_hex": iv.hex(),
        "random_hash_hex": random_hash.hex(),
        "steps": [step_1, step_2, step_3, step_4, step_5],
        "data_integrity": {
            "original_sha256": input_sha256,
            "reconstructed_sha256": reconstructed_sha256,
            "match": input_sha256 == reconstructed_sha256,
        },
        "state_machine_sequence": [
            {"side": "sender",   "event": "prepare_advertisement", "state_before": "QUEUED",       "state_after": "ADVERTISED",   "callback": None},
            {"side": "receiver", "event": "accept_advertisement",  "state_before": "NONE",         "state_after": "TRANSFERRING", "callback": "resource_started"},
            {"side": "receiver", "event": "request_parts",         "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": None},
            {"side": "sender",   "event": "send_part",             "state_before": "ADVERTISED",   "state_after": "TRANSFERRING", "callback": None},
            {"side": "receiver", "event": "receive_part",          "state_before": "TRANSFERRING", "state_after": "TRANSFERRING", "callback": "progress_callback"},
            {"side": "receiver", "event": "assemble",              "state_before": "TRANSFERRING", "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "decompress",            "state_before": "ASSEMBLING",   "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "extract_metadata",      "state_before": "ASSEMBLING",   "state_after": "ASSEMBLING",   "callback": None},
            {"side": "receiver", "event": "verify_and_prove",      "state_before": "ASSEMBLING",   "state_after": "COMPLETE",     "callback": "resource_concluded"},
            {"side": "sender",   "event": "validate_proof",        "state_before": "TRANSFERRING", "state_after": "COMPLETE",     "callback": "completion_callback"},
        ],
    }

    return vector


def build_cancellation_vectors():
    """Build cancellation payload vectors for ICL and RCL."""
    # Use the resource_hash from case 0 (deterministic)
    input_data = deterministic_data(0, 128)
    random_hash = deterministic_random_hash(0)
    data_with_metadata = input_data
    resource_hash = full_hash(data_with_metadata + random_hash)

    # Initiator cancel (RESOURCE_ICL): payload = resource_hash
    # From Resource.cancel() line 1073: cancel_packet = RNS.Packet(self.link, self.hash, context=RNS.Packet.RESOURCE_ICL)
    icl_payload = resource_hash

    # Receiver cancel (RESOURCE_RCL): payload = resource_hash
    # From Resource.accept() line 158: reject_packet = RNS.Packet(advertisement_packet.link, resource_hash, context=RNS.Packet.RESOURCE_RCL)
    rcl_payload = resource_hash

    return [
        {
            "type": "initiator_cancel",
            "description": "Sender cancels transfer (RESOURCE_ICL)",
            "payload_hex": icl_payload.hex(),
            "payload_length": len(icl_payload),
            "payload_content": "resource_hash (32 bytes)",
            "packet_context": f"RESOURCE_ICL (0x{CONTEXT_RESOURCE_ICL:02x})",
            "source": "Resource.cancel() — sends self.hash as payload",
        },
        {
            "type": "receiver_cancel",
            "description": "Receiver rejects/cancels transfer (RESOURCE_RCL)",
            "payload_hex": rcl_payload.hex(),
            "payload_length": len(rcl_payload),
            "payload_content": "resource_hash (32 bytes)",
            "packet_context": f"RESOURCE_RCL (0x{CONTEXT_RESOURCE_RCL:02x})",
            "source": "Resource.accept() rejection — sends resource_hash as payload",
        },
    ]


def verify(output, derived_key):
    """Cross-validate all vectors against resources.json and links.json."""
    from RNS.vendor import umsgpack

    print("  Verifying...")

    # 1. Cross-validate advertisement against resources.json case 0
    resources_data = load_resources_json()
    res_case_0 = resources_data["resource_advertisement_vectors"][0]
    transfer_vec = output["transfer_sequence_vectors"][0]
    step_1 = transfer_vec["steps"][0]

    assert step_1["resource_hash_hex"] == res_case_0["resource_hash_hex"], \
        f"Resource hash mismatch: {step_1['resource_hash_hex']} != {res_case_0['resource_hash_hex']}"

    assert step_1["advertisement_packed_hex"] == res_case_0["advertisement_packed_hex"], \
        f"Advertisement packed hex mismatch"

    assert step_1["hashmap_hex"] == res_case_0["hashmap_hex"], \
        f"Hashmap mismatch"

    assert step_1["expected_proof_hex"] == res_case_0["expected_proof_hex"], \
        f"Expected proof mismatch"

    assert step_1["encrypted_data_length"] == res_case_0["encrypted_data_length"], \
        f"Encrypted data length mismatch"

    print("    [OK] Advertisement cross-validated against resources.json case 0")

    # 2. Cross-validate proof against resources.json proof vector 0
    res_proof_0 = resources_data["resource_proof_vectors"][0]
    step_4 = transfer_vec["steps"][3]

    assert step_4["proof_payload_hex"] == res_proof_0["proof_packet_payload_hex"], \
        f"Proof payload mismatch: {step_4['proof_payload_hex']} != {res_proof_0['proof_packet_payload_hex']}"

    assert step_4["proof_payload_length"] == res_proof_0["proof_packet_payload_length"], \
        f"Proof payload length mismatch"

    print("    [OK] Proof cross-validated against resources.json proof vector 0")

    # 3. Verify request packet round-trip
    step_2 = transfer_vec["steps"][1]
    request_bytes = bytes.fromhex(step_2["request_payload_hex"])

    # Parse it back
    exhausted_flag = request_bytes[0]
    assert exhausted_flag == HASHMAP_IS_NOT_EXHAUSTED, f"Unexpected exhaustion flag: {exhausted_flag}"

    parsed_resource_hash = request_bytes[1:1 + HASHLENGTH_BYTES]
    assert parsed_resource_hash.hex() == step_1["resource_hash_hex"], "Request resource hash mismatch"

    parsed_map_hashes = request_bytes[1 + HASHLENGTH_BYTES:]
    assert parsed_map_hashes.hex() == step_1["hashmap_hex"], "Request map hashes mismatch"

    print("    [OK] Request packet round-trip verified")

    # 4. Verify assembly produces original data
    assert transfer_vec["data_integrity"]["match"] is True, "Data integrity check failed"
    print("    [OK] Assembly produces original data")

    # 5. Verify proof validation logic
    step_5 = transfer_vec["steps"][4]
    assert step_5["proof_valid"] is True, "Proof validation failed"
    print("    [OK] Proof validation logic verified")

    # 6. Cross-validate derived_key against links.json
    links_data = load_links_json()
    hs0 = links_data["handshake_vectors"][0]
    links_derived_key = hs0["step_2_lrproof"]["derived_key"]
    assert derived_key.hex() == links_derived_key, f"derived_key mismatch with links.json"
    print("    [OK] derived_key cross-validated against links.json")

    # 7. Verify library constants match
    verify_library_constants()

    # 8. JSON round-trip integrity
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("    [OK] JSON round-trip integrity verified")

    # 9. Verify advertisement unpacks correctly
    adv_packed = bytes.fromhex(step_1["advertisement_packed_hex"])
    adv = umsgpack.unpackb(adv_packed)
    assert adv["t"] == step_1["encrypted_data_length"]
    assert adv["n"] == step_1["num_parts"]
    assert adv["h"] == bytes.fromhex(step_1["resource_hash_hex"])
    assert adv["r"] == bytes.fromhex(step_1["random_hash_hex"])
    assert adv["f"] == step_1["flags"]
    print("    [OK] Advertisement msgpack unpack verified")

    # --- Mini vector (256KB) verification ---
    mini_vec = output["transfer_sequence_vectors"][1]

    # 10. Verify encrypted data independently
    idx = 1
    mini_input = deterministic_data(idx, 256000)
    mini_random_hash = deterministic_random_hash(idx)
    mini_iv = deterministic_iv(idx)
    mini_pre = mini_random_hash + mini_input
    mini_encrypted = token_encrypt_deterministic(mini_pre, derived_key, mini_iv)
    assert full_hash(mini_encrypted).hex() == mini_vec["encrypted_data_sha256"], \
        "Mini vector: encrypted data SHA256 mismatch"
    assert len(mini_encrypted) == mini_vec["encrypted_data_length"], \
        "Mini vector: encrypted data length mismatch"
    print("    [OK] Mini vector: encrypted data independently verified")

    # 11. Verify hashmap independently
    sdu = RESOURCE_SDU
    mini_num_parts = mini_vec["num_parts"]
    assert mini_num_parts == 552
    regen_hashmap = b""
    for i in range(mini_num_parts):
        part = mini_encrypted[i * sdu:(i + 1) * sdu]
        regen_hashmap += get_map_hash(part, mini_random_hash)
    assert regen_hashmap.hex() == mini_vec["total_hashmap_hex"], \
        "Mini vector: hashmap mismatch"
    print("    [OK] Mini vector: hashmap independently verified")

    # 12. Verify resource hash and expected proof
    mini_resource_hash = full_hash(mini_input + mini_random_hash)
    assert mini_resource_hash.hex() == mini_vec["resource_hash_hex"], \
        "Mini vector: resource hash mismatch"
    mini_expected_proof = full_hash(mini_input + mini_resource_hash)
    assert mini_expected_proof.hex() == mini_vec["expected_proof_hex"], \
        "Mini vector: expected proof mismatch"
    print("    [OK] Mini vector: resource hash and expected proof verified")

    # 13. Verify assembly round-trip
    mini_decrypted = token_decrypt(mini_encrypted, derived_key)
    mini_stripped = mini_decrypted[RANDOM_HASH_SIZE:]
    assert mini_stripped == mini_input, "Mini vector: assembly round-trip data mismatch"
    assert mini_vec["data_integrity"]["match"] is True, "Mini vector: data integrity check failed"
    print("    [OK] Mini vector: assembly round-trip verified")

    # 14. Verify transfer protocol counts
    tp = mini_vec["transfer_protocol"]
    assert tp["total_rounds"] == 62, f"Mini vector: expected 62 rounds, got {tp['total_rounds']}"
    assert len(tp["hmu_packets"]) == 7, f"Mini vector: expected 7 HMU packets, got {len(tp['hmu_packets'])}"
    print("    [OK] Mini vector: 62 rounds, 7 HMU packets verified")

    # 15. Verify HMU packet format
    first_hmu = tp["hmu_packets"][0]
    first_hmu_payload = bytes.fromhex(first_hmu["payload_hex"])
    assert first_hmu_payload[:HASHLENGTH_BYTES] == mini_resource_hash, \
        "Mini vector: first HMU doesn't start with resource_hash"
    hmu_body = umsgpack.unpackb(first_hmu_payload[HASHLENGTH_BYTES:])
    assert isinstance(hmu_body, list) and len(hmu_body) == 2, \
        "Mini vector: HMU body is not [segment, hashmap]"
    assert hmu_body[0] == first_hmu["segment"], \
        "Mini vector: HMU segment index mismatch"
    print("    [OK] Mini vector: HMU packet format verified")

    # 16. Verify hashmap segments
    assert len(mini_vec["hashmap_by_segment"]) == 8, "Mini vector: expected 8 segments"
    for seg_info in mini_vec["hashmap_by_segment"][:7]:
        assert seg_info["hash_count"] == 74, f"Mini vector: segment {seg_info['segment']} expected 74 hashes"
    assert mini_vec["hashmap_by_segment"][7]["hash_count"] == 34, "Mini vector: last segment expected 34 hashes"
    print("    [OK] Mini vector: hashmap segment structure verified")

    # --- Small vector (1MB) verification ---
    small_vec = output["transfer_sequence_vectors"][2]

    # 17. Verify encrypted data independently
    s_idx = 2
    small_input = deterministic_data(s_idx, 1_000_000)
    small_random_hash = deterministic_random_hash(s_idx)
    small_iv = deterministic_iv(s_idx)
    small_pre = small_random_hash + small_input
    small_encrypted = token_encrypt_deterministic(small_pre, derived_key, small_iv)
    assert full_hash(small_encrypted).hex() == small_vec["encrypted_data_sha256"], \
        "Small vector: encrypted data SHA256 mismatch"
    assert len(small_encrypted) == small_vec["encrypted_data_length"], \
        "Small vector: encrypted data length mismatch"
    print("    [OK] Small vector: encrypted data independently verified")

    # 18. Verify hashmap independently
    small_num_parts = small_vec["num_parts"]
    assert small_num_parts == 2156
    regen_hashmap_small = b""
    for i in range(small_num_parts):
        part = small_encrypted[i * sdu:(i + 1) * sdu]
        regen_hashmap_small += get_map_hash(part, small_random_hash)
    assert full_hash(regen_hashmap_small).hex() == small_vec["total_hashmap_sha256"], \
        "Small vector: hashmap SHA256 mismatch"
    print("    [OK] Small vector: hashmap independently verified")

    # 19. Verify resource hash and expected proof
    small_resource_hash = full_hash(small_input + small_random_hash)
    assert small_resource_hash.hex() == small_vec["resource_hash_hex"], \
        "Small vector: resource hash mismatch"
    small_expected_proof = full_hash(small_input + small_resource_hash)
    assert small_expected_proof.hex() == small_vec["expected_proof_hex"], \
        "Small vector: expected proof mismatch"
    print("    [OK] Small vector: resource hash and expected proof verified")

    # 20. Verify assembly round-trip
    small_decrypted = token_decrypt(small_encrypted, derived_key)
    small_stripped = small_decrypted[RANDOM_HASH_SIZE:]
    assert small_stripped == small_input, "Small vector: assembly round-trip data mismatch"
    assert small_vec["data_integrity"]["match"] is True, "Small vector: data integrity check failed"
    print("    [OK] Small vector: assembly round-trip verified")

    # 21. Verify transfer protocol counts
    tp_s = small_vec["transfer_protocol"]
    assert tp_s["total_rounds"] > 200, f"Small vector: expected >200 rounds, got {tp_s['total_rounds']}"
    assert len(tp_s["hmu_packets"]) == 29, f"Small vector: expected 29 HMU packets, got {len(tp_s['hmu_packets'])}"
    print(f"    [OK] Small vector: {tp_s['total_rounds']} rounds, 29 HMU packets verified")

    # 22. Verify hashmap segment structure (29 full of 74 + 1 of remainder)
    assert len(small_vec["hashmap_by_segment"]) == 30, "Small vector: expected 30 hashmap segments"
    for seg_info in small_vec["hashmap_by_segment"][:29]:
        assert seg_info["hash_count"] == 74, f"Small vector: segment {seg_info['segment']} expected 74 hashes"
    last_seg = small_vec["hashmap_by_segment"][29]
    assert last_seg["hash_count"] == 2156 - 29 * 74, \
        f"Small vector: last segment expected {2156 - 29 * 74} hashes, got {last_seg['hash_count']}"
    print("    [OK] Small vector: hashmap segment structure verified")

    # --- Medium vector (5MB) verification ---
    med_vec = output["transfer_sequence_vectors"][3]

    # 23. Verify segment data sizes
    assert med_vec["total_segments"] == 5, "Medium vector: expected 5 segments"
    assert sum(med_vec["segment_sizes"]) == 5_000_000, \
        f"Medium vector: segment sizes sum {sum(med_vec['segment_sizes'])} != 5000000"
    assert med_vec["segment_sizes"] == [1_048_575, 1_048_575, 1_048_575, 1_048_575, 805_700], \
        f"Medium vector: unexpected segment sizes"
    print("    [OK] Medium vector: segment sizes verified")

    # 24. Verify split flag and flags byte
    assert med_vec["split"] is True, "Medium vector: expected split=True"
    assert med_vec["flags"] == 0x05, f"Medium vector: expected flags 0x05, got {med_vec['flags']}"
    print("    [OK] Medium vector: split flag and flags byte verified")

    # 25. Verify per-segment encrypted data and crypto
    med_input = deterministic_data(3, 5_000_000)
    assert full_hash(med_input).hex() == med_vec["input_sha256"], \
        "Medium vector: input data SHA256 mismatch"
    first_read_size = MAX_EFFICIENT_SIZE  # no metadata
    all_stripped = b""
    for seg_info in med_vec["segments"]:
        si = seg_info["segment_index"]
        if si == 1:
            seek = 0
            read_size = first_read_size
        else:
            seek = first_read_size + ((si - 2) * MAX_EFFICIENT_SIZE)
            read_size = MAX_EFFICIENT_SIZE
        if si == med_vec["total_segments"]:
            seg_data_expected = med_input[seek:]
        else:
            seg_data_expected = med_input[seek:seek + read_size]

        assert len(seg_data_expected) == seg_info["segment_data_length"], \
            f"Medium vector segment {si}: data length mismatch"
        assert full_hash(seg_data_expected).hex() == seg_info["segment_data_sha256"], \
            f"Medium vector segment {si}: data SHA256 mismatch"

        # Verify encryption independently
        seg_rh = deterministic_random_hash(300 + si - 1)
        seg_iv = deterministic_iv(300 + si - 1)
        seg_pre = seg_rh + seg_data_expected
        seg_enc = token_encrypt_deterministic(seg_pre, derived_key, seg_iv)
        assert full_hash(seg_enc).hex() == seg_info["encrypted_data_sha256"], \
            f"Medium vector segment {si}: encrypted data SHA256 mismatch"

        # Verify resource hash and proof
        seg_resource_hash = full_hash(seg_data_expected + seg_rh)
        assert seg_resource_hash.hex() == seg_info["resource_hash_hex"], \
            f"Medium vector segment {si}: resource hash mismatch"
        seg_expected_proof = full_hash(seg_data_expected + seg_resource_hash)
        assert seg_expected_proof.hex() == seg_info["expected_proof_hex"], \
            f"Medium vector segment {si}: expected proof mismatch"

        # Verify assembly round-trip
        seg_dec = token_decrypt(seg_enc, derived_key)
        seg_stripped = seg_dec[RANDOM_HASH_SIZE:]
        assert seg_stripped == seg_data_expected, \
            f"Medium vector segment {si}: assembly round-trip mismatch"
        all_stripped += seg_stripped

        # Verify advertisement d field = total_size (5,000,000 for all segments)
        assert seg_info["advertisement_dict"]["d"] == 5_000_000, \
            f"Medium vector segment {si}: advertisement d != 5000000"
        assert seg_info["advertisement_dict"]["i"] == si, \
            f"Medium vector segment {si}: advertisement i mismatch"
        assert seg_info["advertisement_dict"]["l"] == 5, \
            f"Medium vector segment {si}: advertisement l != 5"

    print("    [OK] Medium vector: per-segment crypto independently verified")

    # 26. Verify original_hash consistency
    seg1_hash = med_vec["segments"][0]["resource_hash_hex"]
    assert med_vec["original_hash_hex"] == seg1_hash, \
        "Medium vector: original_hash != segment 1 resource_hash"
    for seg_info in med_vec["segments"]:
        assert seg_info["advertisement_dict"]["o"] == seg1_hash, \
            f"Medium vector segment {seg_info['segment_index']}: original_hash mismatch in advertisement"
    # Note: o field is original_hash.hex() which was set from segment 1's resource_hash
    print("    [OK] Medium vector: original_hash consistency verified")

    # 27. Cross-segment reassembly
    assert all_stripped == med_input, "Medium vector: cross-segment reassembly mismatch"
    assert med_vec["cross_segment_verification"]["match"] is True, \
        "Medium vector: cross-segment verification flag is False"
    print("    [OK] Medium vector: cross-segment reassembly verified")

    # --- Large vector (50MB) verification ---
    large_vec = output["transfer_sequence_vectors"][4]

    # 28. Verify segment data sizes
    assert large_vec["total_segments"] == 48, "Large vector: expected 48 segments"
    assert sum(large_vec["segment_sizes"]) == 50_000_000, \
        f"Large vector: segment sizes sum {sum(large_vec['segment_sizes'])} != 50000000"
    expected_large_sizes = [1_048_575] * 47 + [716_975]
    assert large_vec["segment_sizes"] == expected_large_sizes, \
        f"Large vector: unexpected segment sizes"
    print("    [OK] Large vector: segment sizes verified (47 x 1,048,575 + 716,975 = 50,000,000)")

    # 29. Verify split flag and flags byte
    assert large_vec["split"] is True, "Large vector: expected split=True"
    assert large_vec["flags"] == 0x05, f"Large vector: expected flags 0x05, got {large_vec['flags']}"
    print("    [OK] Large vector: split flag and flags byte verified")

    # 30. Verify per-segment encrypted data and crypto
    large_input = deterministic_data(4, 50_000_000)
    assert full_hash(large_input).hex() == large_vec["input_sha256"], \
        "Large vector: input data SHA256 mismatch"
    first_read_size_l = MAX_EFFICIENT_SIZE  # no metadata
    all_stripped_l = b""
    for seg_info in large_vec["segments"]:
        si = seg_info["segment_index"]
        if si == 1:
            seek = 0
            read_size = first_read_size_l
        else:
            seek = first_read_size_l + ((si - 2) * MAX_EFFICIENT_SIZE)
            read_size = MAX_EFFICIENT_SIZE
        if si == large_vec["total_segments"]:
            seg_data_expected = large_input[seek:]
        else:
            seg_data_expected = large_input[seek:seek + read_size]

        assert len(seg_data_expected) == seg_info["segment_data_length"], \
            f"Large vector segment {si}: data length mismatch"
        assert full_hash(seg_data_expected).hex() == seg_info["segment_data_sha256"], \
            f"Large vector segment {si}: data SHA256 mismatch"

        # Verify encryption independently
        seg_rh = deterministic_random_hash(400 + si - 1)
        seg_iv = deterministic_iv(400 + si - 1)
        seg_pre = seg_rh + seg_data_expected
        seg_enc = token_encrypt_deterministic(seg_pre, derived_key, seg_iv)
        assert full_hash(seg_enc).hex() == seg_info["encrypted_data_sha256"], \
            f"Large vector segment {si}: encrypted data SHA256 mismatch"

        # Verify resource hash and proof
        seg_resource_hash = full_hash(seg_data_expected + seg_rh)
        assert seg_resource_hash.hex() == seg_info["resource_hash_hex"], \
            f"Large vector segment {si}: resource hash mismatch"
        seg_expected_proof = full_hash(seg_data_expected + seg_resource_hash)
        assert seg_expected_proof.hex() == seg_info["expected_proof_hex"], \
            f"Large vector segment {si}: expected proof mismatch"

        # Verify assembly round-trip
        seg_dec = token_decrypt(seg_enc, derived_key)
        seg_stripped = seg_dec[RANDOM_HASH_SIZE:]
        assert seg_stripped == seg_data_expected, \
            f"Large vector segment {si}: assembly round-trip mismatch"
        all_stripped_l += seg_stripped

        # Verify advertisement d field = total_size (50,000,000 for all segments)
        assert seg_info["advertisement_dict"]["d"] == 50_000_000, \
            f"Large vector segment {si}: advertisement d != 50000000"
        assert seg_info["advertisement_dict"]["i"] == si, \
            f"Large vector segment {si}: advertisement i mismatch"
        assert seg_info["advertisement_dict"]["l"] == 48, \
            f"Large vector segment {si}: advertisement l != 48"

    print("    [OK] Large vector: per-segment crypto independently verified")

    # 31. Verify original_hash consistency
    seg1_hash_l = large_vec["segments"][0]["resource_hash_hex"]
    assert large_vec["original_hash_hex"] == seg1_hash_l, \
        "Large vector: original_hash != segment 1 resource_hash"
    for seg_info in large_vec["segments"]:
        assert seg_info["advertisement_dict"]["o"] == seg1_hash_l, \
            f"Large vector segment {seg_info['segment_index']}: original_hash mismatch in advertisement"
    print("    [OK] Large vector: original_hash consistency verified")

    # 32. Cross-segment reassembly
    assert all_stripped_l == large_input, "Large vector: cross-segment reassembly mismatch"
    assert large_vec["cross_segment_verification"]["match"] is True, \
        "Large vector: cross-segment verification flag is False"
    print("    [OK] Large vector: cross-segment reassembly verified")

    # --- Metadata transfer vector (index 5) verification ---
    meta_vec = output["transfer_sequence_vectors"][5]

    # 33. Verify metadata transfer flags and data integrity
    assert meta_vec["has_metadata"] is True, "Metadata vector: expected has_metadata=True"
    assert meta_vec["data_integrity"]["match"] is True, "Metadata vector: data integrity check failed"
    meta_step1 = meta_vec["steps"][0]
    meta_flags = meta_step1["flags"]
    assert meta_flags & 0x20, "Metadata vector: has_metadata flag not set"
    assert meta_flags & 0x01, "Metadata vector: encrypted flag not set"
    print(f"    [OK] Metadata vector: flags=0x{meta_flags:02x}, data integrity verified")

    # 34. Cross-validate metadata encoding with resources.json
    res_case_1 = resources_data["resource_advertisement_vectors"][1]
    assert meta_vec["metadata_dict"] == res_case_1["metadata_dict"], \
        "Metadata vector: metadata_dict doesn't match resources.json case 1"
    assert meta_step1["packed_metadata_hex"] == res_case_1["packed_metadata_hex"], \
        "Metadata vector: packed_metadata doesn't match resources.json case 1"
    print("    [OK] Metadata vector: metadata encoding cross-validated against resources.json case 1")

    # 35. Verify metadata extraction round-trip
    meta_step4 = meta_vec["steps"][3]
    assert meta_step4["metadata_extraction"]["extracted_metadata"] == meta_vec["metadata_dict"], \
        "Metadata vector: extracted metadata doesn't match original"
    print("    [OK] Metadata vector: metadata extraction round-trip verified")

    # --- Compressed transfer vector (index 6) verification ---
    comp_vec = output["transfer_sequence_vectors"][6]

    # 36. Verify compression transfer flags and data integrity
    assert comp_vec["compressed"] is True, "Compressed vector: expected compressed=True"
    assert comp_vec["data_integrity"]["match"] is True, "Compressed vector: data integrity check failed"
    comp_step1 = comp_vec["steps"][0]
    comp_flags = comp_step1["flags"]
    assert comp_flags == 0x03, f"Compressed vector: expected flags=0x03, got 0x{comp_flags:02x}"
    print(f"    [OK] Compressed vector: flags=0x{comp_flags:02x}, data integrity verified")

    # 37. Verify compression independently
    c_idx = 101
    comp_input = deterministic_compressible_data(c_idx, 2048)
    comp_compressed = bz2.compress(comp_input)
    assert len(comp_compressed) < len(comp_input), "Compressed vector: data should be compressible"
    comp_rh = deterministic_random_hash(c_idx)
    comp_iv = deterministic_iv(c_idx)
    comp_pre = comp_rh + comp_compressed
    comp_enc = token_encrypt_deterministic(comp_pre, derived_key, comp_iv)
    assert len(comp_enc) == comp_step1["encrypted_data_length"], \
        "Compressed vector: encrypted data length mismatch"

    # Verify assembly round-trip
    comp_dec = token_decrypt(comp_enc, derived_key)
    comp_stripped = comp_dec[RANDOM_HASH_SIZE:]
    comp_decompressed = bz2.decompress(comp_stripped)
    assert comp_decompressed == comp_input, "Compressed vector: decompression round-trip mismatch"

    # Verify resource hash
    comp_resource_hash = full_hash(comp_input + comp_rh)
    assert comp_resource_hash.hex() == comp_step1["resource_hash_hex"], \
        "Compressed vector: resource hash mismatch"
    print("    [OK] Compressed vector: compression and assembly independently verified")

    # --- Metadata+Compressed transfer vector (index 7) verification ---
    mc_vec = output["transfer_sequence_vectors"][7]

    # 38. Verify metadata+compression flags and data integrity
    assert mc_vec["has_metadata"] is True, "Meta+Comp vector: expected has_metadata=True"
    assert mc_vec["compressed"] is True, "Meta+Comp vector: expected compressed=True"
    assert mc_vec["data_integrity"]["match"] is True, "Meta+Comp vector: data integrity check failed"
    mc_step1 = mc_vec["steps"][0]
    mc_flags = mc_step1["flags"]
    assert mc_flags == 0x23, f"Meta+Comp vector: expected flags=0x23, got 0x{mc_flags:02x}"
    print(f"    [OK] Meta+Comp vector: flags=0x{mc_flags:02x}, data integrity verified")

    # 39. Verify full pipeline independently
    mc_idx = 102
    mc_input = deterministic_compressible_data(mc_idx, 2048)
    mc_meta_dict = {"type": "compressed_with_meta", "version": 1}
    mc_packed_meta = umsgpack.packb(mc_meta_dict)
    mc_meta_bytes = struct.pack(">I", len(mc_packed_meta))[1:] + mc_packed_meta
    mc_data_with_meta = mc_meta_bytes + mc_input
    mc_compressed = bz2.compress(mc_data_with_meta)
    assert len(mc_compressed) < len(mc_data_with_meta), "Meta+Comp vector: should be compressible"

    mc_rh = deterministic_random_hash(mc_idx)
    mc_iv = deterministic_iv(mc_idx)
    mc_pre = mc_rh + mc_compressed
    mc_enc = token_encrypt_deterministic(mc_pre, derived_key, mc_iv)
    assert len(mc_enc) == mc_step1["encrypted_data_length"], \
        "Meta+Comp vector: encrypted data length mismatch"

    # Full assembly round-trip
    mc_dec = token_decrypt(mc_enc, derived_key)
    mc_stripped = mc_dec[RANDOM_HASH_SIZE:]
    mc_decompressed = bz2.decompress(mc_stripped)
    mc_resource_hash = full_hash(mc_data_with_meta + mc_rh)
    assert full_hash(mc_decompressed + mc_rh) == mc_resource_hash, \
        "Meta+Comp vector: hash verification mismatch"

    # Extract metadata
    mc_meta_size = mc_decompressed[0] << 16 | mc_decompressed[1] << 8 | mc_decompressed[2]
    mc_extracted_meta = umsgpack.unpackb(mc_decompressed[3:3 + mc_meta_size])
    mc_extracted_payload = mc_decompressed[3 + mc_meta_size:]
    assert mc_extracted_meta == mc_meta_dict, "Meta+Comp vector: metadata extraction mismatch"
    assert mc_extracted_payload == mc_input, "Meta+Comp vector: payload extraction mismatch"
    print("    [OK] Meta+Comp vector: full pipeline independently verified")

    # 40. Cross-validate metadata+compression against resources.json case 4
    res_case_4 = resources_data["resource_advertisement_vectors"][4]
    assert mc_vec["metadata_dict"] == res_case_4["metadata_dict"], \
        "Meta+Comp vector: metadata_dict doesn't match resources.json case 4"
    assert res_case_4["flags"] == 0x23, \
        f"resources.json case 4: expected flags=0x23, got 0x{res_case_4['flags']:02x}"
    print("    [OK] Meta+Comp vector: cross-validated against resources.json case 4")


def verify_library_constants():
    """Verify our local constants match the actual RNS library values."""
    import RNS
    from RNS.Packet import Packet
    from RNS.Resource import Resource, ResourceAdvertisement

    # Packet context constants
    assert CONTEXT_NONE == Packet.NONE
    assert CONTEXT_RESOURCE == Packet.RESOURCE
    assert CONTEXT_RESOURCE_ADV == Packet.RESOURCE_ADV
    assert CONTEXT_RESOURCE_REQ == Packet.RESOURCE_REQ
    assert CONTEXT_RESOURCE_HMU == Packet.RESOURCE_HMU
    assert CONTEXT_RESOURCE_PRF == Packet.RESOURCE_PRF
    assert CONTEXT_RESOURCE_ICL == Packet.RESOURCE_ICL
    assert CONTEXT_RESOURCE_RCL == Packet.RESOURCE_RCL

    # Core constants
    assert MTU == RNS.Reticulum.MTU
    assert HEADER_MINSIZE == RNS.Reticulum.HEADER_MINSIZE
    assert HEADER_MAXSIZE == RNS.Reticulum.HEADER_MAXSIZE
    assert IFAC_MIN_SIZE == RNS.Reticulum.IFAC_MIN_SIZE
    assert TOKEN_OVERHEAD == RNS.Identity.TOKEN_OVERHEAD
    assert HASHLENGTH_BYTES == RNS.Identity.HASHLENGTH // 8
    assert RESOURCE_SDU == RNS.Reticulum.MDU

    # Resource constants
    assert WINDOW == Resource.WINDOW
    assert MAPHASH_LEN == Resource.MAPHASH_LEN
    assert RANDOM_HASH_SIZE == Resource.RANDOM_HASH_SIZE
    assert HASHMAP_IS_NOT_EXHAUSTED == Resource.HASHMAP_IS_NOT_EXHAUSTED
    assert HASHMAP_IS_EXHAUSTED == Resource.HASHMAP_IS_EXHAUSTED

    # Status constants
    assert STATUS_QUEUED == Resource.QUEUED
    assert STATUS_ADVERTISED == Resource.ADVERTISED
    assert STATUS_TRANSFERRING == Resource.TRANSFERRING
    assert STATUS_ASSEMBLING == Resource.ASSEMBLING
    assert STATUS_COMPLETE == Resource.COMPLETE
    assert STATUS_FAILED == Resource.FAILED
    assert STATUS_CORRUPT == Resource.CORRUPT

    # ResourceAdvertisement constants
    assert OVERHEAD == ResourceAdvertisement.OVERHEAD
    assert HASHMAP_MAX_LEN == ResourceAdvertisement.HASHMAP_MAX_LEN

    print("    [OK] All library constants verified")


def main():
    print("Extracting resource transfer protocol test vectors...")

    # Load derived key from links.json (handshake scenario 0)
    links_data = load_links_json()
    hs0 = links_data["handshake_vectors"][0]
    derived_key = bytes.fromhex(hs0["step_2_lrproof"]["derived_key"])
    print(f"  Loaded derived_key from links.json ({len(derived_key)} bytes)")

    print("Extracting constants...")
    constants = extract_constants()

    print("Building transfer sequence vectors (micro 128B, mini 256KB, small 1MB, medium 5MB, large 50MB)...")
    transfer_vectors = build_transfer_sequence(derived_key)
    print(f"  Built {len(transfer_vectors)} transfer sequence vector(s)")

    print("Building metadata transfer sequence (128B with metadata, flags=0x21)...")
    metadata_vec = build_metadata_transfer_sequence(derived_key)
    transfer_vectors.append(metadata_vec)
    print("  Built metadata transfer sequence")

    print("Building compressed transfer sequence (2KB compressed, flags=0x03)...")
    compressed_vec = build_compressed_transfer_sequence(derived_key)
    transfer_vectors.append(compressed_vec)
    print("  Built compressed transfer sequence")

    print("Building metadata+compressed transfer sequence (2KB with metadata+compression, flags=0x23)...")
    meta_compressed_vec = build_metadata_compressed_transfer_sequence(derived_key)
    transfer_vectors.append(meta_compressed_vec)
    print("  Built metadata+compressed transfer sequence")

    print(f"  Total: {len(transfer_vectors)} transfer sequence vectors")

    print("Building cancellation vectors...")
    cancel_vectors = build_cancellation_vectors()
    print(f"  Built {len(cancel_vectors)} cancellation vectors")

    output = {
        "description": "Reticulum v1.1.3 - resource transfer protocol test vectors",
        "source": "RNS/Resource.py, RNS/Packet.py",
        "constants": constants,
        "transfer_sequence_vectors": transfer_vectors,
        "cancellation_vectors": cancel_vectors,
    }

    verify(output, derived_key)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
