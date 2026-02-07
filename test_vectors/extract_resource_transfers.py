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
    result = b""
    counter = 0
    while len(result) < length:
        chunk = hashlib.sha256(seed + struct.pack(">I", counter)).digest()
        result += chunk
        counter += 1
    return result[:length]


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

    return [vector]


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

    print("Building transfer sequence vectors...")
    transfer_vectors = build_transfer_sequence(derived_key)
    print(f"  Built {len(transfer_vectors)} transfer sequence vector(s)")

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
