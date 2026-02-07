#!/usr/bin/env python3
"""
Extract request/response protocol test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Link/Transport/Resource objects) to
avoid Transport init. Real RNS crypto primitives are used for encryption,
hashing, and serialization.

Covers:
  - Request/Response constants (context types, policies, receipt statuses)
  - Path hash computation (handler routing lookup)
  - Request serialization (timestamp + path_hash + data → msgpack)
  - Response serialization (request_id + response_data → msgpack)
  - Small request wire format (encrypted packet construction)
  - Small response wire format (encrypted packet construction)
  - Large request/response resource flags
  - Policy enforcement vectors
  - Timeout computation vectors
  - Round-trip integration vectors

Usage:
    python3 test_vectors/extract_requests.py

Output:
    test_vectors/requests.json
"""

import hashlib
import json
import math
import os
import struct
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

from RNS.vendor import umsgpack

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requests.json")
KEYPAIRS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")
LINKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "links.json")

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

# Packet types
PACKET_DATA = 0x00

# Header types
HEADER_1 = 0x00

# Destination types
DEST_LINK = 0x03

# Transport types
BROADCAST = 0x00

# Context flag values
FLAG_SET = 0x01

# Packet contexts
CONTEXT_NONE = 0x00
CONTEXT_REQUEST = 0x09
CONTEXT_RESPONSE = 0x0A

# Access policies (from Destination)
ALLOW_NONE = 0x00
ALLOW_ALL = 0x01
ALLOW_LIST = 0x02

# RequestReceipt statuses
RECEIPT_FAILED = 0x00
RECEIPT_SENT = 0x01
RECEIPT_DELIVERED = 0x02
RECEIPT_RECEIVING = 0x03
RECEIPT_READY = 0x04

# Timeout constants
RESPONSE_MAX_GRACE_TIME = 10
TRAFFIC_TIMEOUT_FACTOR = 6


# --- Helper functions ---

def load_keypairs():
    with open(KEYPAIRS_PATH, "r") as f:
        data = json.load(f)
    return data["keypairs"]


def load_links_json():
    with open(LINKS_PATH, "r") as f:
        return json.load(f)


def full_hash(data):
    return hashlib.sha256(data).digest()


def truncated_hash(data):
    return hashlib.sha256(data).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def deterministic_data(index, length):
    """Generate deterministic data of given length via SHA-256 expansion."""
    seed = hashlib.sha256(b"reticulum_test_request_data_" + str(index).encode()).digest()
    result = b""
    counter = 0
    while len(result) < length:
        chunk = hashlib.sha256(seed + struct.pack(">I", counter)).digest()
        result += chunk
        counter += 1
    return result[:length]


def deterministic_iv(index):
    """Generate deterministic 16-byte IV."""
    return hashlib.sha256(b"reticulum_test_request_iv_" + str(index).encode()).digest()[:16]


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


def build_link_packet_flags():
    """Compute flags byte for a link DATA packet with FLAG_SET.

    flags = (HEADER_1<<6) | (FLAG_SET<<5) | (BROADCAST<<4) | (LINK<<2) | DATA
          = (0<<6) | (1<<5) | (0<<4) | (3<<2) | 0 = 0x2C
    """
    return (HEADER_1 << 6) | (FLAG_SET << 5) | (BROADCAST << 4) | (DEST_LINK << 2) | PACKET_DATA


def build_raw_packet(link_id, context_byte, token_data):
    """Build raw packet bytes for a link DATA packet.

    Header: flags(1) + hops(1) + link_id(16) + context(1) = 19 bytes
    """
    flags = build_link_packet_flags()
    hops = 0
    header = struct.pack("!B", flags) + struct.pack("!B", hops) + link_id + bytes([context_byte])
    return header + token_data


def get_hashable_part(raw):
    """Compute hashable part of a raw packet (HEADER_1 format).

    hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]
    """
    return bytes([raw[0] & 0x0F]) + raw[2:]


def get_truncated_hash(raw):
    """Get truncated hash (request_id) of a raw packet."""
    return truncated_hash(get_hashable_part(raw))


# ============================================================
# Extraction functions
# ============================================================

def extract_constants():
    """Extract all request/response protocol constants."""
    return {
        "packet_contexts": {
            "REQUEST": CONTEXT_REQUEST,
            "REQUEST_hex": f"0x{CONTEXT_REQUEST:02x}",
            "RESPONSE": CONTEXT_RESPONSE,
            "RESPONSE_hex": f"0x{CONTEXT_RESPONSE:02x}",
        },
        "access_policies": {
            "ALLOW_NONE": ALLOW_NONE,
            "ALLOW_NONE_hex": f"0x{ALLOW_NONE:02x}",
            "ALLOW_ALL": ALLOW_ALL,
            "ALLOW_ALL_hex": f"0x{ALLOW_ALL:02x}",
            "ALLOW_LIST": ALLOW_LIST,
            "ALLOW_LIST_hex": f"0x{ALLOW_LIST:02x}",
        },
        "receipt_statuses": {
            "FAILED": RECEIPT_FAILED,
            "SENT": RECEIPT_SENT,
            "DELIVERED": RECEIPT_DELIVERED,
            "RECEIVING": RECEIPT_RECEIVING,
            "READY": RECEIPT_READY,
        },
        "timeouts": {
            "RESPONSE_MAX_GRACE_TIME": RESPONSE_MAX_GRACE_TIME,
            "TRAFFIC_TIMEOUT_FACTOR": TRAFFIC_TIMEOUT_FACTOR,
        },
        "sizes": {
            "LINK_MDU": LINK_MDU,
            "LINK_MDU_derivation": f"floor(({MTU} - {IFAC_MIN_SIZE} - {HEADER_MINSIZE} - {TOKEN_OVERHEAD}) / {AES128_BLOCKSIZE}) * {AES128_BLOCKSIZE} - 1 = {LINK_MDU}",
        },
        "packet_flags": {
            "link_data_flags": build_link_packet_flags(),
            "link_data_flags_hex": f"0x{build_link_packet_flags():02x}",
            "link_data_flags_description": "HEADER_1 | FLAG_SET | BROADCAST | LINK | DATA",
            "link_data_flags_formula": "(0<<6) | (1<<5) | (0<<4) | (3<<2) | 0",
        },
    }


def extract_path_hash_vectors():
    """Extract path string → truncated hash vectors for handler routing."""
    vectors = []

    test_paths = [
        ("/echo", "Simple echo path"),
        ("/api/v1/status", "REST-style nested path"),
        ("/random/text", "Random text path"),
        ("/", "Single character path"),
        ("/a/very/long/path/that/tests/deep/nesting/levels/in/the/routing/table", "Long deeply nested path"),
    ]

    for idx, (path, desc) in enumerate(test_paths):
        path_bytes = path.encode("utf-8")
        path_hash = truncated_hash(path_bytes)

        vectors.append({
            "index": idx,
            "description": desc,
            "path": path,
            "path_bytes_hex": path_bytes.hex(),
            "path_hash": path_hash.hex(),
            "algorithm": "SHA256(path.encode('utf-8'))[:16]",
        })

    return vectors


def extract_request_serialization_vectors():
    """Extract request serialization vectors.

    Request format: umsgpack.packb([timestamp, path_hash, data])
    """
    vectors = []

    # Fixed timestamp for reproducibility
    fixed_timestamp = 1700000000.0

    test_cases = [
        # (path, data, description)
        ("/echo", None, "Request with None data"),
        ("/echo", b"hello world", "Request with bytes data"),
        ("/api/v1/status", {"key": "value", "count": 42}, "Request with dict data"),
    ]

    for idx, (path, data, desc) in enumerate(test_cases):
        path_hash = truncated_hash(path.encode("utf-8"))
        unpacked_request = [fixed_timestamp, path_hash, data]
        packed_request = umsgpack.packb(unpacked_request)
        fits_in_mdu = len(packed_request) <= LINK_MDU

        vector = {
            "index": idx,
            "description": desc,
            "path": path,
            "timestamp": fixed_timestamp,
            "path_hash": path_hash.hex(),
            "data_description": "None" if data is None else type(data).__name__,
            "packed_request_hex": packed_request.hex(),
            "packed_request_length": len(packed_request),
            "fits_in_mdu": fits_in_mdu,
            "mdu": LINK_MDU,
        }

        if data is not None and isinstance(data, bytes):
            vector["data_hex"] = data.hex()
        elif data is not None and isinstance(data, dict):
            vector["data_json"] = data

        vectors.append(vector)

    # Near-MDU case: data sized to make packed_request just fit
    path = "/echo"
    path_hash = truncated_hash(path.encode("utf-8"))
    # Measure overhead: timestamp + path_hash + empty bytes
    overhead_request = umsgpack.packb([fixed_timestamp, path_hash, b""])
    overhead = len(overhead_request) - 1  # -1 for the empty bytes fixstr
    # msgpack bin header overhead: 1 byte for fixstr up to 31, 2 bytes for bin8 up to 255
    # We want total packed = LINK_MDU exactly
    # For bin8 (length 32-255): header is 2 bytes; for bin16: 3 bytes
    # packed = overhead + 2 + data_len (for bin8 range)
    target_data_len = LINK_MDU - overhead - 2  # bin8: 0xc4 + length byte
    if target_data_len > 255:
        target_data_len = LINK_MDU - overhead - 3  # bin16

    near_mdu_data = deterministic_data(100, target_data_len)
    near_mdu_unpacked = [fixed_timestamp, path_hash, near_mdu_data]
    near_mdu_packed = umsgpack.packb(near_mdu_unpacked)

    # Adjust if not exact
    while len(near_mdu_packed) > LINK_MDU:
        target_data_len -= 1
        near_mdu_data = deterministic_data(100, target_data_len)
        near_mdu_unpacked = [fixed_timestamp, path_hash, near_mdu_data]
        near_mdu_packed = umsgpack.packb(near_mdu_unpacked)

    while len(near_mdu_packed) < LINK_MDU:
        target_data_len += 1
        near_mdu_data = deterministic_data(100, target_data_len)
        near_mdu_unpacked = [fixed_timestamp, path_hash, near_mdu_data]
        near_mdu_packed = umsgpack.packb(near_mdu_unpacked)

    # Back off by 1 if we overshot
    if len(near_mdu_packed) > LINK_MDU:
        target_data_len -= 1
        near_mdu_data = deterministic_data(100, target_data_len)
        near_mdu_unpacked = [fixed_timestamp, path_hash, near_mdu_data]
        near_mdu_packed = umsgpack.packb(near_mdu_unpacked)

    vectors.append({
        "index": len(vectors),
        "description": "Request at exact MDU boundary (fits)",
        "path": path,
        "timestamp": fixed_timestamp,
        "path_hash": path_hash.hex(),
        "data_length": len(near_mdu_data),
        "data_hex": near_mdu_data.hex(),
        "packed_request_hex": near_mdu_packed.hex(),
        "packed_request_length": len(near_mdu_packed),
        "fits_in_mdu": len(near_mdu_packed) <= LINK_MDU,
        "mdu": LINK_MDU,
    })

    # Over-MDU case: request that must go as Resource
    over_mdu_data = deterministic_data(200, LINK_MDU)  # data alone is MDU-sized → packed > MDU
    over_mdu_unpacked = [fixed_timestamp, path_hash, over_mdu_data]
    over_mdu_packed = umsgpack.packb(over_mdu_unpacked)
    assert len(over_mdu_packed) > LINK_MDU
    over_mdu_request_id = truncated_hash(over_mdu_packed)

    vectors.append({
        "index": len(vectors),
        "description": "Request exceeding MDU (sent as Resource)",
        "path": path,
        "timestamp": fixed_timestamp,
        "path_hash": path_hash.hex(),
        "data_length": len(over_mdu_data),
        "data_hex_prefix": over_mdu_data[:32].hex() + f"... ({len(over_mdu_data)} bytes total)",
        "packed_request_hex_prefix": over_mdu_packed[:32].hex() + f"... ({len(over_mdu_packed)} bytes total)",
        "packed_request_length": len(over_mdu_packed),
        "fits_in_mdu": False,
        "mdu": LINK_MDU,
        "request_id": over_mdu_request_id.hex(),
        "request_id_algorithm": "truncated_hash(packed_request) — used for large requests sent as Resource",
    })

    return vectors


def extract_response_serialization_vectors():
    """Extract response serialization vectors.

    Response format: umsgpack.packb([request_id, response_data])
    """
    vectors = []

    # Use a deterministic request_id
    fixed_request_id = truncated_hash(b"test_request_id_for_response_vectors")

    test_cases = [
        # (response_data, description)
        ("echo response", "String response"),
        (b"\x01\x02\x03\x04", "Bytes response"),
        ({"status": "ok", "result": 123}, "Dict response"),
    ]

    for idx, (response_data, desc) in enumerate(test_cases):
        packed_response = umsgpack.packb([fixed_request_id, response_data])
        fits_in_mdu = len(packed_response) <= LINK_MDU

        vector = {
            "index": idx,
            "description": desc,
            "request_id": fixed_request_id.hex(),
            "packed_response_hex": packed_response.hex(),
            "packed_response_length": len(packed_response),
            "fits_in_mdu": fits_in_mdu,
            "mdu": LINK_MDU,
        }

        if isinstance(response_data, str):
            vector["response_data"] = response_data
        elif isinstance(response_data, bytes):
            vector["response_data_hex"] = response_data.hex()
        elif isinstance(response_data, dict):
            vector["response_data_json"] = response_data

        vectors.append(vector)

    # Near-MDU response
    overhead_response = umsgpack.packb([fixed_request_id, b""])
    overhead = len(overhead_response) - 1
    target_len = LINK_MDU - overhead - 2  # bin8 header
    if target_len > 255:
        target_len = LINK_MDU - overhead - 3

    near_mdu_data = deterministic_data(300, target_len)
    near_mdu_packed = umsgpack.packb([fixed_request_id, near_mdu_data])

    while len(near_mdu_packed) > LINK_MDU:
        target_len -= 1
        near_mdu_data = deterministic_data(300, target_len)
        near_mdu_packed = umsgpack.packb([fixed_request_id, near_mdu_data])

    while len(near_mdu_packed) < LINK_MDU:
        target_len += 1
        near_mdu_data = deterministic_data(300, target_len)
        near_mdu_packed = umsgpack.packb([fixed_request_id, near_mdu_data])

    if len(near_mdu_packed) > LINK_MDU:
        target_len -= 1
        near_mdu_data = deterministic_data(300, target_len)
        near_mdu_packed = umsgpack.packb([fixed_request_id, near_mdu_data])

    vectors.append({
        "index": len(vectors),
        "description": "Response at exact MDU boundary (fits)",
        "request_id": fixed_request_id.hex(),
        "response_data_length": len(near_mdu_data),
        "response_data_hex": near_mdu_data.hex(),
        "packed_response_hex": near_mdu_packed.hex(),
        "packed_response_length": len(near_mdu_packed),
        "fits_in_mdu": len(near_mdu_packed) <= LINK_MDU,
        "mdu": LINK_MDU,
    })

    # Over-MDU response
    over_mdu_data = deterministic_data(400, LINK_MDU)
    over_mdu_packed = umsgpack.packb([fixed_request_id, over_mdu_data])
    assert len(over_mdu_packed) > LINK_MDU

    vectors.append({
        "index": len(vectors),
        "description": "Response exceeding MDU (sent as Resource)",
        "request_id": fixed_request_id.hex(),
        "response_data_length": len(over_mdu_data),
        "response_data_hex_prefix": over_mdu_data[:32].hex() + f"... ({len(over_mdu_data)} bytes total)",
        "packed_response_hex_prefix": over_mdu_packed[:32].hex() + f"... ({len(over_mdu_packed)} bytes total)",
        "packed_response_length": len(over_mdu_packed),
        "fits_in_mdu": False,
        "mdu": LINK_MDU,
    })

    return vectors


def extract_small_request_wire_vectors(derived_key, link_id):
    """Extract full encrypted packet construction for small requests.

    For requests that fit in MDU:
    1. Pack request: umsgpack.packb([timestamp, path_hash, data])
    2. Encrypt: Token(derived_key).encrypt(packed_request) with deterministic IV
    3. Build header: flags(1) + hops(1) + link_id(16) + context(1) = 19 bytes
    4. raw = header + token_data
    5. hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]
    6. request_id = truncated_hash(hashable_part)
    """
    vectors = []

    fixed_timestamp = 1700000000.0

    test_cases = [
        # (path, data, iv_index, description)
        ("/echo", None, 0, "Small request: None data"),
        ("/echo", b"hello", 1, "Small request: bytes data"),
        ("/api/v1/status", {"query": "test"}, 2, "Small request: dict data"),
    ]

    for idx, (path, data, iv_index, desc) in enumerate(test_cases):
        path_hash = truncated_hash(path.encode("utf-8"))
        unpacked_request = [fixed_timestamp, path_hash, data]
        packed_request = umsgpack.packb(unpacked_request)
        assert len(packed_request) <= LINK_MDU, f"Test case {idx} exceeds MDU"

        iv = deterministic_iv(iv_index)
        token_data = token_encrypt_deterministic(packed_request, derived_key, iv)

        raw = build_raw_packet(link_id, CONTEXT_REQUEST, token_data)
        hashable_part = get_hashable_part(raw)
        request_id = truncated_hash(hashable_part)

        # Verify decryption round-trip
        decrypted = token_decrypt(token_data, derived_key)
        assert decrypted == packed_request, f"Decryption round-trip failed for case {idx}"

        # Verify unpacking
        unpacked = umsgpack.unpackb(decrypted)
        assert unpacked[1] == path_hash, f"Path hash mismatch for case {idx}"

        vectors.append({
            "index": idx,
            "description": desc,
            "path": path,
            "timestamp": fixed_timestamp,
            "path_hash": path_hash.hex(),
            "data_description": "None" if data is None else type(data).__name__,
            "packed_request_hex": packed_request.hex(),
            "packed_request_length": len(packed_request),
            "iv": iv.hex(),
            "token_data_hex": token_data.hex(),
            "token_data_length": len(token_data),
            "flags_byte": f"0x{build_link_packet_flags():02x}",
            "context_byte": f"0x{CONTEXT_REQUEST:02x}",
            "link_id": link_id.hex(),
            "raw_packet_hex": raw.hex(),
            "raw_packet_length": len(raw),
            "hashable_part_hex": hashable_part.hex(),
            "hashable_part_length": len(hashable_part),
            "request_id": request_id.hex(),
            "request_id_algorithm": "truncated_hash(hashable_part) where hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]",
        })

    return vectors


def extract_small_response_wire_vectors(derived_key, link_id, request_ids):
    """Extract full encrypted packet construction for small responses.

    Response payload: umsgpack.packb([request_id, response_data])
    Context: RESPONSE (0x0A)
    """
    vectors = []

    test_cases = [
        # (request_id_index, response_data, iv_index, description)
        (0, "echo reply", 10, "Small response: string data"),
        (1, b"\xde\xad\xbe\xef", 11, "Small response: bytes data"),
        (2, {"status": "ok"}, 12, "Small response: dict data"),
    ]

    for idx, (req_id_idx, response_data, iv_index, desc) in enumerate(test_cases):
        request_id = request_ids[req_id_idx]
        packed_response = umsgpack.packb([request_id, response_data])
        assert len(packed_response) <= LINK_MDU, f"Response case {idx} exceeds MDU"

        iv = deterministic_iv(iv_index)
        token_data = token_encrypt_deterministic(packed_response, derived_key, iv)

        raw = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data)
        hashable_part = get_hashable_part(raw)
        packet_hash = full_hash(hashable_part)

        # Verify decryption round-trip
        decrypted = token_decrypt(token_data, derived_key)
        assert decrypted == packed_response, f"Response decryption round-trip failed for case {idx}"

        # Verify unpacking
        unpacked = umsgpack.unpackb(decrypted)
        assert unpacked[0] == request_id, f"Request ID mismatch in response for case {idx}"

        vector = {
            "index": idx,
            "description": desc,
            "request_id": request_id.hex(),
            "packed_response_hex": packed_response.hex(),
            "packed_response_length": len(packed_response),
            "iv": iv.hex(),
            "token_data_hex": token_data.hex(),
            "token_data_length": len(token_data),
            "flags_byte": f"0x{build_link_packet_flags():02x}",
            "context_byte": f"0x{CONTEXT_RESPONSE:02x}",
            "link_id": link_id.hex(),
            "raw_packet_hex": raw.hex(),
            "raw_packet_length": len(raw),
            "hashable_part_hex": hashable_part.hex(),
            "hashable_part_length": len(hashable_part),
            "packet_hash": packet_hash.hex(),
        }

        if isinstance(response_data, str):
            vector["response_data"] = response_data
        elif isinstance(response_data, bytes):
            vector["response_data_hex"] = response_data.hex()
        elif isinstance(response_data, dict):
            vector["response_data_json"] = response_data

        vectors.append(vector)

    return vectors


def extract_large_request_resource_vectors():
    """Extract vectors for requests/responses that exceed MDU and go as Resources.

    For large requests:
    - request_id = truncated_hash(packed_request)
    - Resource created with: request_id=request_id, is_response=False

    For large responses:
    - Resource created with: request_id=request_id, is_response=True
    - packed_response = umsgpack.packb([request_id, response_data])
    """
    vectors = []

    fixed_timestamp = 1700000000.0

    # Large request
    path = "/upload"
    path_hash = truncated_hash(path.encode("utf-8"))
    large_data = deterministic_data(500, LINK_MDU + 100)
    unpacked_request = [fixed_timestamp, path_hash, large_data]
    packed_request = umsgpack.packb(unpacked_request)
    assert len(packed_request) > LINK_MDU
    request_id = truncated_hash(packed_request)

    vectors.append({
        "index": 0,
        "description": "Large request sent as Resource",
        "type": "request",
        "path": path,
        "timestamp": fixed_timestamp,
        "path_hash": path_hash.hex(),
        "data_length": len(large_data),
        "packed_request_length": len(packed_request),
        "exceeds_mdu": True,
        "request_id": request_id.hex(),
        "request_id_algorithm": "truncated_hash(packed_request)",
        "resource_params": {
            "is_response": False,
            "request_id": request_id.hex(),
        },
        "receiver_side": {
            "note": "Receiver computes request_id = truncated_hash(packed_request) after resource transfer completes",
            "unpacked_structure": "[timestamp, path_hash, data]",
        },
    })

    # Large response
    large_response_data = deterministic_data(600, LINK_MDU + 100)
    packed_response = umsgpack.packb([request_id, large_response_data])
    assert len(packed_response) > LINK_MDU

    vectors.append({
        "index": 1,
        "description": "Large response sent as Resource",
        "type": "response",
        "request_id": request_id.hex(),
        "response_data_length": len(large_response_data),
        "packed_response_length": len(packed_response),
        "exceeds_mdu": True,
        "resource_params": {
            "is_response": True,
            "request_id": request_id.hex(),
        },
        "receiver_side": {
            "note": "Receiver unpacks: [request_id, response_data] = umsgpack.unpackb(resource.data.read())",
            "unpacked_structure": "[request_id, response_data]",
        },
    })

    return vectors


def extract_policy_vectors(keypairs):
    """Extract access policy enforcement vectors.

    Logic from Link.handle_request():
      allowed = False
      if allow != ALLOW_NONE:
          if allow == ALLOW_LIST:
              if remote_identity is not None and remote_identity.hash in allowed_list:
                  allowed = True
          elif allow == ALLOW_ALL:
              allowed = True
    """
    vectors = []

    identity_hash_0 = bytes.fromhex(keypairs[0]["identity_hash"])
    identity_hash_1 = bytes.fromhex(keypairs[1]["identity_hash"])
    allowed_list = [identity_hash_0]

    cases = [
        # (policy, remote_identity_hash, expected, description)
        (ALLOW_NONE, identity_hash_0, False, "ALLOW_NONE: always blocked (even with valid identity)"),
        (ALLOW_NONE, None, False, "ALLOW_NONE: always blocked (no identity)"),
        (ALLOW_ALL, identity_hash_0, True, "ALLOW_ALL: always allowed (with identity)"),
        (ALLOW_ALL, None, True, "ALLOW_ALL: always allowed (no identity)"),
        (ALLOW_LIST, identity_hash_0, True, "ALLOW_LIST: identity in list → allowed"),
        (ALLOW_LIST, identity_hash_1, False, "ALLOW_LIST: identity not in list → blocked"),
        (ALLOW_LIST, None, False, "ALLOW_LIST: no identity (unidentified peer) → blocked"),
    ]

    policy_names = {ALLOW_NONE: "ALLOW_NONE", ALLOW_ALL: "ALLOW_ALL", ALLOW_LIST: "ALLOW_LIST"}

    for idx, (policy, remote_hash, expected, desc) in enumerate(cases):
        vector = {
            "index": idx,
            "description": desc,
            "policy": policy,
            "policy_name": policy_names[policy],
            "remote_identity_hash": remote_hash.hex() if remote_hash else None,
            "allowed_list": [h.hex() for h in allowed_list],
            "expected_allowed": expected,
        }

        # Reproduce the logic
        allowed = False
        if not policy == ALLOW_NONE:
            if policy == ALLOW_LIST:
                if remote_hash is not None and remote_hash in allowed_list:
                    allowed = True
            elif policy == ALLOW_ALL:
                allowed = True

        assert allowed == expected, f"Policy case {idx}: expected {expected}, got {allowed}"
        vector["computed_allowed"] = allowed
        vectors.append(vector)

    return vectors


def extract_timeout_vectors():
    """Extract timeout computation vectors.

    Formula: timeout = rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125
    """
    vectors = []

    rtt_values = [0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0]

    for idx, rtt in enumerate(rtt_values):
        timeout = rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125
        vectors.append({
            "index": idx,
            "description": f"Timeout for RTT={rtt}s",
            "rtt": rtt,
            "traffic_timeout_factor": TRAFFIC_TIMEOUT_FACTOR,
            "response_max_grace_time": RESPONSE_MAX_GRACE_TIME,
            "grace_multiplier": 1.125,
            "timeout": timeout,
            "formula": "rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125",
            "computation": f"{rtt} * {TRAFFIC_TIMEOUT_FACTOR} + {RESPONSE_MAX_GRACE_TIME} * 1.125 = {rtt * TRAFFIC_TIMEOUT_FACTOR} + {RESPONSE_MAX_GRACE_TIME * 1.125} = {timeout}",
        })

    return vectors


def extract_round_trip_vectors(derived_key, link_id):
    """Extract complete request/response lifecycle vectors.

    1. Handler registration: path → path_hash
    2. Request packing and encryption
    3. request_id derivation from raw packet
    4. Receiver: decrypt, unpack, handler lookup by path_hash
    5. Response generation, packing, encryption
    6. Initiator: decrypt, unpack, match request_id
    """
    vectors = []

    # Round-trip 0: Simple echo
    path = "/echo"
    request_data = b"ping"
    response_data = b"pong"
    fixed_timestamp = 1700000000.0

    # Step 1: Handler registration
    path_hash = truncated_hash(path.encode("utf-8"))

    # Step 2: Request packing
    unpacked_request = [fixed_timestamp, path_hash, request_data]
    packed_request = umsgpack.packb(unpacked_request)
    assert len(packed_request) <= LINK_MDU

    # Step 3: Encrypt request
    iv_req = deterministic_iv(50)
    token_data_req = token_encrypt_deterministic(packed_request, derived_key, iv_req)
    raw_req = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req)
    hashable_part_req = get_hashable_part(raw_req)
    request_id = truncated_hash(hashable_part_req)

    # Step 4: Receiver decrypts and unpacks
    decrypted_request = token_decrypt(token_data_req, derived_key)
    assert decrypted_request == packed_request
    unpacked_at_receiver = umsgpack.unpackb(decrypted_request)
    received_timestamp = unpacked_at_receiver[0]
    received_path_hash = unpacked_at_receiver[1]
    received_data = unpacked_at_receiver[2]
    assert received_path_hash == path_hash
    assert received_data == request_data

    # Step 5: Response generation and encryption
    packed_response = umsgpack.packb([request_id, response_data])
    assert len(packed_response) <= LINK_MDU

    iv_resp = deterministic_iv(51)
    token_data_resp = token_encrypt_deterministic(packed_response, derived_key, iv_resp)
    raw_resp = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp)

    # Step 6: Initiator decrypts and matches
    decrypted_response = token_decrypt(token_data_resp, derived_key)
    assert decrypted_response == packed_response
    unpacked_response = umsgpack.unpackb(decrypted_response)
    response_request_id = unpacked_response[0]
    response_payload = unpacked_response[1]
    assert response_request_id == request_id
    assert response_payload == response_data

    vectors.append({
        "index": 0,
        "description": "Complete echo request/response lifecycle",
        "path": path,
        "timestamp": fixed_timestamp,
        "request_data_hex": request_data.hex(),
        "response_data_hex": response_data.hex(),
        "step_1_registration": {
            "path": path,
            "path_hash": path_hash.hex(),
        },
        "step_2_request_packing": {
            "unpacked_request": f"[{fixed_timestamp}, path_hash, request_data]",
            "packed_request_hex": packed_request.hex(),
            "packed_request_length": len(packed_request),
        },
        "step_3_request_encryption": {
            "iv": iv_req.hex(),
            "token_data_hex": token_data_req.hex(),
            "raw_packet_hex": raw_req.hex(),
            "raw_packet_length": len(raw_req),
            "hashable_part_hex": hashable_part_req.hex(),
            "request_id": request_id.hex(),
        },
        "step_4_receiver_decrypt": {
            "decrypted_matches": decrypted_request == packed_request,
            "received_timestamp": received_timestamp,
            "received_path_hash": received_path_hash.hex(),
            "received_data_hex": received_data.hex() if isinstance(received_data, bytes) else str(received_data),
            "path_hash_lookup_matches": received_path_hash == path_hash,
        },
        "step_5_response_encryption": {
            "packed_response_hex": packed_response.hex(),
            "packed_response_length": len(packed_response),
            "iv": iv_resp.hex(),
            "token_data_hex": token_data_resp.hex(),
            "raw_packet_hex": raw_resp.hex(),
            "raw_packet_length": len(raw_resp),
        },
        "step_6_initiator_decrypt": {
            "decrypted_matches": decrypted_response == packed_response,
            "response_request_id": response_request_id.hex(),
            "response_request_id_matches": response_request_id == request_id,
            "response_payload_hex": response_payload.hex() if isinstance(response_payload, bytes) else str(response_payload),
            "payload_matches": response_payload == response_data,
        },
        "verified": True,
    })

    # Round-trip 1: Dict request/response with string path
    path2 = "/api/v1/query"
    request_data2 = {"action": "lookup", "id": 42}
    response_data2 = {"status": "found", "name": "test_item"}
    fixed_timestamp2 = 1700000001.0

    path_hash2 = truncated_hash(path2.encode("utf-8"))
    unpacked_request2 = [fixed_timestamp2, path_hash2, request_data2]
    packed_request2 = umsgpack.packb(unpacked_request2)
    assert len(packed_request2) <= LINK_MDU

    iv_req2 = deterministic_iv(52)
    token_data_req2 = token_encrypt_deterministic(packed_request2, derived_key, iv_req2)
    raw_req2 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req2)
    hashable_part_req2 = get_hashable_part(raw_req2)
    request_id2 = truncated_hash(hashable_part_req2)

    decrypted_request2 = token_decrypt(token_data_req2, derived_key)
    assert decrypted_request2 == packed_request2

    packed_response2 = umsgpack.packb([request_id2, response_data2])
    assert len(packed_response2) <= LINK_MDU

    iv_resp2 = deterministic_iv(53)
    token_data_resp2 = token_encrypt_deterministic(packed_response2, derived_key, iv_resp2)
    raw_resp2 = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp2)

    decrypted_response2 = token_decrypt(token_data_resp2, derived_key)
    unpacked_response2 = umsgpack.unpackb(decrypted_response2)
    assert unpacked_response2[0] == request_id2

    vectors.append({
        "index": 1,
        "description": "Dict request/response lifecycle",
        "path": path2,
        "timestamp": fixed_timestamp2,
        "request_data_json": request_data2,
        "response_data_json": response_data2,
        "step_1_registration": {
            "path": path2,
            "path_hash": path_hash2.hex(),
        },
        "step_2_request_packing": {
            "packed_request_hex": packed_request2.hex(),
            "packed_request_length": len(packed_request2),
        },
        "step_3_request_encryption": {
            "iv": iv_req2.hex(),
            "token_data_hex": token_data_req2.hex(),
            "raw_packet_hex": raw_req2.hex(),
            "raw_packet_length": len(raw_req2),
            "hashable_part_hex": hashable_part_req2.hex(),
            "request_id": request_id2.hex(),
        },
        "step_5_response_encryption": {
            "packed_response_hex": packed_response2.hex(),
            "packed_response_length": len(packed_response2),
            "iv": iv_resp2.hex(),
            "token_data_hex": token_data_resp2.hex(),
            "raw_packet_hex": raw_resp2.hex(),
            "raw_packet_length": len(raw_resp2),
        },
        "step_6_initiator_decrypt": {
            "response_request_id": unpacked_response2[0].hex(),
            "response_request_id_matches": unpacked_response2[0] == request_id2,
        },
        "verified": True,
    })

    # Round-trip 2: None data request and response
    path3 = "/echo"
    request_data3 = None
    response_data3 = None
    fixed_timestamp3 = 1700000002.0

    path_hash3 = truncated_hash(path3.encode("utf-8"))
    unpacked_request3 = [fixed_timestamp3, path_hash3, request_data3]
    packed_request3 = umsgpack.packb(unpacked_request3)
    assert len(packed_request3) <= LINK_MDU

    iv_req3 = deterministic_iv(60)
    token_data_req3 = token_encrypt_deterministic(packed_request3, derived_key, iv_req3)
    raw_req3 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req3)
    hashable_part_req3 = get_hashable_part(raw_req3)
    request_id3 = truncated_hash(hashable_part_req3)

    decrypted_request3 = token_decrypt(token_data_req3, derived_key)
    assert decrypted_request3 == packed_request3

    packed_response3 = umsgpack.packb([request_id3, response_data3])
    assert len(packed_response3) <= LINK_MDU

    iv_resp3 = deterministic_iv(61)
    token_data_resp3 = token_encrypt_deterministic(packed_response3, derived_key, iv_resp3)
    raw_resp3 = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp3)

    decrypted_response3 = token_decrypt(token_data_resp3, derived_key)
    unpacked_response3 = umsgpack.unpackb(decrypted_response3)
    assert unpacked_response3[0] == request_id3

    vectors.append({
        "index": 2,
        "description": "None data request/response lifecycle",
        "path": path3,
        "timestamp": fixed_timestamp3,
        "request_data": None,
        "response_data": None,
        "transport_mode": {"request": "inline", "response": "inline"},
        "step_1_registration": {
            "path": path3,
            "path_hash": path_hash3.hex(),
        },
        "step_2_request_packing": {
            "packed_request_hex": packed_request3.hex(),
            "packed_request_length": len(packed_request3),
        },
        "step_3_request_encryption": {
            "iv": iv_req3.hex(),
            "token_data_hex": token_data_req3.hex(),
            "raw_packet_hex": raw_req3.hex(),
            "raw_packet_length": len(raw_req3),
            "hashable_part_hex": hashable_part_req3.hex(),
            "request_id": request_id3.hex(),
        },
        "step_5_response_encryption": {
            "packed_response_hex": packed_response3.hex(),
            "packed_response_length": len(packed_response3),
            "iv": iv_resp3.hex(),
            "token_data_hex": token_data_resp3.hex(),
            "raw_packet_hex": raw_resp3.hex(),
            "raw_packet_length": len(raw_resp3),
        },
        "step_6_initiator_decrypt": {
            "response_request_id": unpacked_response3[0].hex(),
            "response_request_id_matches": unpacked_response3[0] == request_id3,
        },
        "verified": True,
    })

    # Round-trip 3: Integer data
    path4 = "/echo"
    request_data4 = 42
    response_data4 = 9999
    fixed_timestamp4 = 1700000003.0

    path_hash4 = truncated_hash(path4.encode("utf-8"))
    unpacked_request4 = [fixed_timestamp4, path_hash4, request_data4]
    packed_request4 = umsgpack.packb(unpacked_request4)
    assert len(packed_request4) <= LINK_MDU

    iv_req4 = deterministic_iv(62)
    token_data_req4 = token_encrypt_deterministic(packed_request4, derived_key, iv_req4)
    raw_req4 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req4)
    hashable_part_req4 = get_hashable_part(raw_req4)
    request_id4 = truncated_hash(hashable_part_req4)

    decrypted_request4 = token_decrypt(token_data_req4, derived_key)
    assert decrypted_request4 == packed_request4

    packed_response4 = umsgpack.packb([request_id4, response_data4])
    assert len(packed_response4) <= LINK_MDU

    iv_resp4 = deterministic_iv(63)
    token_data_resp4 = token_encrypt_deterministic(packed_response4, derived_key, iv_resp4)
    raw_resp4 = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp4)

    decrypted_response4 = token_decrypt(token_data_resp4, derived_key)
    unpacked_response4 = umsgpack.unpackb(decrypted_response4)
    assert unpacked_response4[0] == request_id4
    assert unpacked_response4[1] == response_data4

    vectors.append({
        "index": 3,
        "description": "Integer data request/response lifecycle",
        "path": path4,
        "timestamp": fixed_timestamp4,
        "request_data": request_data4,
        "response_data": response_data4,
        "transport_mode": {"request": "inline", "response": "inline"},
        "step_1_registration": {
            "path": path4,
            "path_hash": path_hash4.hex(),
        },
        "step_2_request_packing": {
            "packed_request_hex": packed_request4.hex(),
            "packed_request_length": len(packed_request4),
        },
        "step_3_request_encryption": {
            "iv": iv_req4.hex(),
            "token_data_hex": token_data_req4.hex(),
            "raw_packet_hex": raw_req4.hex(),
            "raw_packet_length": len(raw_req4),
            "hashable_part_hex": hashable_part_req4.hex(),
            "request_id": request_id4.hex(),
        },
        "step_5_response_encryption": {
            "packed_response_hex": packed_response4.hex(),
            "packed_response_length": len(packed_response4),
            "iv": iv_resp4.hex(),
            "token_data_hex": token_data_resp4.hex(),
            "raw_packet_hex": raw_resp4.hex(),
            "raw_packet_length": len(raw_resp4),
        },
        "step_6_initiator_decrypt": {
            "response_request_id": unpacked_response4[0].hex(),
            "response_request_id_matches": unpacked_response4[0] == request_id4,
            "response_payload": unpacked_response4[1],
            "payload_matches": unpacked_response4[1] == response_data4,
        },
        "verified": True,
    })

    # Round-trip 4: List data
    path5 = "/echo"
    request_data5 = [1, "two", b"\x03"]
    response_data5 = ["ok", True]
    fixed_timestamp5 = 1700000004.0

    path_hash5 = truncated_hash(path5.encode("utf-8"))
    unpacked_request5 = [fixed_timestamp5, path_hash5, request_data5]
    packed_request5 = umsgpack.packb(unpacked_request5)
    assert len(packed_request5) <= LINK_MDU

    iv_req5 = deterministic_iv(64)
    token_data_req5 = token_encrypt_deterministic(packed_request5, derived_key, iv_req5)
    raw_req5 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req5)
    hashable_part_req5 = get_hashable_part(raw_req5)
    request_id5 = truncated_hash(hashable_part_req5)

    decrypted_request5 = token_decrypt(token_data_req5, derived_key)
    assert decrypted_request5 == packed_request5

    packed_response5 = umsgpack.packb([request_id5, response_data5])
    assert len(packed_response5) <= LINK_MDU

    iv_resp5 = deterministic_iv(65)
    token_data_resp5 = token_encrypt_deterministic(packed_response5, derived_key, iv_resp5)
    raw_resp5 = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp5)

    decrypted_response5 = token_decrypt(token_data_resp5, derived_key)
    unpacked_response5 = umsgpack.unpackb(decrypted_response5)
    assert unpacked_response5[0] == request_id5

    vectors.append({
        "index": 4,
        "description": "List data request/response lifecycle",
        "path": path5,
        "timestamp": fixed_timestamp5,
        "request_data_description": "[1, 'two', b'\\x03']",
        "response_data_description": "['ok', True]",
        "transport_mode": {"request": "inline", "response": "inline"},
        "step_1_registration": {
            "path": path5,
            "path_hash": path_hash5.hex(),
        },
        "step_2_request_packing": {
            "packed_request_hex": packed_request5.hex(),
            "packed_request_length": len(packed_request5),
        },
        "step_3_request_encryption": {
            "iv": iv_req5.hex(),
            "token_data_hex": token_data_req5.hex(),
            "raw_packet_hex": raw_req5.hex(),
            "raw_packet_length": len(raw_req5),
            "hashable_part_hex": hashable_part_req5.hex(),
            "request_id": request_id5.hex(),
        },
        "step_5_response_encryption": {
            "packed_response_hex": packed_response5.hex(),
            "packed_response_length": len(packed_response5),
            "iv": iv_resp5.hex(),
            "token_data_hex": token_data_resp5.hex(),
            "raw_packet_hex": raw_resp5.hex(),
            "raw_packet_length": len(raw_resp5),
        },
        "step_6_initiator_decrypt": {
            "response_request_id": unpacked_response5[0].hex(),
            "response_request_id_matches": unpacked_response5[0] == request_id5,
        },
        "verified": True,
    })

    # Round-trip 5: Near-MDU request (inline), small response (inline)
    path6 = "/echo"
    fixed_timestamp6 = 1700000005.0
    path_hash6 = truncated_hash(path6.encode("utf-8"))

    # Size request data to make packed_request just fit in MDU
    overhead_req6 = umsgpack.packb([fixed_timestamp6, path_hash6, b""])
    overhead6 = len(overhead_req6) - 1
    target_data_len6 = LINK_MDU - overhead6 - 2  # bin8 header
    if target_data_len6 > 255:
        target_data_len6 = LINK_MDU - overhead6 - 3  # bin16

    near_mdu_data6 = deterministic_data(600, target_data_len6)
    near_mdu_packed6 = umsgpack.packb([fixed_timestamp6, path_hash6, near_mdu_data6])

    while len(near_mdu_packed6) > LINK_MDU:
        target_data_len6 -= 1
        near_mdu_data6 = deterministic_data(600, target_data_len6)
        near_mdu_packed6 = umsgpack.packb([fixed_timestamp6, path_hash6, near_mdu_data6])

    while len(near_mdu_packed6) < LINK_MDU:
        target_data_len6 += 1
        near_mdu_data6 = deterministic_data(600, target_data_len6)
        near_mdu_packed6 = umsgpack.packb([fixed_timestamp6, path_hash6, near_mdu_data6])

    if len(near_mdu_packed6) > LINK_MDU:
        target_data_len6 -= 1
        near_mdu_data6 = deterministic_data(600, target_data_len6)
        near_mdu_packed6 = umsgpack.packb([fixed_timestamp6, path_hash6, near_mdu_data6])

    assert len(near_mdu_packed6) == LINK_MDU

    iv_req6 = deterministic_iv(66)
    token_data_req6 = token_encrypt_deterministic(near_mdu_packed6, derived_key, iv_req6)
    raw_req6 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req6)
    hashable_part_req6 = get_hashable_part(raw_req6)
    request_id6 = truncated_hash(hashable_part_req6)

    decrypted_request6 = token_decrypt(token_data_req6, derived_key)
    assert decrypted_request6 == near_mdu_packed6

    response_data6 = b"ack"
    packed_response6 = umsgpack.packb([request_id6, response_data6])
    assert len(packed_response6) <= LINK_MDU

    iv_resp6 = deterministic_iv(67)
    token_data_resp6 = token_encrypt_deterministic(packed_response6, derived_key, iv_resp6)
    raw_resp6 = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp6)

    decrypted_response6 = token_decrypt(token_data_resp6, derived_key)
    unpacked_response6 = umsgpack.unpackb(decrypted_response6)
    assert unpacked_response6[0] == request_id6
    assert unpacked_response6[1] == response_data6

    vectors.append({
        "index": 5,
        "description": "Near-MDU request (exact fit) with small response",
        "path": path6,
        "timestamp": fixed_timestamp6,
        "request_data_length": len(near_mdu_data6),
        "response_data_hex": response_data6.hex(),
        "transport_mode": {"request": "inline", "response": "inline"},
        "step_1_registration": {
            "path": path6,
            "path_hash": path_hash6.hex(),
        },
        "step_2_request_packing": {
            "packed_request_hex": near_mdu_packed6.hex(),
            "packed_request_length": len(near_mdu_packed6),
            "fits_exactly_in_mdu": len(near_mdu_packed6) == LINK_MDU,
        },
        "step_3_request_encryption": {
            "iv": iv_req6.hex(),
            "token_data_hex": token_data_req6.hex(),
            "raw_packet_hex": raw_req6.hex(),
            "raw_packet_length": len(raw_req6),
            "hashable_part_hex": hashable_part_req6.hex(),
            "request_id": request_id6.hex(),
        },
        "step_5_response_encryption": {
            "packed_response_hex": packed_response6.hex(),
            "packed_response_length": len(packed_response6),
            "iv": iv_resp6.hex(),
            "token_data_hex": token_data_resp6.hex(),
            "raw_packet_hex": raw_resp6.hex(),
            "raw_packet_length": len(raw_resp6),
        },
        "step_6_initiator_decrypt": {
            "response_request_id": unpacked_response6[0].hex(),
            "response_request_id_matches": unpacked_response6[0] == request_id6,
            "response_payload_hex": unpacked_response6[1].hex(),
            "payload_matches": unpacked_response6[1] == response_data6,
        },
        "verified": True,
    })

    # Round-trip 6: Over-MDU request (resource), small response (inline)
    path7 = "/echo"
    fixed_timestamp7 = 1700000006.0
    path_hash7 = truncated_hash(path7.encode("utf-8"))

    over_mdu_req_data7 = deterministic_data(700, LINK_MDU + 50)
    unpacked_request7 = [fixed_timestamp7, path_hash7, over_mdu_req_data7]
    packed_request7 = umsgpack.packb(unpacked_request7)
    assert len(packed_request7) > LINK_MDU
    request_id7 = truncated_hash(packed_request7)

    response_data7 = b"received"
    packed_response7 = umsgpack.packb([request_id7, response_data7])
    assert len(packed_response7) <= LINK_MDU

    iv_resp7 = deterministic_iv(68)
    token_data_resp7 = token_encrypt_deterministic(packed_response7, derived_key, iv_resp7)
    raw_resp7 = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp7)

    decrypted_response7 = token_decrypt(token_data_resp7, derived_key)
    unpacked_response7 = umsgpack.unpackb(decrypted_response7)
    assert unpacked_response7[0] == request_id7
    assert unpacked_response7[1] == response_data7

    vectors.append({
        "index": 6,
        "description": "Over-MDU request (resource) with small inline response",
        "path": path7,
        "timestamp": fixed_timestamp7,
        "request_data_length": len(over_mdu_req_data7),
        "response_data_hex": response_data7.hex(),
        "transport_mode": {"request": "resource", "response": "inline"},
        "step_1_registration": {
            "path": path7,
            "path_hash": path_hash7.hex(),
        },
        "step_2_request_packing": {
            "packed_request_length": len(packed_request7),
            "exceeds_mdu": True,
            "request_id": request_id7.hex(),
            "request_id_algorithm": "truncated_hash(packed_request) — large request sent as Resource",
        },
        "step_5_response_encryption": {
            "packed_response_hex": packed_response7.hex(),
            "packed_response_length": len(packed_response7),
            "iv": iv_resp7.hex(),
            "token_data_hex": token_data_resp7.hex(),
            "raw_packet_hex": raw_resp7.hex(),
            "raw_packet_length": len(raw_resp7),
        },
        "step_6_initiator_decrypt": {
            "response_request_id": unpacked_response7[0].hex(),
            "response_request_id_matches": unpacked_response7[0] == request_id7,
            "response_payload_hex": unpacked_response7[1].hex(),
            "payload_matches": unpacked_response7[1] == response_data7,
        },
        "verified": True,
    })

    # Round-trip 7: Small request (inline), over-MDU response (resource)
    path8 = "/echo"
    request_data8 = b"fetch"
    fixed_timestamp8 = 1700000007.0
    path_hash8 = truncated_hash(path8.encode("utf-8"))

    unpacked_request8 = [fixed_timestamp8, path_hash8, request_data8]
    packed_request8 = umsgpack.packb(unpacked_request8)
    assert len(packed_request8) <= LINK_MDU

    iv_req8 = deterministic_iv(69)
    token_data_req8 = token_encrypt_deterministic(packed_request8, derived_key, iv_req8)
    raw_req8 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req8)
    hashable_part_req8 = get_hashable_part(raw_req8)
    request_id8 = truncated_hash(hashable_part_req8)

    decrypted_request8 = token_decrypt(token_data_req8, derived_key)
    assert decrypted_request8 == packed_request8

    over_mdu_resp_data8 = deterministic_data(800, LINK_MDU + 50)
    packed_response8 = umsgpack.packb([request_id8, over_mdu_resp_data8])
    assert len(packed_response8) > LINK_MDU

    vectors.append({
        "index": 7,
        "description": "Small inline request with over-MDU response (resource)",
        "path": path8,
        "timestamp": fixed_timestamp8,
        "request_data_hex": request_data8.hex(),
        "response_data_length": len(over_mdu_resp_data8),
        "transport_mode": {"request": "inline", "response": "resource"},
        "step_1_registration": {
            "path": path8,
            "path_hash": path_hash8.hex(),
        },
        "step_2_request_packing": {
            "packed_request_hex": packed_request8.hex(),
            "packed_request_length": len(packed_request8),
        },
        "step_3_request_encryption": {
            "iv": iv_req8.hex(),
            "token_data_hex": token_data_req8.hex(),
            "raw_packet_hex": raw_req8.hex(),
            "raw_packet_length": len(raw_req8),
            "hashable_part_hex": hashable_part_req8.hex(),
            "request_id": request_id8.hex(),
        },
        "step_5_response_packing": {
            "packed_response_length": len(packed_response8),
            "exceeds_mdu": True,
            "note": "Response sent as Resource with request_id and is_response=True",
            "resource_params": {
                "is_response": True,
                "request_id": request_id8.hex(),
            },
        },
        "verified": True,
    })

    # Round-trip 8: Both request and response over-MDU (resource)
    path9 = "/echo"
    fixed_timestamp9 = 1700000008.0
    path_hash9 = truncated_hash(path9.encode("utf-8"))

    over_mdu_req_data9 = deterministic_data(900, LINK_MDU + 100)
    unpacked_request9 = [fixed_timestamp9, path_hash9, over_mdu_req_data9]
    packed_request9 = umsgpack.packb(unpacked_request9)
    assert len(packed_request9) > LINK_MDU
    request_id9 = truncated_hash(packed_request9)

    over_mdu_resp_data9 = deterministic_data(901, LINK_MDU + 100)
    packed_response9 = umsgpack.packb([request_id9, over_mdu_resp_data9])
    assert len(packed_response9) > LINK_MDU

    vectors.append({
        "index": 8,
        "description": "Both request and response over-MDU (both as resource)",
        "path": path9,
        "timestamp": fixed_timestamp9,
        "request_data_length": len(over_mdu_req_data9),
        "response_data_length": len(over_mdu_resp_data9),
        "transport_mode": {"request": "resource", "response": "resource"},
        "step_1_registration": {
            "path": path9,
            "path_hash": path_hash9.hex(),
        },
        "step_2_request_packing": {
            "packed_request_length": len(packed_request9),
            "exceeds_mdu": True,
            "request_id": request_id9.hex(),
            "request_id_algorithm": "truncated_hash(packed_request) — large request sent as Resource",
        },
        "step_5_response_packing": {
            "packed_response_length": len(packed_response9),
            "exceeds_mdu": True,
            "note": "Response sent as Resource with request_id and is_response=True",
            "resource_params": {
                "is_response": True,
                "request_id": request_id9.hex(),
            },
        },
        "verified": True,
    })

    # Round-trip 9: Nested dict data
    path10 = "/echo"
    request_data10 = {"user": {"id": 1, "name": "alice", "roles": ["admin", "user"]}}
    response_data10 = {"status": "ok", "user": {"id": 1, "active": True}}
    fixed_timestamp10 = 1700000009.0

    path_hash10 = truncated_hash(path10.encode("utf-8"))
    unpacked_request10 = [fixed_timestamp10, path_hash10, request_data10]
    packed_request10 = umsgpack.packb(unpacked_request10)
    assert len(packed_request10) <= LINK_MDU

    iv_req10 = deterministic_iv(70)
    token_data_req10 = token_encrypt_deterministic(packed_request10, derived_key, iv_req10)
    raw_req10 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req10)
    hashable_part_req10 = get_hashable_part(raw_req10)
    request_id10 = truncated_hash(hashable_part_req10)

    decrypted_request10 = token_decrypt(token_data_req10, derived_key)
    assert decrypted_request10 == packed_request10

    packed_response10 = umsgpack.packb([request_id10, response_data10])
    assert len(packed_response10) <= LINK_MDU

    iv_resp10 = deterministic_iv(71)
    token_data_resp10 = token_encrypt_deterministic(packed_response10, derived_key, iv_resp10)
    raw_resp10 = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp10)

    decrypted_response10 = token_decrypt(token_data_resp10, derived_key)
    unpacked_response10 = umsgpack.unpackb(decrypted_response10)
    assert unpacked_response10[0] == request_id10

    vectors.append({
        "index": 9,
        "description": "Nested dict request/response lifecycle",
        "path": path10,
        "timestamp": fixed_timestamp10,
        "request_data_json": request_data10,
        "response_data_json": response_data10,
        "transport_mode": {"request": "inline", "response": "inline"},
        "step_1_registration": {
            "path": path10,
            "path_hash": path_hash10.hex(),
        },
        "step_2_request_packing": {
            "packed_request_hex": packed_request10.hex(),
            "packed_request_length": len(packed_request10),
        },
        "step_3_request_encryption": {
            "iv": iv_req10.hex(),
            "token_data_hex": token_data_req10.hex(),
            "raw_packet_hex": raw_req10.hex(),
            "raw_packet_length": len(raw_req10),
            "hashable_part_hex": hashable_part_req10.hex(),
            "request_id": request_id10.hex(),
        },
        "step_5_response_encryption": {
            "packed_response_hex": packed_response10.hex(),
            "packed_response_length": len(packed_response10),
            "iv": iv_resp10.hex(),
            "token_data_hex": token_data_resp10.hex(),
            "raw_packet_hex": raw_resp10.hex(),
            "raw_packet_length": len(raw_resp10),
        },
        "step_6_initiator_decrypt": {
            "response_request_id": unpacked_response10[0].hex(),
            "response_request_id_matches": unpacked_response10[0] == request_id10,
        },
        "verified": True,
    })

    return vectors


def extract_receipt_lifecycle_vectors():
    """Extract RequestReceipt state machine lifecycle vectors.

    Documents the state transitions and callback invocations for different
    request/response transport combinations.

    Source: RNS/Link.py RequestReceipt class (lines 1356-1549)

    States:
      SENT (0x01) → initial state
      DELIVERED (0x02) → request resource transfer completed
      RECEIVING (0x03) → response resource transfer in progress
      READY (0x04) → response received successfully
      FAILED (0x00) → timeout or transfer failure

    Callbacks:
      response_callback(receipt) → called when status becomes READY
      failed_callback(receipt) → called when status becomes FAILED
      progress_callback(receipt) → called during response resource transfer
    """
    vectors = []

    # Vector 0: Inline request + inline response
    # Simplest path: SENT → READY
    vectors.append({
        "index": 0,
        "description": "Inline request with inline response (simplest path)",
        "request_transport": "inline",
        "response_transport": "inline",
        "round_trip_vector_index": 0,
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request packet sent"},
            {"status": RECEIPT_READY, "status_name": "READY",
             "trigger": "Response packet received and unpacked"},
        ],
        "callbacks_invoked": [
            {"callback": "response_callback", "at_status": "READY",
             "note": "Called with receipt; receipt.response contains response data"},
        ],
        "receipt_response": "Response data from unpacked response packet",
        "progress_at_completion": 1.0,
    })

    # Vector 1: Inline request + resource response
    # SENT → RECEIVING → READY
    vectors.append({
        "index": 1,
        "description": "Inline request with resource response",
        "request_transport": "inline",
        "response_transport": "resource",
        "round_trip_vector_index": 7,
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request packet sent"},
            {"status": RECEIPT_RECEIVING, "status_name": "RECEIVING",
             "trigger": "Response resource transfer begins (response_resource_progress called)"},
            {"status": RECEIPT_READY, "status_name": "READY",
             "trigger": "Response resource transfer completed (response_received called)"},
        ],
        "callbacks_invoked": [
            {"callback": "progress_callback", "at_status": "RECEIVING",
             "note": "Called multiple times as resource segments arrive; receipt.progress updated"},
            {"callback": "progress_callback", "at_status": "READY",
             "note": "Final progress_callback with progress=1.0"},
            {"callback": "response_callback", "at_status": "READY",
             "note": "Called with receipt; receipt.response contains response data"},
        ],
        "receipt_response": "Response data unpacked from completed resource",
        "progress_at_completion": 1.0,
    })

    # Vector 2: Resource request + inline response
    # SENT → DELIVERED → READY
    vectors.append({
        "index": 2,
        "description": "Resource request with inline response",
        "request_transport": "resource",
        "response_transport": "inline",
        "round_trip_vector_index": 6,
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request resource advertised"},
            {"status": RECEIPT_DELIVERED, "status_name": "DELIVERED",
             "trigger": "Request resource transfer completed (request_resource_concluded with success)"},
            {"status": RECEIPT_READY, "status_name": "READY",
             "trigger": "Response packet received and unpacked"},
        ],
        "callbacks_invoked": [
            {"callback": "response_callback", "at_status": "READY",
             "note": "Called with receipt; receipt.response contains response data"},
        ],
        "receipt_response": "Response data from unpacked response packet",
        "progress_at_completion": 1.0,
        "timeout_note": "Response timeout timer starts after DELIVERED state",
    })

    # Vector 3: Resource request + resource response
    # SENT → DELIVERED → RECEIVING → READY
    vectors.append({
        "index": 3,
        "description": "Resource request with resource response (full lifecycle)",
        "request_transport": "resource",
        "response_transport": "resource",
        "round_trip_vector_index": 8,
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request resource advertised"},
            {"status": RECEIPT_DELIVERED, "status_name": "DELIVERED",
             "trigger": "Request resource transfer completed (request_resource_concluded with success)"},
            {"status": RECEIPT_RECEIVING, "status_name": "RECEIVING",
             "trigger": "Response resource transfer begins (response_resource_progress called)"},
            {"status": RECEIPT_READY, "status_name": "READY",
             "trigger": "Response resource transfer completed (response_received called)"},
        ],
        "callbacks_invoked": [
            {"callback": "progress_callback", "at_status": "RECEIVING",
             "note": "Called multiple times as response resource segments arrive"},
            {"callback": "progress_callback", "at_status": "READY",
             "note": "Final progress_callback with progress=1.0"},
            {"callback": "response_callback", "at_status": "READY",
             "note": "Called with receipt; receipt.response contains response data"},
        ],
        "receipt_response": "Response data unpacked from completed resource",
        "progress_at_completion": 1.0,
        "timeout_note": "Response timeout timer starts after DELIVERED state",
    })

    # Vector 4: Resource request + timeout (no response)
    # SENT → DELIVERED → FAILED
    vectors.append({
        "index": 4,
        "description": "Resource request with response timeout",
        "request_transport": "resource",
        "response_transport": "none (timeout)",
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request resource advertised"},
            {"status": RECEIPT_DELIVERED, "status_name": "DELIVERED",
             "trigger": "Request resource transfer completed (request_resource_concluded with success)"},
            {"status": RECEIPT_FAILED, "status_name": "FAILED",
             "trigger": "Response timeout expired (request_timed_out called)"},
        ],
        "callbacks_invoked": [
            {"callback": "failed_callback", "at_status": "FAILED",
             "note": "Called with receipt; receipt.response is None"},
        ],
        "receipt_response": None,
        "timeout_formula": "rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125",
        "timeout_constants": {
            "TRAFFIC_TIMEOUT_FACTOR": TRAFFIC_TIMEOUT_FACTOR,
            "RESPONSE_MAX_GRACE_TIME": RESPONSE_MAX_GRACE_TIME,
        },
    })

    # Vector 5: Resource request + transfer failure
    # SENT → FAILED
    vectors.append({
        "index": 5,
        "description": "Resource request with transfer failure",
        "request_transport": "resource",
        "response_transport": "none (transfer failed)",
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request resource advertised"},
            {"status": RECEIPT_FAILED, "status_name": "FAILED",
             "trigger": "Request resource transfer failed (request_resource_concluded with failure)"},
        ],
        "callbacks_invoked": [
            {"callback": "failed_callback", "at_status": "FAILED",
             "note": "Called with receipt; receipt.response is None"},
        ],
        "receipt_response": None,
        "failure_note": "Resource transfer may fail due to link closure, timeout, or peer rejection",
    })

    return vectors


def extract_handler_registration_vectors(keypairs):
    """Extract handler registration storage structure vectors.

    Documents what register_request_handler() stores in self.request_handlers:
      path_hash = SHA256(path.encode('utf-8'))[:16]
      request_handlers[path_hash] = [path, response_generator, allow, allowed_list, auto_compress]
    """
    identity_hash_0 = bytes.fromhex(keypairs[0]["identity_hash"])

    test_cases = [
        # (path, allow, allowed_list, auto_compress, description)
        ("/echo", ALLOW_ALL, None, True, "Basic with defaults"),
        ("/api/v1/status", ALLOW_NONE, None, True, "Default deny policy"),
        ("/upload", ALLOW_LIST, [identity_hash_0], False, "With allow list"),
        ("/config", ALLOW_ALL, None, 4096, "Integer auto_compress threshold"),
    ]

    policy_names = {ALLOW_NONE: "ALLOW_NONE", ALLOW_ALL: "ALLOW_ALL", ALLOW_LIST: "ALLOW_LIST"}

    vectors = []
    all_handlers = {}

    for idx, (path, allow, allowed_list, auto_compress, desc) in enumerate(test_cases):
        path_hash = truncated_hash(path.encode("utf-8"))
        stored = [path, "response_generator", allow, allowed_list, auto_compress]
        all_handlers[path_hash] = stored

        vector = {
            "index": idx,
            "description": desc,
            "path": path,
            "path_hash": path_hash.hex(),
            "stored_structure": {
                "index_0_path": path,
                "index_1_response_generator": "callable (not serializable)",
                "index_2_allow": allow,
                "index_2_allow_name": policy_names[allow],
                "index_3_allowed_list": [h.hex() for h in allowed_list] if allowed_list else None,
                "index_4_auto_compress": auto_compress,
            },
            "dict_key": path_hash.hex(),
            "algorithm": "SHA256(path.encode('utf-8'))[:16]",
        }
        vectors.append(vector)

    # Multi-handler vector: final dict state after registering all 4
    multi_handler = {
        "description": "Final dict state after registering all 4 handlers",
        "dict_size": len(all_handlers),
        "keys": [ph.hex() for ph in all_handlers.keys()],
        "paths": [all_handlers[ph][0] for ph in all_handlers],
    }

    return {"individual_vectors": vectors, "multi_handler": multi_handler}


def extract_handler_deregistration_vectors():
    """Extract handler deregistration behavior vectors.

    Simulates dict operations matching Destination.deregister_request_handler()
    (Destination.py:399-411). Sequential scenarios building on previous state.
    """
    # Start with 2 registered handlers
    path_echo = "/echo"
    path_status = "/api/v1/status"
    hash_echo = truncated_hash(path_echo.encode("utf-8"))
    hash_status = truncated_hash(path_status.encode("utf-8"))

    handlers = {
        hash_echo: [path_echo, "generator", ALLOW_ALL, None, True],
        hash_status: [path_status, "generator", ALLOW_NONE, None, True],
    }

    initial_state = {
        "dict_size": len(handlers),
        "keys": [h.hex() for h in handlers.keys()],
    }

    steps = []

    # Step 1: Deregister /echo → True, size=1
    path_hash = truncated_hash(path_echo.encode("utf-8"))
    if path_hash in handlers:
        handlers.pop(path_hash)
        result = True
    else:
        result = False
    steps.append({
        "step": 1,
        "action": f"deregister '{path_echo}'",
        "path": path_echo,
        "path_hash": path_hash.hex(),
        "expected_return": result,
        "dict_size_after": len(handlers),
        "remaining_keys": [h.hex() for h in handlers.keys()],
    })

    # Step 2: Deregister /echo again → False, size=1
    path_hash = truncated_hash(path_echo.encode("utf-8"))
    if path_hash in handlers:
        handlers.pop(path_hash)
        result = True
    else:
        result = False
    steps.append({
        "step": 2,
        "action": f"deregister '{path_echo}' again (already removed)",
        "path": path_echo,
        "path_hash": path_hash.hex(),
        "expected_return": result,
        "dict_size_after": len(handlers),
        "remaining_keys": [h.hex() for h in handlers.keys()],
    })

    # Step 3: Deregister /nonexistent → False, size=1
    path_nonexistent = "/nonexistent"
    path_hash = truncated_hash(path_nonexistent.encode("utf-8"))
    if path_hash in handlers:
        handlers.pop(path_hash)
        result = True
    else:
        result = False
    steps.append({
        "step": 3,
        "action": f"deregister '{path_nonexistent}' (never registered)",
        "path": path_nonexistent,
        "path_hash": path_hash.hex(),
        "expected_return": result,
        "dict_size_after": len(handlers),
        "remaining_keys": [h.hex() for h in handlers.keys()],
    })

    # Step 4: Deregister /api/v1/status → True, size=0
    path_hash = truncated_hash(path_status.encode("utf-8"))
    if path_hash in handlers:
        handlers.pop(path_hash)
        result = True
    else:
        result = False
    steps.append({
        "step": 4,
        "action": f"deregister '{path_status}'",
        "path": path_status,
        "path_hash": path_hash.hex(),
        "expected_return": result,
        "dict_size_after": len(handlers),
        "remaining_keys": [h.hex() for h in handlers.keys()],
    })

    return {
        "initial_state": initial_state,
        "steps": steps,
        "note": "Steps are sequential — each builds on the previous dict state",
    }


def extract_handler_invocation_vectors(derived_key, link_id, keypairs):
    """Extract handler invocation dispatch vectors.

    Documents how Link.handle_request() (Link.py:857-886) dispatches to the
    response_generator based on inspect.signature parameter count.

    5-param: response_generator(path, request_data, request_id, remote_identity, requested_at)
    6-param: response_generator(path, request_data, request_id, link_id, remote_identity, requested_at)
    """
    identity_hash_0 = bytes.fromhex(keypairs[0]["identity_hash"])
    fixed_timestamp = 1700000000.0

    # Build request packets to derive request_ids (reusing small_request_wire logic)
    test_cases = [
        # (path, data, param_count, remote_identity_hash, iv_index, description)
        ("/echo", b"hello", 5, identity_hash_0, 20, "5-param dispatch"),
        ("/echo", b"hello", 6, identity_hash_0, 21, "6-param dispatch (with link_id)"),
        ("/api/v1/status", {"query": "test"}, 6, None, 22, "6-param, no remote identity"),
    ]

    vectors = []
    for idx, (path, data, param_count, remote_identity_hash, iv_index, desc) in enumerate(test_cases):
        path_hash = truncated_hash(path.encode("utf-8"))
        unpacked_request = [fixed_timestamp, path_hash, data]
        packed_request = umsgpack.packb(unpacked_request)

        iv = deterministic_iv(iv_index)
        token_data = token_encrypt_deterministic(packed_request, derived_key, iv)
        raw = build_raw_packet(link_id, CONTEXT_REQUEST, token_data)
        hashable_part = get_hashable_part(raw)
        request_id = truncated_hash(hashable_part)

        if param_count == 5:
            dispatch_args = {
                "arg_0_path": path,
                "arg_1_request_data": data.hex() if isinstance(data, bytes) else data,
                "arg_2_request_id": request_id.hex(),
                "arg_3_remote_identity": remote_identity_hash.hex() if remote_identity_hash else None,
                "arg_4_requested_at": fixed_timestamp,
            }
        else:
            dispatch_args = {
                "arg_0_path": path,
                "arg_1_request_data": data.hex() if isinstance(data, bytes) else data,
                "arg_2_request_id": request_id.hex(),
                "arg_3_link_id": link_id.hex(),
                "arg_4_remote_identity": remote_identity_hash.hex() if remote_identity_hash else None,
                "arg_5_requested_at": fixed_timestamp,
            }

        vector = {
            "index": idx,
            "description": desc,
            "path": path,
            "path_hash": path_hash.hex(),
            "timestamp": fixed_timestamp,
            "request_id": request_id.hex(),
            "param_count": param_count,
            "dispatch_args": dispatch_args,
            "dispatch_algorithm": (
                "if len(inspect.signature(response_generator).parameters) == 5: "
                "response_generator(path, request_data, request_id, remote_identity, requested_at); "
                "elif == 6: response_generator(path, request_data, request_id, link_id, remote_identity, requested_at)"
            ),
            "unpacked_request_indices": {
                "0": "requested_at (float timestamp)",
                "1": "path_hash (16 bytes, used for handler lookup)",
                "2": "request_data (arbitrary msgpack-serializable data)",
            },
        }
        vectors.append(vector)

    # Handler not found vector
    unknown_path = "/unknown"
    unknown_path_hash = truncated_hash(unknown_path.encode("utf-8"))
    vectors.append({
        "index": len(vectors),
        "description": "Handler not found (path_hash not in request_handlers dict)",
        "path": unknown_path,
        "path_hash": unknown_path_hash.hex(),
        "handler_found": False,
        "behavior": "Request silently ignored — no response sent, no error raised",
    })

    return vectors


def extract_handler_validation_vectors():
    """Extract handler registration validation (error condition) vectors.

    Documents error conditions from Destination.register_request_handler()
    (Destination.py:391-393).
    """
    valid_policies = [ALLOW_NONE, ALLOW_ALL, ALLOW_LIST]

    vectors = [
        {
            "index": 0,
            "path": None,
            "response_generator": "callable",
            "allow": ALLOW_ALL,
            "expected_error": "ValueError",
            "error_message": "Invalid path specified",
            "description": "path is None",
            "validation_rule": "path == None or path == ''",
        },
        {
            "index": 1,
            "path": "",
            "response_generator": "callable",
            "allow": ALLOW_ALL,
            "expected_error": "ValueError",
            "error_message": "Invalid path specified",
            "description": "path is empty string",
            "validation_rule": "path == None or path == ''",
        },
        {
            "index": 2,
            "path": "/echo",
            "response_generator": None,
            "allow": ALLOW_ALL,
            "expected_error": "ValueError",
            "error_message": "Invalid response generator specified",
            "description": "response_generator is None (not callable)",
            "validation_rule": "not callable(response_generator)",
        },
        {
            "index": 3,
            "path": "/echo",
            "response_generator": "a string",
            "allow": ALLOW_ALL,
            "expected_error": "ValueError",
            "error_message": "Invalid response generator specified",
            "description": "response_generator is a string (not callable)",
            "validation_rule": "not callable(response_generator)",
        },
        {
            "index": 4,
            "path": "/echo",
            "response_generator": "callable",
            "allow": 0xFF,
            "expected_error": "ValueError",
            "error_message": "Invalid request policy",
            "description": "invalid allow policy value (0xFF)",
            "validation_rule": "not allow in [ALLOW_NONE, ALLOW_ALL, ALLOW_LIST]",
        },
    ]

    return {
        "vectors": vectors,
        "valid_policies": valid_policies,
        "valid_policy_names": ["ALLOW_NONE (0x00)", "ALLOW_ALL (0x01)", "ALLOW_LIST (0x02)"],
        "note": "Validation occurs in order: path → response_generator → allow policy",
    }


def extract_policy_enforcement_wire_vectors(derived_key, link_id, keypairs):
    """Extract end-to-end wire-format vectors combining request + policy + response.

    7 vectors showing the full flow for each policy/identity combination.
    For allowed requests: full request AND response wire format.
    For denied requests: full request wire format, response=null, silent drop.

    IV range: 100-113 (2 IVs per vector that gets a response: req + resp)
    Timestamps: 1700000100.0+
    """
    identity_hash_0 = bytes.fromhex(keypairs[0]["identity_hash"])
    identity_hash_1 = bytes.fromhex(keypairs[1]["identity_hash"])
    allowed_list = [identity_hash_0]

    policy_names = {ALLOW_NONE: "ALLOW_NONE", ALLOW_ALL: "ALLOW_ALL", ALLOW_LIST: "ALLOW_LIST"}

    cases = [
        # (policy, remote_identity_hash, expected_allowed, iv_req, iv_resp, description)
        (ALLOW_ALL,  identity_hash_0, True,  100, 101, "ALLOW_ALL + identified peer"),
        (ALLOW_ALL,  None,            True,  102, 103, "ALLOW_ALL + unidentified peer"),
        (ALLOW_NONE, identity_hash_0, False, 104, None, "ALLOW_NONE + identified peer"),
        (ALLOW_NONE, None,            False, 105, None, "ALLOW_NONE + unidentified peer"),
        (ALLOW_LIST, identity_hash_0, True,  106, 107, "ALLOW_LIST + authorized identity"),
        (ALLOW_LIST, identity_hash_1, False, 108, None, "ALLOW_LIST + unauthorized identity"),
        (ALLOW_LIST, None,            False, 109, None, "ALLOW_LIST + unidentified peer"),
    ]

    path = "/echo"
    path_hash = truncated_hash(path.encode("utf-8"))
    response_data = b"echo_reply"

    vectors = []
    for idx, (policy, remote_hash, expected_allowed, iv_req_idx, iv_resp_idx, desc) in enumerate(cases):
        timestamp = 1700000100.0 + idx
        request_data = deterministic_data(1000 + idx, 32)

        # Build request wire format
        unpacked_request = [timestamp, path_hash, request_data]
        packed_request = umsgpack.packb(unpacked_request)
        assert len(packed_request) <= LINK_MDU

        iv_req = deterministic_iv(iv_req_idx)
        token_data_req = token_encrypt_deterministic(packed_request, derived_key, iv_req)
        raw_req = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_req)
        hashable_part_req = get_hashable_part(raw_req)
        request_id = truncated_hash(hashable_part_req)

        # Verify request decryption round-trip
        decrypted = token_decrypt(token_data_req, derived_key)
        assert decrypted == packed_request

        # Reproduce policy logic from Link.handle_request() (Link.py:871-877)
        allowed = False
        if not policy == ALLOW_NONE:
            if policy == ALLOW_LIST:
                if remote_hash is not None and remote_hash in allowed_list:
                    allowed = True
            elif policy == ALLOW_ALL:
                allowed = True
        assert allowed == expected_allowed

        vector = {
            "index": idx,
            "description": desc,
            "path": path,
            "path_hash": path_hash.hex(),
            "timestamp": timestamp,
            "request_data_hex": request_data.hex(),
            "policy": policy,
            "policy_name": policy_names[policy],
            "remote_identity_hash": remote_hash.hex() if remote_hash else None,
            "allowed_list": [h.hex() for h in allowed_list],
            "expected_allowed": expected_allowed,
            "request_wire": {
                "packed_request_hex": packed_request.hex(),
                "iv": iv_req.hex(),
                "token_data_hex": token_data_req.hex(),
                "raw_packet_hex": raw_req.hex(),
                "request_id": request_id.hex(),
            },
            "policy_trace": {
                "step_1_check_allow_none": f"policy ({policy_names[policy]}) == ALLOW_NONE? {policy == ALLOW_NONE}",
                "step_2_check_allow_list": f"policy == ALLOW_LIST? {policy == ALLOW_LIST}" if policy != ALLOW_NONE else "skipped (ALLOW_NONE)",
                "step_3_result": f"allowed = {allowed}",
            },
        }

        if expected_allowed:
            # Build response wire format
            packed_response = umsgpack.packb([request_id, response_data])
            assert len(packed_response) <= LINK_MDU

            iv_resp = deterministic_iv(iv_resp_idx)
            token_data_resp = token_encrypt_deterministic(packed_response, derived_key, iv_resp)
            raw_resp = build_raw_packet(link_id, CONTEXT_RESPONSE, token_data_resp)

            # Verify response round-trip
            decrypted_resp = token_decrypt(token_data_resp, derived_key)
            assert decrypted_resp == packed_response
            unpacked_resp = umsgpack.unpackb(decrypted_resp)
            assert unpacked_resp[0] == request_id

            vector["response_wire"] = {
                "response_data_hex": response_data.hex(),
                "packed_response_hex": packed_response.hex(),
                "iv": iv_resp.hex(),
                "token_data_hex": token_data_resp.hex(),
                "raw_packet_hex": raw_resp.hex(),
            }
            vector["server_behavior"] = "handler_invoked_and_response_sent"
        else:
            vector["response_wire"] = None
            vector["server_behavior"] = "silent_drop"
            vector["server_log"] = "Request <id> from <identity> not allowed for: <path>"
            vector["client_consequence"] = {
                "inline_request": (
                    "PacketReceipt is proved via link-layer implicit proof, so "
                    "PacketReceipt.status becomes DELIVERED. However, no response "
                    "arrives. PacketReceipt.check_timeout() only fires when status "
                    "== SENT, so timeout never triggers. RequestReceipt stays at "
                    "SENT indefinitely. failed_callback is never invoked."
                ),
                "resource_request": (
                    "Resource transfer completes, RequestReceipt transitions to "
                    "DELIVERED. __response_timeout_job polls until timeout expires, "
                    "then calls request_timed_out(). Since status == DELIVERED, "
                    "failed_callback IS invoked."
                ),
            }

        vectors.append(vector)

    return vectors


def extract_failure_callback_vectors(derived_key, link_id):
    """Extract receipt state vectors at failed_callback invocation time.

    5 vectors covering every failure path in the request/response protocol.

    For resource-transport requests (vectors 0-2): failed_callback IS invoked
    because request_timed_out() or request_resource_concluded() correctly
    transitions the receipt to FAILED.

    For inline-transport requests (vectors 3-4): failed_callback is NOT invoked
    due to the PacketReceipt/RequestReceipt status interaction described in the
    client_consequence notes.

    IV range: 114-123
    Timestamps: 1700000200.0+
    """
    path = "/echo"
    path_hash = truncated_hash(path.encode("utf-8"))
    vectors = []

    # --- Vector 0: Resource transfer failure (SENT -> FAILED) ---
    timestamp_0 = 1700000200.0
    data_0 = deterministic_data(2000, LINK_MDU + 50)
    unpacked_0 = [timestamp_0, path_hash, data_0]
    packed_0 = umsgpack.packb(unpacked_0)
    assert len(packed_0) > LINK_MDU
    request_id_0 = truncated_hash(packed_0)

    vectors.append({
        "index": 0,
        "description": "Resource transfer failure (request never delivered)",
        "transport": "resource",
        "request_id": request_id_0.hex(),
        "packed_request_length": len(packed_0),
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request resource advertised"},
            {"status": RECEIPT_FAILED, "status_name": "FAILED",
             "trigger": "request_resource_concluded() called with resource.status != COMPLETE"},
        ],
        "callback_invoked": True,
        "callback": "failed_callback",
        "receipt_state_at_callback": {
            "status": RECEIPT_FAILED,
            "status_name": "FAILED",
            "response": None,
            "concluded_at": "set to time.time()",
            "progress": 0,
            "get_response()": None,
            "get_response_time()": None,
            "concluded()": True,
        },
        "source_reference": "Link.py:RequestReceipt.request_resource_concluded() lines 1413-1423",
    })

    # --- Vector 1: Response timeout after resource delivery (SENT -> DELIVERED -> FAILED) ---
    timestamp_1 = 1700000201.0
    data_1 = deterministic_data(2001, LINK_MDU + 50)
    unpacked_1 = [timestamp_1, path_hash, data_1]
    packed_1 = umsgpack.packb(unpacked_1)
    assert len(packed_1) > LINK_MDU
    request_id_1 = truncated_hash(packed_1)

    vectors.append({
        "index": 1,
        "description": "Response timeout after successful resource delivery",
        "transport": "resource",
        "request_id": request_id_1.hex(),
        "packed_request_length": len(packed_1),
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request resource advertised"},
            {"status": RECEIPT_DELIVERED, "status_name": "DELIVERED",
             "trigger": "request_resource_concluded() with resource.status == COMPLETE"},
            {"status": RECEIPT_FAILED, "status_name": "FAILED",
             "trigger": "__response_timeout_job() expired, calls request_timed_out(None)"},
        ],
        "callback_invoked": True,
        "callback": "failed_callback",
        "timeout_mechanism": {
            "description": "__response_timeout_job polls every 0.1s while status == DELIVERED",
            "deadline": "time.time() + timeout at DELIVERED transition",
            "timeout_formula": "rtt * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125",
        },
        "receipt_state_at_callback": {
            "status": RECEIPT_FAILED,
            "status_name": "FAILED",
            "response": None,
            "concluded_at": "set to time.time()",
            "progress": 0,
            "get_response()": None,
            "get_response_time()": None,
            "concluded()": True,
        },
        "source_reference": "Link.py:RequestReceipt.__response_timeout_job() lines 1426-1433, request_timed_out() lines 1436-1445",
    })

    # --- Vector 2: Policy block on resource request (SENT -> DELIVERED -> FAILED) ---
    timestamp_2 = 1700000202.0
    data_2 = deterministic_data(2002, LINK_MDU + 50)
    unpacked_2 = [timestamp_2, path_hash, data_2]
    packed_2 = umsgpack.packb(unpacked_2)
    assert len(packed_2) > LINK_MDU
    request_id_2 = truncated_hash(packed_2)

    vectors.append({
        "index": 2,
        "description": "Policy block on resource-transport request (times out)",
        "transport": "resource",
        "request_id": request_id_2.hex(),
        "packed_request_length": len(packed_2),
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request resource advertised"},
            {"status": RECEIPT_DELIVERED, "status_name": "DELIVERED",
             "trigger": "request_resource_concluded() with resource.status == COMPLETE"},
            {"status": RECEIPT_FAILED, "status_name": "FAILED",
             "trigger": "Server silently drops (policy block). __response_timeout_job() expires."},
        ],
        "callback_invoked": True,
        "callback": "failed_callback",
        "server_behavior": "silent_drop (policy denies, no response sent)",
        "receipt_state_at_callback": {
            "status": RECEIPT_FAILED,
            "status_name": "FAILED",
            "response": None,
            "concluded_at": "set to time.time()",
            "progress": 0,
            "get_response()": None,
            "get_response_time()": None,
            "concluded()": True,
        },
        "note": "Indistinguishable from vector 1 at the client — both result in timeout after DELIVERED",
        "source_reference": "Link.py:handle_request() lines 906-908 (silent drop), request_timed_out() lines 1436-1445",
    })

    # --- Vector 3: Inline packet never gets application response (SENT -> stuck) ---
    timestamp_3 = 1700000203.0
    data_3 = b"ping"
    unpacked_3 = [timestamp_3, path_hash, data_3]
    packed_3 = umsgpack.packb(unpacked_3)
    assert len(packed_3) <= LINK_MDU

    iv_3 = deterministic_iv(114)
    token_data_3 = token_encrypt_deterministic(packed_3, derived_key, iv_3)
    raw_3 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_3)
    request_id_3 = get_truncated_hash(raw_3)

    vectors.append({
        "index": 3,
        "description": "Inline request with no response (handler not found or server drops)",
        "transport": "inline",
        "request_id": request_id_3.hex(),
        "request_wire": {
            "packed_request_hex": packed_3.hex(),
            "iv": iv_3.hex(),
            "token_data_hex": token_data_3.hex(),
            "raw_packet_hex": raw_3.hex(),
        },
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request packet sent"},
        ],
        "callback_invoked": False,
        "callback": None,
        "stuck_state": {
            "status": RECEIPT_SENT,
            "status_name": "SENT",
            "response": None,
            "concluded_at": None,
            "progress": 0,
            "get_response()": None,
            "get_response_time()": None,
            "concluded()": False,
        },
        "behavioral_gap": (
            "PacketReceipt.set_timeout_callback(request_timed_out) is set in "
            "RequestReceipt.__init__. PacketReceipt.check_timeout() only fires "
            "when PacketReceipt.status == SENT. On a link with implicit proofs, "
            "the packet is proved delivered, so PacketReceipt.status becomes "
            "DELIVERED and check_timeout() never fires. RequestReceipt stays "
            "at SENT. failed_callback is never invoked."
        ),
        "source_reference": (
            "Packet.py:PacketReceipt.check_timeout() line 560 (status==SENT guard), "
            "Link.py:RequestReceipt.request_timed_out() line 1437 (status==DELIVERED guard)"
        ),
    })

    # --- Vector 4: Inline request policy blocked (same outcome as vector 3) ---
    timestamp_4 = 1700000204.0
    data_4 = b"blocked"
    unpacked_4 = [timestamp_4, path_hash, data_4]
    packed_4 = umsgpack.packb(unpacked_4)
    assert len(packed_4) <= LINK_MDU

    iv_4 = deterministic_iv(115)
    token_data_4 = token_encrypt_deterministic(packed_4, derived_key, iv_4)
    raw_4 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_4)
    request_id_4 = get_truncated_hash(raw_4)

    vectors.append({
        "index": 4,
        "description": "Inline request policy-blocked (packet delivered but no response)",
        "transport": "inline",
        "request_id": request_id_4.hex(),
        "request_wire": {
            "packed_request_hex": packed_4.hex(),
            "iv": iv_4.hex(),
            "token_data_hex": token_data_4.hex(),
            "raw_packet_hex": raw_4.hex(),
        },
        "state_transitions": [
            {"status": RECEIPT_SENT, "status_name": "SENT",
             "trigger": "Request packet sent"},
        ],
        "callback_invoked": False,
        "callback": None,
        "server_behavior": "silent_drop (policy denies, no response sent)",
        "stuck_state": {
            "status": RECEIPT_SENT,
            "status_name": "SENT",
            "response": None,
            "concluded_at": None,
            "progress": 0,
            "get_response()": None,
            "get_response_time()": None,
            "concluded()": False,
        },
        "behavioral_gap": (
            "Same as vector 3: packet is delivered (link implicit proof), "
            "but server silently drops due to policy. PacketReceipt timeout "
            "never fires because PacketReceipt.status is already DELIVERED. "
            "RequestReceipt stays at SENT. failed_callback never invoked."
        ),
        "note": "Client cannot distinguish policy-block from handler-not-found for inline requests",
        "source_reference": "Link.py:handle_request() lines 906-908, Packet.py:check_timeout() line 560",
    })

    return vectors


def extract_handler_error_vectors(derived_key, link_id):
    """Extract server-side handler error vectors.

    4 vectors documenting what happens when the response_generator has
    wrong signature or raises an exception.

    IV range: 124-127
    Timestamps: 1700000300.0+
    """
    path = "/echo"
    path_hash = truncated_hash(path.encode("utf-8"))
    vectors = []

    # --- Vector 0: Wrong param count (4 params) ---
    timestamp_0 = 1700000300.0
    data_0 = b"test_4param"
    unpacked_0 = [timestamp_0, path_hash, data_0]
    packed_0 = umsgpack.packb(unpacked_0)
    assert len(packed_0) <= LINK_MDU

    iv_0 = deterministic_iv(124)
    token_data_0 = token_encrypt_deterministic(packed_0, derived_key, iv_0)
    raw_0 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_0)
    request_id_0 = get_truncated_hash(raw_0)

    vectors.append({
        "index": 0,
        "description": "Handler with 4 parameters (too few)",
        "path": path,
        "path_hash": path_hash.hex(),
        "timestamp": timestamp_0,
        "request_id": request_id_0.hex(),
        "request_wire": {
            "packed_request_hex": packed_0.hex(),
            "iv": iv_0.hex(),
            "token_data_hex": token_data_0.hex(),
            "raw_packet_hex": raw_0.hex(),
        },
        "handler_param_count": 4,
        "expected_exception": "TypeError",
        "expected_message": "Invalid signature for response generator callback",
        "response_sent": False,
        "server_behavior": (
            "inspect.signature(response_generator).parameters has 4 entries. "
            "Neither == 5 nor == 6 branch matches. Raises TypeError. "
            "Exception propagates — no response sent."
        ),
        "source_reference": "Link.py:handle_request() lines 881-886",
    })

    # --- Vector 1: Wrong param count (7 params) ---
    timestamp_1 = 1700000301.0
    data_1 = b"test_7param"
    unpacked_1 = [timestamp_1, path_hash, data_1]
    packed_1 = umsgpack.packb(unpacked_1)
    assert len(packed_1) <= LINK_MDU

    iv_1 = deterministic_iv(125)
    token_data_1 = token_encrypt_deterministic(packed_1, derived_key, iv_1)
    raw_1 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_1)
    request_id_1 = get_truncated_hash(raw_1)

    vectors.append({
        "index": 1,
        "description": "Handler with 7 parameters (too many)",
        "path": path,
        "path_hash": path_hash.hex(),
        "timestamp": timestamp_1,
        "request_id": request_id_1.hex(),
        "request_wire": {
            "packed_request_hex": packed_1.hex(),
            "iv": iv_1.hex(),
            "token_data_hex": token_data_1.hex(),
            "raw_packet_hex": raw_1.hex(),
        },
        "handler_param_count": 7,
        "expected_exception": "TypeError",
        "expected_message": "Invalid signature for response generator callback",
        "response_sent": False,
        "server_behavior": (
            "inspect.signature(response_generator).parameters has 7 entries. "
            "Neither == 5 nor == 6 branch matches. Raises TypeError. "
            "Exception propagates — no response sent."
        ),
        "source_reference": "Link.py:handle_request() lines 881-886",
    })

    # --- Vector 2: Handler raises exception ---
    timestamp_2 = 1700000302.0
    data_2 = b"test_exception"
    unpacked_2 = [timestamp_2, path_hash, data_2]
    packed_2 = umsgpack.packb(unpacked_2)
    assert len(packed_2) <= LINK_MDU

    iv_2 = deterministic_iv(126)
    token_data_2 = token_encrypt_deterministic(packed_2, derived_key, iv_2)
    raw_2 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_2)
    request_id_2 = get_truncated_hash(raw_2)

    vectors.append({
        "index": 2,
        "description": "Handler raises RuntimeError",
        "path": path,
        "path_hash": path_hash.hex(),
        "timestamp": timestamp_2,
        "request_id": request_id_2.hex(),
        "request_wire": {
            "packed_request_hex": packed_2.hex(),
            "iv": iv_2.hex(),
            "token_data_hex": token_data_2.hex(),
            "raw_packet_hex": raw_2.hex(),
        },
        "handler_param_count": 5,
        "expected_exception": "RuntimeError",
        "expected_message": "application-defined error",
        "response_sent": False,
        "server_behavior": (
            "Handler is called with correct 5-param signature but raises "
            "RuntimeError during execution. Exception propagates from "
            "handle_request() — no try/except around the response_generator "
            "call. No response is sent."
        ),
        "source_reference": "Link.py:handle_request() lines 881-882 (no try/except around call)",
    })

    # --- Vector 3: Handler returns None ---
    timestamp_3 = 1700000303.0
    data_3 = b"test_none_return"
    unpacked_3 = [timestamp_3, path_hash, data_3]
    packed_3 = umsgpack.packb(unpacked_3)
    assert len(packed_3) <= LINK_MDU

    iv_3 = deterministic_iv(127)
    token_data_3 = token_encrypt_deterministic(packed_3, derived_key, iv_3)
    raw_3 = build_raw_packet(link_id, CONTEXT_REQUEST, token_data_3)
    request_id_3 = get_truncated_hash(raw_3)

    vectors.append({
        "index": 3,
        "description": "Handler returns None (intentional no-response)",
        "path": path,
        "path_hash": path_hash.hex(),
        "timestamp": timestamp_3,
        "request_id": request_id_3.hex(),
        "request_wire": {
            "packed_request_hex": packed_3.hex(),
            "iv": iv_3.hex(),
            "token_data_hex": token_data_3.hex(),
            "raw_packet_hex": raw_3.hex(),
        },
        "handler_param_count": 5,
        "expected_exception": None,
        "response_sent": False,
        "server_behavior": (
            "Handler returns None. Line 897: 'if response != None' check fails. "
            "No response packet or resource is created. This is intentional — "
            "handlers may return None to indicate no response should be sent."
        ),
        "note": "Not an error — this is a valid handler behavior",
        "source_reference": "Link.py:handle_request() line 897 ('if response != None')",
    })

    return vectors


# ============================================================
# Verification
# ============================================================

def verify(output, derived_key):
    """Cross-validate all vectors."""
    print("  Verifying...")

    # 1. Path hash vectors
    for pv in output["path_hash_vectors"]:
        path_bytes = pv["path"].encode("utf-8")
        computed = truncated_hash(path_bytes)
        assert computed.hex() == pv["path_hash"], f"Path hash {pv['index']}: mismatch"
    print(f"    [OK] {len(output['path_hash_vectors'])} path hash vectors verified")

    # 2. Request serialization round-trip
    for rv in output["request_serialization_vectors"]:
        packed = bytes.fromhex(rv["packed_request_hex"]) if "packed_request_hex" in rv else None
        if packed:
            unpacked = umsgpack.unpackb(packed)
            assert isinstance(unpacked, list) and len(unpacked) == 3
            assert unpacked[0] == rv["timestamp"]
            assert unpacked[1] == bytes.fromhex(rv["path_hash"])
            repacked = umsgpack.packb(unpacked)
            assert repacked == packed, f"Request serialization {rv['index']}: repack mismatch"
    print(f"    [OK] {len(output['request_serialization_vectors'])} request serialization vectors verified")

    # 3. Response serialization round-trip
    for rv in output["response_serialization_vectors"]:
        packed = bytes.fromhex(rv["packed_response_hex"]) if "packed_response_hex" in rv else None
        if packed:
            unpacked = umsgpack.unpackb(packed)
            assert isinstance(unpacked, list) and len(unpacked) == 2
            assert unpacked[0] == bytes.fromhex(rv["request_id"])
            repacked = umsgpack.packb(unpacked)
            assert repacked == packed, f"Response serialization {rv['index']}: repack mismatch"
    print(f"    [OK] {len(output['response_serialization_vectors'])} response serialization vectors verified")

    # 4. Small request wire vectors: decrypt and verify
    for wv in output["small_request_wire_vectors"]:
        token_data = bytes.fromhex(wv["token_data_hex"])
        decrypted = token_decrypt(token_data, derived_key)
        packed_request = bytes.fromhex(wv["packed_request_hex"])
        assert decrypted == packed_request, f"Wire request {wv['index']}: decrypt mismatch"

        # Verify request_id derivation
        raw = bytes.fromhex(wv["raw_packet_hex"])
        hashable = get_hashable_part(raw)
        assert hashable.hex() == wv["hashable_part_hex"], f"Wire request {wv['index']}: hashable part mismatch"
        request_id = truncated_hash(hashable)
        assert request_id.hex() == wv["request_id"], f"Wire request {wv['index']}: request_id mismatch"
    print(f"    [OK] {len(output['small_request_wire_vectors'])} small request wire vectors verified")

    # 5. Small response wire vectors: decrypt and verify
    for wv in output["small_response_wire_vectors"]:
        token_data = bytes.fromhex(wv["token_data_hex"])
        decrypted = token_decrypt(token_data, derived_key)
        packed_response = bytes.fromhex(wv["packed_response_hex"])
        assert decrypted == packed_response, f"Wire response {wv['index']}: decrypt mismatch"
    print(f"    [OK] {len(output['small_response_wire_vectors'])} small response wire vectors verified")

    # 6. Policy enforcement
    for pv in output["policy_vectors"]:
        assert pv["computed_allowed"] == pv["expected_allowed"], f"Policy {pv['index']}: mismatch"
    print(f"    [OK] {len(output['policy_vectors'])} policy vectors verified")

    # 7. Timeout computation
    for tv in output["timeout_vectors"]:
        computed = tv["rtt"] * TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125
        assert abs(computed - tv["timeout"]) < 1e-10, f"Timeout {tv['index']}: mismatch"
    print(f"    [OK] {len(output['timeout_vectors'])} timeout vectors verified")

    # 8. Round-trip integration
    for rv in output["round_trip_vectors"]:
        assert rv["verified"] is True, f"Round-trip {rv['index']}: verification failed"
    print(f"    [OK] {len(output['round_trip_vectors'])} round-trip vectors verified")

    # 9. Handler registration vectors
    reg = output["handler_registration_vectors"]
    for rv in reg["individual_vectors"]:
        path_hash = truncated_hash(rv["path"].encode("utf-8"))
        assert path_hash.hex() == rv["path_hash"], f"Handler reg {rv['index']}: path_hash mismatch"
        assert path_hash.hex() == rv["dict_key"], f"Handler reg {rv['index']}: dict_key mismatch"
    assert reg["multi_handler"]["dict_size"] == len(reg["individual_vectors"])
    print(f"    [OK] {len(reg['individual_vectors'])} handler registration vectors verified")

    # 10. Handler deregistration vectors
    dereg = output["handler_deregistration_vectors"]
    # Replay the deregistration sequence
    hash_echo = truncated_hash("/echo".encode("utf-8"))
    hash_status = truncated_hash("/api/v1/status".encode("utf-8"))
    sim_handlers = {hash_echo.hex(): True, hash_status.hex(): True}
    for step in dereg["steps"]:
        ph = step["path_hash"]
        if ph in sim_handlers:
            del sim_handlers[ph]
            assert step["expected_return"] is True, f"Deregistration step {step['step']}: expected True"
        else:
            assert step["expected_return"] is False, f"Deregistration step {step['step']}: expected False"
        assert step["dict_size_after"] == len(sim_handlers), f"Deregistration step {step['step']}: size mismatch"
    print(f"    [OK] {len(dereg['steps'])} handler deregistration steps verified")

    # 11. Handler invocation vectors
    inv = output["handler_invocation_vectors"]
    for iv_vec in inv:
        if "handler_found" in iv_vec and iv_vec["handler_found"] is False:
            continue
        path_hash = truncated_hash(iv_vec["path"].encode("utf-8"))
        assert path_hash.hex() == iv_vec["path_hash"], f"Invocation {iv_vec['index']}: path_hash mismatch"
        assert iv_vec["param_count"] in (5, 6), f"Invocation {iv_vec['index']}: invalid param_count"
        if iv_vec["param_count"] == 5:
            assert "arg_3_remote_identity" in iv_vec["dispatch_args"]
            assert "arg_3_link_id" not in iv_vec["dispatch_args"]
        else:
            assert "arg_3_link_id" in iv_vec["dispatch_args"]
            assert "arg_4_remote_identity" in iv_vec["dispatch_args"]
    print(f"    [OK] {len(inv)} handler invocation vectors verified")

    # 12. Handler validation vectors
    val = output["handler_validation_vectors"]
    for vv in val["vectors"]:
        assert vv["expected_error"] == "ValueError", f"Validation {vv['index']}: expected ValueError"
    assert val["valid_policies"] == [ALLOW_NONE, ALLOW_ALL, ALLOW_LIST]
    print(f"    [OK] {len(val['vectors'])} handler validation vectors verified")

    # 13. Receipt lifecycle vectors
    valid_statuses = {RECEIPT_FAILED, RECEIPT_SENT, RECEIPT_DELIVERED, RECEIPT_RECEIVING, RECEIPT_READY}
    terminal_statuses = {RECEIPT_READY, RECEIPT_FAILED}
    rt_count = len(output["round_trip_vectors"])
    for lv in output["receipt_lifecycle_vectors"]:
        transitions = lv["state_transitions"]
        assert len(transitions) >= 2, f"Lifecycle {lv['index']}: needs at least 2 transitions"
        # First status must be SENT
        assert transitions[0]["status"] == RECEIPT_SENT, f"Lifecycle {lv['index']}: must start with SENT"
        # Last status must be READY or FAILED
        assert transitions[-1]["status"] in terminal_statuses, f"Lifecycle {lv['index']}: must end with READY or FAILED"
        # All statuses must be valid
        for t in transitions:
            assert t["status"] in valid_statuses, f"Lifecycle {lv['index']}: invalid status {t['status']}"
        # Cross-reference indices must be valid
        if "round_trip_vector_index" in lv:
            assert lv["round_trip_vector_index"] < rt_count, f"Lifecycle {lv['index']}: invalid round_trip ref"
        # Must have at least one callback
        assert len(lv["callbacks_invoked"]) >= 1, f"Lifecycle {lv['index']}: needs at least 1 callback"
    print(f"    [OK] {len(output['receipt_lifecycle_vectors'])} receipt lifecycle vectors verified")

    # 14. Policy enforcement wire vectors
    for pv in output["policy_enforcement_wire_vectors"]:
        # Verify request wire format decrypt/round-trip
        req_wire = pv["request_wire"]
        token_data = bytes.fromhex(req_wire["token_data_hex"])
        decrypted = token_decrypt(token_data, derived_key)
        packed_request = bytes.fromhex(req_wire["packed_request_hex"])
        assert decrypted == packed_request, f"Policy enforcement {pv['index']}: request decrypt mismatch"

        # Verify request_id derivation
        raw = bytes.fromhex(req_wire["raw_packet_hex"])
        computed_id = get_truncated_hash(raw)
        assert computed_id.hex() == req_wire["request_id"], f"Policy enforcement {pv['index']}: request_id mismatch"

        # Reproduce policy logic
        policy = pv["policy"]
        remote_hash = bytes.fromhex(pv["remote_identity_hash"]) if pv["remote_identity_hash"] else None
        al = [bytes.fromhex(h) for h in pv["allowed_list"]]
        allowed = False
        if not policy == ALLOW_NONE:
            if policy == ALLOW_LIST:
                if remote_hash is not None and remote_hash in al:
                    allowed = True
            elif policy == ALLOW_ALL:
                allowed = True
        assert allowed == pv["expected_allowed"], f"Policy enforcement {pv['index']}: policy mismatch"

        # Verify response wire for allowed vectors
        if pv["expected_allowed"]:
            assert pv["response_wire"] is not None, f"Policy enforcement {pv['index']}: missing response"
            resp_token = bytes.fromhex(pv["response_wire"]["token_data_hex"])
            decrypted_resp = token_decrypt(resp_token, derived_key)
            packed_resp = bytes.fromhex(pv["response_wire"]["packed_response_hex"])
            assert decrypted_resp == packed_resp, f"Policy enforcement {pv['index']}: response decrypt mismatch"
        else:
            assert pv["response_wire"] is None, f"Policy enforcement {pv['index']}: should have no response"
            assert pv["server_behavior"] == "silent_drop"
    print(f"    [OK] {len(output['policy_enforcement_wire_vectors'])} policy enforcement wire vectors verified")

    # 15. Failure callback vectors
    for fv in output["failure_callback_vectors"]:
        transitions = fv["state_transitions"]
        assert len(transitions) >= 1, f"Failure callback {fv['index']}: needs at least 1 transition"
        # First status must be SENT
        assert transitions[0]["status"] == RECEIPT_SENT, f"Failure callback {fv['index']}: must start at SENT"

        if fv["callback_invoked"]:
            # Must end at FAILED
            assert transitions[-1]["status"] == RECEIPT_FAILED, f"Failure callback {fv['index']}: must end at FAILED"
            assert fv["callback"] == "failed_callback"
            state = fv["receipt_state_at_callback"]
            assert state["status"] == RECEIPT_FAILED
            assert state["response"] is None
            assert state["get_response()"] is None
            assert state["get_response_time()"] is None
            assert state["concluded()"] is True
        else:
            # Stuck at SENT
            assert transitions[-1]["status"] == RECEIPT_SENT, f"Failure callback {fv['index']}: should stay at SENT"
            assert fv["callback"] is None
            state = fv["stuck_state"]
            assert state["status"] == RECEIPT_SENT
            assert state["response"] is None
            assert state["concluded()"] is False

        # Verify wire format for inline vectors
        if "request_wire" in fv:
            req_wire = fv["request_wire"]
            token_data = bytes.fromhex(req_wire["token_data_hex"])
            decrypted = token_decrypt(token_data, derived_key)
            packed = bytes.fromhex(req_wire["packed_request_hex"])
            assert decrypted == packed, f"Failure callback {fv['index']}: decrypt mismatch"
    print(f"    [OK] {len(output['failure_callback_vectors'])} failure callback vectors verified")

    # 16. Handler error vectors
    for hv in output["handler_error_vectors"]:
        assert hv["response_sent"] is False, f"Handler error {hv['index']}: should not send response"
        # Verify wire format construction
        req_wire = hv["request_wire"]
        token_data = bytes.fromhex(req_wire["token_data_hex"])
        decrypted = token_decrypt(token_data, derived_key)
        packed = bytes.fromhex(req_wire["packed_request_hex"])
        assert decrypted == packed, f"Handler error {hv['index']}: decrypt mismatch"

        raw = bytes.fromhex(req_wire["raw_packet_hex"])
        computed_id = get_truncated_hash(raw)
        assert computed_id.hex() == hv["request_id"], f"Handler error {hv['index']}: request_id mismatch"
    print(f"    [OK] {len(output['handler_error_vectors'])} handler error vectors verified")

    # JSON round-trip integrity
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("    [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify our local constants match the actual RNS library values."""
    import RNS

    assert CONTEXT_REQUEST == RNS.Packet.REQUEST, f"REQUEST: {CONTEXT_REQUEST} != {RNS.Packet.REQUEST}"
    assert CONTEXT_RESPONSE == RNS.Packet.RESPONSE, f"RESPONSE: {CONTEXT_RESPONSE} != {RNS.Packet.RESPONSE}"
    assert ALLOW_NONE == RNS.Destination.ALLOW_NONE, f"ALLOW_NONE: {ALLOW_NONE} != {RNS.Destination.ALLOW_NONE}"
    assert ALLOW_ALL == RNS.Destination.ALLOW_ALL, f"ALLOW_ALL: {ALLOW_ALL} != {RNS.Destination.ALLOW_ALL}"
    assert ALLOW_LIST == RNS.Destination.ALLOW_LIST, f"ALLOW_LIST: {ALLOW_LIST} != {RNS.Destination.ALLOW_LIST}"
    assert RESPONSE_MAX_GRACE_TIME == RNS.Resource.RESPONSE_MAX_GRACE_TIME
    assert TOKEN_OVERHEAD == RNS.Identity.TOKEN_OVERHEAD
    assert LINK_MDU == math.floor((MTU - IFAC_MIN_SIZE - RNS.Reticulum.HEADER_MINSIZE - RNS.Identity.TOKEN_OVERHEAD) / RNS.Identity.AES128_BLOCKSIZE) * RNS.Identity.AES128_BLOCKSIZE - 1

    from RNS.Link import RequestReceipt
    assert RECEIPT_FAILED == RequestReceipt.FAILED
    assert RECEIPT_SENT == RequestReceipt.SENT
    assert RECEIPT_DELIVERED == RequestReceipt.DELIVERED
    assert RECEIPT_RECEIVING == RequestReceipt.RECEIVING
    assert RECEIPT_READY == RequestReceipt.READY

    print("  [OK] All library constants verified")


# ============================================================
# Main
# ============================================================

def main():
    print("Extracting request/response protocol test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    # Load prerequisite data
    links_data = load_links_json()
    keypairs = load_keypairs()

    # Use handshake_vectors[0] for derived_key and link_id
    handshake = links_data["handshake_vectors"][0]
    derived_key = bytes.fromhex(handshake["step_2_lrproof"]["derived_key"])
    link_id = bytes.fromhex(handshake["step_1_linkrequest"]["link_id"])

    print("Extracting constants...")
    constants = extract_constants()

    print("Extracting path hash vectors...")
    path_hash_vectors = extract_path_hash_vectors()
    print(f"  Extracted {len(path_hash_vectors)} path hash vectors")

    print("Extracting request serialization vectors...")
    req_ser_vectors = extract_request_serialization_vectors()
    print(f"  Extracted {len(req_ser_vectors)} request serialization vectors")

    print("Extracting response serialization vectors...")
    resp_ser_vectors = extract_response_serialization_vectors()
    print(f"  Extracted {len(resp_ser_vectors)} response serialization vectors")

    print("Extracting small request wire vectors...")
    small_req_vectors = extract_small_request_wire_vectors(derived_key, link_id)
    print(f"  Extracted {len(small_req_vectors)} small request wire vectors")

    # Collect request_ids from wire vectors for response construction
    request_ids = [bytes.fromhex(v["request_id"]) for v in small_req_vectors]

    print("Extracting small response wire vectors...")
    small_resp_vectors = extract_small_response_wire_vectors(derived_key, link_id, request_ids)
    print(f"  Extracted {len(small_resp_vectors)} small response wire vectors")

    print("Extracting large request/response resource vectors...")
    large_vectors = extract_large_request_resource_vectors()
    print(f"  Extracted {len(large_vectors)} large request/response resource vectors")

    print("Extracting policy enforcement vectors...")
    policy_vectors = extract_policy_vectors(keypairs)
    print(f"  Extracted {len(policy_vectors)} policy enforcement vectors")

    print("Extracting timeout vectors...")
    timeout_vectors = extract_timeout_vectors()
    print(f"  Extracted {len(timeout_vectors)} timeout vectors")

    print("Extracting round-trip integration vectors...")
    rt_vectors = extract_round_trip_vectors(derived_key, link_id)
    print(f"  Extracted {len(rt_vectors)} round-trip vectors")

    print("Extracting receipt lifecycle vectors...")
    receipt_lifecycle_vectors = extract_receipt_lifecycle_vectors()
    print(f"  Extracted {len(receipt_lifecycle_vectors)} receipt lifecycle vectors")

    print("Extracting handler registration vectors...")
    handler_reg_vectors = extract_handler_registration_vectors(keypairs)
    print(f"  Extracted {len(handler_reg_vectors['individual_vectors'])} handler registration vectors")

    print("Extracting handler deregistration vectors...")
    handler_dereg_vectors = extract_handler_deregistration_vectors()
    print(f"  Extracted {len(handler_dereg_vectors['steps'])} handler deregistration steps")

    print("Extracting handler invocation vectors...")
    handler_inv_vectors = extract_handler_invocation_vectors(derived_key, link_id, keypairs)
    print(f"  Extracted {len(handler_inv_vectors)} handler invocation vectors")

    print("Extracting handler validation vectors...")
    handler_val_vectors = extract_handler_validation_vectors()
    print(f"  Extracted {len(handler_val_vectors['vectors'])} handler validation vectors")

    print("Extracting policy enforcement wire vectors...")
    policy_enforcement_vectors = extract_policy_enforcement_wire_vectors(derived_key, link_id, keypairs)
    print(f"  Extracted {len(policy_enforcement_vectors)} policy enforcement wire vectors")

    print("Extracting failure callback vectors...")
    failure_callback_vectors = extract_failure_callback_vectors(derived_key, link_id)
    print(f"  Extracted {len(failure_callback_vectors)} failure callback vectors")

    print("Extracting handler error vectors...")
    handler_error_vectors = extract_handler_error_vectors(derived_key, link_id)
    print(f"  Extracted {len(handler_error_vectors)} handler error vectors")

    output = {
        "description": "Reticulum v1.1.3 - request/response protocol test vectors",
        "source": "RNS/Link.py, RNS/Destination.py, RNS/Packet.py, RNS/Resource.py",
        "handshake_reference": "handshake_vectors[0] from links.json",
        "constants": constants,
        "path_hash_vectors": path_hash_vectors,
        "request_serialization_vectors": req_ser_vectors,
        "response_serialization_vectors": resp_ser_vectors,
        "small_request_wire_vectors": small_req_vectors,
        "small_response_wire_vectors": small_resp_vectors,
        "large_request_resource_vectors": large_vectors,
        "policy_vectors": policy_vectors,
        "timeout_vectors": timeout_vectors,
        "round_trip_vectors": rt_vectors,
        "receipt_lifecycle_vectors": receipt_lifecycle_vectors,
        "handler_registration_vectors": handler_reg_vectors,
        "handler_deregistration_vectors": handler_dereg_vectors,
        "handler_invocation_vectors": handler_inv_vectors,
        "handler_validation_vectors": handler_val_vectors,
        "policy_enforcement_wire_vectors": policy_enforcement_vectors,
        "failure_callback_vectors": failure_callback_vectors,
        "handler_error_vectors": handler_error_vectors,
    }

    verify(output, derived_key)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
