#!/usr/bin/env python3
"""
Extract resource transfer test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Link/Transport/Resource objects) to
avoid Transport init. Real RNS crypto primitives are used for encryption,
hashing, and serialization.

Covers:
  - Resource constants (window, SDU, hashmap, flags)
  - Metadata encoding (msgpack + 3-byte size prefix)
  - Resource advertisement construction (encrypt, segment, hashmap, pack)
  - Receiver-side assembly (join, decrypt, decompress, verify)
  - Resource proof computation and validation
  - Invalid metadata edge case

Usage:
    python3 test_vectors/extract_resources.py

Output:
    test_vectors/resources.json
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

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources.json")
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

# Resource SDU: size of each encrypted part = link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE
# This is Reticulum.MDU = Packet.MDU = 500 - 37 - 1 = 462
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
    """Extract all Resource and ResourceAdvertisement constants."""
    return {
        "window": {
            "WINDOW": WINDOW,
            "WINDOW_MIN": WINDOW_MIN,
            "WINDOW_MAX_SLOW": WINDOW_MAX_SLOW,
            "WINDOW_MAX_VERY_SLOW": WINDOW_MAX_VERY_SLOW,
            "WINDOW_MAX_FAST": WINDOW_MAX_FAST,
            "WINDOW_MAX": WINDOW_MAX,
            "WINDOW_FLEXIBILITY": WINDOW_FLEXIBILITY,
        },
        "rate_thresholds": {
            "FAST_RATE_THRESHOLD": FAST_RATE_THRESHOLD,
            "FAST_RATE_THRESHOLD_derivation": f"WINDOW_MAX_SLOW({WINDOW_MAX_SLOW}) - WINDOW({WINDOW}) - 2 = {FAST_RATE_THRESHOLD}",
            "VERY_SLOW_RATE_THRESHOLD": VERY_SLOW_RATE_THRESHOLD,
            "RATE_FAST": RATE_FAST,
            "RATE_FAST_note": "50 Kbps in bytes/sec = (50*1000)/8",
            "RATE_VERY_SLOW": RATE_VERY_SLOW,
            "RATE_VERY_SLOW_note": "2 Kbps in bytes/sec = (2*1000)/8",
        },
        "sizes": {
            "MAPHASH_LEN": MAPHASH_LEN,
            "RANDOM_HASH_SIZE": RANDOM_HASH_SIZE,
            "SDU": RESOURCE_SDU,
            "SDU_derivation": f"MTU({MTU}) - HEADER_MAXSIZE({HEADER_MAXSIZE}) - IFAC_MIN_SIZE({IFAC_MIN_SIZE}) = {RESOURCE_SDU}",
            "SDU_note": "Resource.SDU = RNS.Packet.MDU = RNS.Reticulum.MDU at class level; instance sdu from link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE",
            "MAX_EFFICIENT_SIZE": MAX_EFFICIENT_SIZE,
            "METADATA_MAX_SIZE": METADATA_MAX_SIZE,
            "AUTO_COMPRESS_MAX_SIZE": AUTO_COMPRESS_MAX_SIZE,
        },
        "advertisement": {
            "OVERHEAD": OVERHEAD,
            "HASHMAP_MAX_LEN": HASHMAP_MAX_LEN,
            "HASHMAP_MAX_LEN_derivation": f"floor((LINK_MDU({LINK_MDU}) - OVERHEAD({OVERHEAD})) / MAPHASH_LEN({MAPHASH_LEN})) = {HASHMAP_MAX_LEN}",
            "COLLISION_GUARD_SIZE": COLLISION_GUARD_SIZE,
            "COLLISION_GUARD_SIZE_derivation": f"2 * WINDOW_MAX({WINDOW_MAX}) + HASHMAP_MAX_LEN({HASHMAP_MAX_LEN}) = {COLLISION_GUARD_SIZE}",
        },
        "timeouts": {
            "PART_TIMEOUT_FACTOR": PART_TIMEOUT_FACTOR,
            "PART_TIMEOUT_FACTOR_AFTER_RTT": PART_TIMEOUT_FACTOR_AFTER_RTT,
            "PROOF_TIMEOUT_FACTOR": PROOF_TIMEOUT_FACTOR,
            "MAX_RETRIES": MAX_RETRIES,
            "MAX_ADV_RETRIES": MAX_ADV_RETRIES,
            "SENDER_GRACE_TIME": SENDER_GRACE_TIME,
            "PROCESSING_GRACE": PROCESSING_GRACE,
            "RETRY_GRACE_TIME": RETRY_GRACE_TIME,
            "PER_RETRY_DELAY": PER_RETRY_DELAY,
            "WATCHDOG_MAX_SLEEP": WATCHDOG_MAX_SLEEP,
            "RESPONSE_MAX_GRACE_TIME": RESPONSE_MAX_GRACE_TIME,
        },
        "status_codes": {
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
        "hashmap_exhaustion": {
            "HASHMAP_IS_NOT_EXHAUSTED": HASHMAP_IS_NOT_EXHAUSTED,
            "HASHMAP_IS_EXHAUSTED": HASHMAP_IS_EXHAUSTED,
        },
        "flags": {
            "bit_0_encrypted": "0x01",
            "bit_1_compressed": "0x02",
            "bit_2_split": "0x04",
            "bit_3_is_request": "0x08",
            "bit_4_is_response": "0x10",
            "bit_5_has_metadata": "0x20",
            "formula": "flags = has_metadata<<5 | is_response<<4 | is_request<<3 | split<<2 | compressed<<1 | encrypted",
        },
    }


def extract_metadata_vectors():
    """Generate metadata encoding test vectors."""
    from RNS.vendor import umsgpack

    vectors = []

    # Case 0: Simple metadata
    meta_0 = {"text": "hello", "n": 42}
    packed_0 = umsgpack.packb(meta_0)
    size_prefix_0 = struct.pack(">I", len(packed_0))[1:]
    full_0 = size_prefix_0 + packed_0

    vectors.append({
        "index": 0,
        "description": "Simple metadata with string and integer",
        "metadata_dict": {"text": "hello", "n": 42},
        "packed_metadata_hex": packed_0.hex(),
        "packed_metadata_length": len(packed_0),
        "size_prefix_hex": size_prefix_0.hex(),
        "size_prefix_note": "struct.pack('>I', len(packed))[1:] — 3 bytes big-endian, drop leading byte",
        "full_metadata_bytes_hex": full_0.hex(),
        "full_metadata_length": len(full_0),
    })

    # Case 1: Metadata with binary blob
    binary_blob = hashlib.sha256(b"reticulum_test_metadata_binary").digest()
    meta_1 = {"type": "binary_test", "blob": binary_blob}
    packed_1 = umsgpack.packb(meta_1)
    size_prefix_1 = struct.pack(">I", len(packed_1))[1:]
    full_1 = size_prefix_1 + packed_1

    vectors.append({
        "index": 1,
        "description": "Metadata with 32-byte binary blob",
        "metadata_dict": {"type": "binary_test", "blob": binary_blob.hex()},
        "metadata_dict_note": "blob value shown as hex; actual msgpack uses raw bytes",
        "packed_metadata_hex": packed_1.hex(),
        "packed_metadata_length": len(packed_1),
        "size_prefix_hex": size_prefix_1.hex(),
        "full_metadata_bytes_hex": full_1.hex(),
        "full_metadata_length": len(full_1),
    })

    # Case 2: Large metadata (8KB blob)
    large_blob = deterministic_data(99, 8192)
    meta_2 = {"type": "large_test", "data": large_blob}
    packed_2 = umsgpack.packb(meta_2)
    size_prefix_2 = struct.pack(">I", len(packed_2))[1:]
    full_2 = size_prefix_2 + packed_2

    vectors.append({
        "index": 2,
        "description": "Large metadata with 8KB binary blob",
        "metadata_dict": {"type": "large_test", "data_length": len(large_blob)},
        "metadata_dict_note": "data field is 8192 bytes of deterministic data (index=99)",
        "packed_metadata_hex": hex_prefix(packed_2, 64),
        "packed_metadata_length": len(packed_2),
        "size_prefix_hex": size_prefix_2.hex(),
        "full_metadata_bytes_hex": hex_prefix(full_2, 64),
        "full_metadata_length": len(full_2),
    })

    return vectors


def build_resource_vectors(derived_key):
    """Build resource advertisement test vectors.

    Returns list of dicts, each with all intermediate values.
    """
    from RNS.vendor import umsgpack

    cases = []

    # --- Case 0: Micro resource (128 bytes), no metadata, no compression ---
    cases.append({
        "description": "Micro resource (128 bytes), no metadata, no compression",
        "data_length": 128,
        "metadata": None,
        "compressible": False,
        "auto_compress": True,
    })

    # --- Case 1: Micro resource (128 bytes), WITH metadata, no compression ---
    cases.append({
        "description": "Micro resource (128 bytes) with metadata, no compression",
        "data_length": 128,
        "metadata": {"filename": "test.bin", "size": 128},
        "compressible": False,
        "auto_compress": True,
    })

    # --- Case 2: Small compressible resource (~2KB), no metadata, WITH compression ---
    cases.append({
        "description": "Small compressible resource (~2KB), no metadata, compressed",
        "data_length": 2048,
        "metadata": None,
        "compressible": True,
        "auto_compress": True,
    })

    # --- Case 3: Multi-part resource (~2KB random), no metadata, no compression ---
    cases.append({
        "description": "Multi-part resource (~2KB random data), no metadata, no compression",
        "data_length": 2048,
        "metadata": None,
        "compressible": False,
        "auto_compress": True,
    })

    vectors = []

    for idx, case in enumerate(cases):
        # Generate input data
        if case["compressible"]:
            # Highly compressible: repeated pattern
            pattern = b"RETICULUM_TEST_PATTERN_" + str(idx).encode() + b"_"
            input_data = (pattern * ((case["data_length"] // len(pattern)) + 1))[:case["data_length"]]
        else:
            input_data = deterministic_data(idx, case["data_length"])

        # Process metadata
        metadata_dict = case["metadata"]
        has_metadata = metadata_dict is not None

        if has_metadata:
            packed_metadata = umsgpack.packb(metadata_dict)
            metadata_size = len(packed_metadata)
            metadata_bytes = struct.pack(">I", metadata_size)[1:] + packed_metadata
        else:
            metadata_bytes = b""

        # Combine: metadata + resource_data (this is "data" in Resource.__init__ line 330-331)
        if has_metadata:
            data_with_metadata = metadata_bytes + input_data
        else:
            data_with_metadata = input_data

        total_size = len(data_with_metadata)

        # Compression (mirrors Resource.__init__ lines 386-416)
        auto_compress = case["auto_compress"]
        if auto_compress and len(input_data) <= AUTO_COMPRESS_MAX_SIZE:
            compressed_data = bz2.compress(data_with_metadata)
        else:
            compressed_data = data_with_metadata

        if len(compressed_data) < len(data_with_metadata) and auto_compress:
            compressed = True
            payload_after_compress = compressed_data
        else:
            compressed = False
            payload_after_compress = data_with_metadata

        # Random hash (deterministic for test vectors)
        random_hash = deterministic_random_hash(idx)

        # Pre-encryption data: random_hash(4) + payload
        pre_encryption_data = random_hash + payload_after_compress

        # Encrypt with Token (deterministic IV)
        iv = deterministic_iv(idx)
        encrypted_data = token_encrypt_deterministic(pre_encryption_data, derived_key, iv)

        # Verify round-trip
        decrypted = token_decrypt(encrypted_data, derived_key)
        assert decrypted == pre_encryption_data, f"Token round-trip failed for case {idx}"

        encrypted_size = len(encrypted_data)

        # Segment into parts
        sdu = RESOURCE_SDU
        num_parts = int(math.ceil(encrypted_size / float(sdu)))

        # Compute resource hash: SHA256(data_with_metadata + random_hash)
        # This is from line 438: self.hash = RNS.Identity.full_hash(data+self.random_hash)
        # where "data" at that point = metadata_bytes + resource_data (line 330-331)
        resource_hash = full_hash(data_with_metadata + random_hash)
        original_hash = resource_hash  # first segment

        # Compute expected proof: SHA256(data_with_metadata + resource_hash)
        # From line 440: self.expected_proof = RNS.Identity.full_hash(data+self.hash)
        expected_proof = full_hash(data_with_metadata + resource_hash)

        # Build parts and hashmap
        parts = []
        hashmap = b""
        for i in range(num_parts):
            part_data = encrypted_data[i * sdu:(i + 1) * sdu]
            map_hash = get_map_hash(part_data, random_hash)
            hashmap += map_hash
            parts.append({
                "index": i,
                "offset": i * sdu,
                "length": len(part_data),
                "data_hex": hex_prefix(part_data, 64),
                "map_hash_hex": map_hash.hex(),
            })

        # Build flags byte
        encrypted_flag = True  # Resource always encrypts
        split_flag = False  # single segment
        is_request_flag = False
        is_response_flag = False
        flags = (
            (int(has_metadata) << 5) |
            (int(is_response_flag) << 4) |
            (int(is_request_flag) << 3) |
            (int(split_flag) << 2) |
            (int(compressed) << 1) |
            int(encrypted_flag)
        )

        # Build advertisement dict (matches ResourceAdvertisement.pack())
        # Only include first HASHMAP_MAX_LEN entries of hashmap in segment 0
        hashmap_for_adv_count = min(num_parts, HASHMAP_MAX_LEN)
        hashmap_for_adv = b""
        for i in range(hashmap_for_adv_count):
            hashmap_for_adv += hashmap[i * MAPHASH_LEN:(i + 1) * MAPHASH_LEN]

        adv_dict = {
            "t": encrypted_size,          # Transfer size (encrypted)
            "d": total_size,              # Data size (uncompressed with metadata)
            "n": num_parts,               # Number of parts
            "h": resource_hash,           # Resource hash (bytes)
            "r": random_hash,             # Random hash (bytes)
            "o": original_hash,           # Original hash (bytes)
            "i": 1,                       # Segment index (1-based)
            "l": 1,                       # Total segments
            "q": None,                    # Request ID
            "f": flags,                   # Flags byte
            "m": hashmap_for_adv,         # Hashmap for this segment
        }

        # Pack advertisement
        adv_packed = umsgpack.packb(adv_dict)

        # Verify unpack round-trip
        adv_unpacked = umsgpack.unpackb(adv_packed)
        assert adv_unpacked["t"] == encrypted_size
        assert adv_unpacked["h"] == resource_hash
        assert adv_unpacked["f"] == flags

        # Build the vector
        vector = {
            "index": idx,
            "description": case["description"],
            "input_data_hex": hex_prefix(input_data, 64),
            "input_data_length": len(input_data),
            "metadata_dict": metadata_dict,
            "has_metadata": has_metadata,
        }

        if has_metadata:
            vector["packed_metadata_hex"] = packed_metadata.hex()
            vector["metadata_size_prefix_hex"] = struct.pack(">I", metadata_size)[1:].hex()
            vector["metadata_bytes_hex"] = hex_prefix(metadata_bytes, 64)
            vector["metadata_bytes_length"] = len(metadata_bytes)

        vector.update({
            "data_with_metadata_hex": hex_prefix(data_with_metadata, 64),
            "data_with_metadata_length": len(data_with_metadata),
            "total_size": total_size,
            "random_hash_hex": random_hash.hex(),
            "random_hash_seed": f"SHA256(b'reticulum_test_resource_random_hash_{idx}')[:4]",
            "auto_compress": auto_compress,
            "compressed": compressed,
        })

        if compressed:
            vector["compressed_data_hex"] = hex_prefix(compressed_data, 64)
            vector["compressed_length"] = len(compressed_data)
            vector["compression_savings"] = len(data_with_metadata) - len(compressed_data)

        vector.update({
            "pre_encryption_data_hex": hex_prefix(pre_encryption_data, 64),
            "pre_encryption_data_length": len(pre_encryption_data),
            "pre_encryption_layout": f"random_hash({RANDOM_HASH_SIZE}) + {'compressed_data' if compressed else 'data_with_metadata'}({len(payload_after_compress)}) = {len(pre_encryption_data)}",
            "deterministic_iv_hex": iv.hex(),
            "deterministic_iv_seed": f"SHA256(b'reticulum_test_resource_iv_{idx}')[:16]",
            "encrypted_data_hex": hex_prefix(encrypted_data, 128),
            "encrypted_data_length": encrypted_size,
            "encryption_layout": f"IV(16) + AES_ciphertext + HMAC(32) = {encrypted_size}",
            "sdu": sdu,
            "num_parts": num_parts,
            "parts": parts,
            "hashmap_hex": hashmap.hex(),
            "hashmap_length": len(hashmap),
            "resource_hash_hex": resource_hash.hex(),
            "resource_hash_note": "SHA256(data_with_metadata + random_hash)",
            "original_hash_hex": original_hash.hex(),
            "expected_proof_hex": expected_proof.hex(),
            "expected_proof_note": "SHA256(data_with_metadata + resource_hash)",
            "flags": flags,
            "flags_hex": f"0x{flags:02x}",
            "flags_breakdown": {
                "encrypted": bool(flags & 0x01),
                "compressed": bool(flags & 0x02),
                "split": bool(flags & 0x04),
                "is_request": bool(flags & 0x08),
                "is_response": bool(flags & 0x10),
                "has_metadata": bool(flags & 0x20),
            },
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
            "advertisement_packed_hex": adv_packed.hex(),
            "advertisement_packed_length": len(adv_packed),
        })

        vectors.append(vector)

    return vectors


def extract_assembly_vectors(resource_vectors, derived_key):
    """Generate receiver-side assembly verification vectors."""

    vectors = []

    for rv in resource_vectors:
        idx = rv["index"]
        encrypted_data_hex = rv["encrypted_data_hex"]

        # Get full encrypted data (reconstruct from parts)
        # Parts contain the encrypted data sliced at sdu boundaries
        encrypted_parts_data = []
        for part in rv["parts"]:
            part_hex = part["data_hex"]
            # Handle truncated hex
            if "..." in part_hex:
                # Can't use truncated data for assembly; we need full encrypted data
                # But we stored the full encrypted data hex (possibly truncated too)
                pass
            else:
                encrypted_parts_data.append(bytes.fromhex(part_hex))

        # If all parts have full hex, reconstruct. Otherwise use token_encrypt to recreate.
        # We need to regenerate the encrypted data from scratch for full verification.
        random_hash = deterministic_random_hash(idx)
        iv = deterministic_iv(idx)

        # Regenerate input data
        case_compressed = rv["compressed"]
        case_has_metadata = rv["has_metadata"]
        input_data_length = rv["input_data_length"]

        # Regenerate the compressible case
        if case_compressed and idx == 2:
            pattern = b"RETICULUM_TEST_PATTERN_" + str(idx).encode() + b"_"
            input_data = (pattern * ((input_data_length // len(pattern)) + 1))[:input_data_length]
        else:
            input_data = deterministic_data(idx, input_data_length)

        # Rebuild data_with_metadata
        if case_has_metadata:
            from RNS.vendor import umsgpack
            metadata_dict = rv["metadata_dict"]
            packed_metadata = umsgpack.packb(metadata_dict)
            metadata_bytes = struct.pack(">I", len(packed_metadata))[1:] + packed_metadata
            data_with_metadata = metadata_bytes + input_data
        else:
            data_with_metadata = input_data

        # Compress if needed
        if case_compressed:
            payload = bz2.compress(data_with_metadata)
        else:
            payload = data_with_metadata

        # Pre-encryption data
        pre_enc = random_hash + payload
        encrypted_data = token_encrypt_deterministic(pre_enc, derived_key, iv)

        # Now simulate receiver-side assembly
        # Step 1: Join parts (just the encrypted data stream)
        stream = encrypted_data  # receiver joins all part data

        # Step 2: Decrypt
        decrypted_stream = token_decrypt(stream, derived_key)

        # Step 3: Strip random hash (first 4 bytes)
        stripped_data = decrypted_stream[RANDOM_HASH_SIZE:]

        # Step 4: Decompress if flagged
        if case_compressed:
            decompressed_data = bz2.decompress(stripped_data)
        else:
            decompressed_data = stripped_data

        # Step 5: Verify hash
        resource_hash = bytes.fromhex(rv["resource_hash_hex"])
        calculated_hash = full_hash(decompressed_data + random_hash)
        verified = calculated_hash == resource_hash

        # Step 6: Extract metadata if flagged
        extracted_metadata = None
        extracted_payload = decompressed_data
        if case_has_metadata:
            metadata_size = decompressed_data[0] << 16 | decompressed_data[1] << 8 | decompressed_data[2]
            packed_metadata_extracted = decompressed_data[3:3 + metadata_size]
            from RNS.vendor import umsgpack
            extracted_metadata = umsgpack.unpackb(packed_metadata_extracted)
            extracted_payload = decompressed_data[3 + metadata_size:]

        assert verified, f"Assembly verification failed for case {idx}"
        assert extracted_payload == input_data, f"Assembled payload doesn't match input for case {idx}"
        if case_has_metadata:
            assert extracted_metadata == rv["metadata_dict"], f"Metadata mismatch for case {idx}"

        vector = {
            "index": idx,
            "description": f"Assembly verification for: {rv['description']}",
            "resource_hash_hex": rv["resource_hash_hex"],
            "random_hash_hex": rv["random_hash_hex"],
            "flags": rv["flags"],
            "steps": {
                "1_join_parts": f"Concatenate {rv['num_parts']} encrypted part(s) → {len(encrypted_data)} bytes",
                "2_decrypt": f"Token.decrypt(stream) → {len(decrypted_stream)} bytes",
                "3_strip_random_hash": f"Remove first {RANDOM_HASH_SIZE} bytes → {len(stripped_data)} bytes",
            },
            "decrypted_stream_hex": hex_prefix(decrypted_stream, 64),
            "decrypted_stream_length": len(decrypted_stream),
            "stripped_data_hex": hex_prefix(stripped_data, 64),
            "stripped_data_length": len(stripped_data),
        }

        if case_compressed:
            vector["steps"]["4_decompress"] = f"bz2.decompress(stripped_data) → {len(decompressed_data)} bytes"
            vector["decompressed_data_hex"] = hex_prefix(decompressed_data, 64)
            vector["decompressed_data_length"] = len(decompressed_data)

        vector["steps"]["5_verify_hash"] = f"SHA256(assembled_data + random_hash) == resource_hash → {verified}"
        vector["calculated_hash_hex"] = calculated_hash.hex()
        vector["verified"] = verified

        if case_has_metadata:
            vector["steps"]["6_extract_metadata"] = f"Read 3-byte size prefix, extract {metadata_size} bytes of packed metadata"
            vector["extracted_metadata_size"] = metadata_size
            vector["extracted_metadata"] = extracted_metadata
            vector["extracted_payload_hex"] = hex_prefix(extracted_payload, 64)
            vector["extracted_payload_length"] = len(extracted_payload)
        else:
            vector["extracted_payload_hex"] = hex_prefix(extracted_payload, 64)
            vector["extracted_payload_length"] = len(extracted_payload)

        vectors.append(vector)

    return vectors


def extract_proof_vectors(resource_vectors):
    """Generate resource proof test vectors."""

    vectors = []

    for rv in resource_vectors:
        idx = rv["index"]
        resource_hash = bytes.fromhex(rv["resource_hash_hex"])
        expected_proof = bytes.fromhex(rv["expected_proof_hex"])
        data_with_metadata_length = rv["data_with_metadata_length"]

        # Resource proof: SHA256(data_with_metadata + resource_hash)
        # The receiver computes this from the assembled plaintext data

        # Proof packet payload: resource_hash(32) + proof(32) = 64 bytes
        proof_packet_payload = resource_hash + expected_proof

        vectors.append({
            "index": idx,
            "description": f"Resource proof for: {rv['description']}",
            "resource_hash_hex": resource_hash.hex(),
            "expected_proof_hex": expected_proof.hex(),
            "proof_computation": "SHA256(data_with_metadata + resource_hash)",
            "proof_computation_note": "data_with_metadata is the pre-compression, pre-encryption plaintext (metadata_bytes + resource_data)",
            "proof_packet_payload_hex": proof_packet_payload.hex(),
            "proof_packet_payload_length": len(proof_packet_payload),
            "proof_packet_layout": f"resource_hash({HASHLENGTH_BYTES}) + proof({HASHLENGTH_BYTES}) = {len(proof_packet_payload)} bytes",
            "validation_note": "Sender validates: proof_data[32:] == self.expected_proof (Resource.validate_proof line 774)",
        })

    return vectors


def extract_invalid_metadata_vector():
    """Document the invalid metadata size edge case."""
    return {
        "description": "Metadata exceeding METADATA_MAX_SIZE raises SystemError",
        "METADATA_MAX_SIZE": METADATA_MAX_SIZE,
        "METADATA_MAX_SIZE_hex": f"0x{METADATA_MAX_SIZE:06x}",
        "METADATA_MAX_SIZE_bytes": f"{METADATA_MAX_SIZE} bytes ({METADATA_MAX_SIZE / (1024*1024):.0f} MiB - 1 byte)",
        "error_type": "SystemError",
        "error_message": "Resource metadata size exceeded",
        "source": "Resource.py line 262",
        "size_prefix_max": "3 bytes big-endian = 0xFFFFFF = 16777215",
        "note": "The 3-byte size prefix naturally limits metadata to 16777215 bytes",
    }


def verify(output, derived_key):
    """Cross-validate all vectors."""
    from RNS.Cryptography.Token import Token
    from RNS.vendor import umsgpack

    print("  Verifying...")
    token = Token(key=derived_key)

    # 1. Verify metadata vectors: pack/unpack round-trip
    for mv in output["metadata_vectors"]:
        # For cases 0 and 1 (non-truncated), verify full round-trip
        if "..." not in mv["packed_metadata_hex"]:
            packed = bytes.fromhex(mv["packed_metadata_hex"])
            unpacked = umsgpack.unpackb(packed)
            # Check size prefix decoding
            full_bytes = bytes.fromhex(mv["full_metadata_bytes_hex"])
            decoded_size = full_bytes[0] << 16 | full_bytes[1] << 8 | full_bytes[2]
            assert decoded_size == len(packed), f"Metadata size prefix mismatch: {decoded_size} != {len(packed)}"
            assert full_bytes[3:3 + decoded_size] == packed

    print(f"    [OK] {len(output['metadata_vectors'])} metadata vectors verified")

    # 2. Verify resource advertisement vectors
    for rv in output["resource_advertisement_vectors"]:
        # Verify advertisement unpacks correctly
        adv_packed = bytes.fromhex(rv["advertisement_packed_hex"])
        adv = umsgpack.unpackb(adv_packed)
        assert adv["t"] == rv["encrypted_data_length"]
        assert adv["d"] == rv["total_size"]
        assert adv["n"] == rv["num_parts"]
        assert adv["f"] == rv["flags"]
        assert adv["h"] == bytes.fromhex(rv["resource_hash_hex"])
        assert adv["r"] == bytes.fromhex(rv["random_hash_hex"])
        assert adv["o"] == bytes.fromhex(rv["original_hash_hex"])
        assert adv["i"] == 1
        assert adv["l"] == 1

        # Verify flags breakdown
        fb = rv["flags_breakdown"]
        f = rv["flags"]
        assert fb["encrypted"] == bool(f & 0x01)
        assert fb["compressed"] == bool(f & 0x02)
        assert fb["split"] == bool(f & 0x04)
        assert fb["is_request"] == bool(f & 0x08)
        assert fb["is_response"] == bool(f & 0x10)
        assert fb["has_metadata"] == bool(f & 0x20)

    print(f"    [OK] {len(output['resource_advertisement_vectors'])} resource advertisement vectors verified")

    # 3. Verify assembly vectors
    for av in output["assembly_vectors"]:
        assert av["verified"] is True, f"Assembly verification failed for case {av['index']}"

    print(f"    [OK] {len(output['assembly_vectors'])} assembly vectors verified")

    # 4. Verify proof vectors: recompute from known data
    for pv in output["resource_proof_vectors"]:
        idx = pv["index"]
        rv = output["resource_advertisement_vectors"][idx]

        # Reconstruct data_with_metadata
        input_data_length = rv["input_data_length"]
        case_has_metadata = rv["has_metadata"]
        case_compressed = rv["compressed"]

        if case_compressed and idx == 2:
            pattern = b"RETICULUM_TEST_PATTERN_" + str(idx).encode() + b"_"
            input_data = (pattern * ((input_data_length // len(pattern)) + 1))[:input_data_length]
        else:
            input_data = deterministic_data(idx, input_data_length)

        if case_has_metadata:
            metadata_dict = rv["metadata_dict"]
            packed_metadata = umsgpack.packb(metadata_dict)
            metadata_bytes = struct.pack(">I", len(packed_metadata))[1:] + packed_metadata
            data_with_metadata = metadata_bytes + input_data
        else:
            data_with_metadata = input_data

        random_hash = bytes.fromhex(rv["random_hash_hex"])
        resource_hash = bytes.fromhex(rv["resource_hash_hex"])

        # Verify resource hash
        expected_hash = full_hash(data_with_metadata + random_hash)
        assert expected_hash == resource_hash, f"Resource hash mismatch for case {idx}"

        # Verify proof
        expected_proof = full_hash(data_with_metadata + resource_hash)
        assert expected_proof.hex() == pv["expected_proof_hex"], f"Proof mismatch for case {idx}"

    print(f"    [OK] {len(output['resource_proof_vectors'])} resource proof vectors verified")

    # 5. Cross-check derived_key from links.json
    links_data = load_links_json()
    hs0 = links_data["handshake_vectors"][0]
    links_derived_key = hs0["step_2_lrproof"]["derived_key"]
    assert derived_key.hex() == links_derived_key, f"derived_key mismatch with links.json"
    print("    [OK] derived_key cross-validated against links.json")

    # 6. JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("    [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify our local constants match the actual RNS library values."""
    import RNS
    from RNS.Link import Link
    from RNS.Packet import Packet
    from RNS.Resource import Resource, ResourceAdvertisement

    assert MTU == RNS.Reticulum.MTU
    assert HEADER_MINSIZE == RNS.Reticulum.HEADER_MINSIZE
    assert HEADER_MAXSIZE == RNS.Reticulum.HEADER_MAXSIZE
    assert IFAC_MIN_SIZE == RNS.Reticulum.IFAC_MIN_SIZE
    assert TOKEN_OVERHEAD == RNS.Identity.TOKEN_OVERHEAD
    assert AES128_BLOCKSIZE == RNS.Identity.AES128_BLOCKSIZE
    assert HASHLENGTH_BYTES == RNS.Identity.HASHLENGTH // 8
    assert TRUNCATED_HASHLENGTH_BYTES == RNS.Reticulum.TRUNCATED_HASHLENGTH // 8

    assert LINK_MDU == Link.MDU, f"LINK_MDU mismatch: {LINK_MDU} != {Link.MDU}"
    assert RESOURCE_SDU == Packet.MDU, f"RESOURCE_SDU mismatch: {RESOURCE_SDU} != {Packet.MDU}"
    assert RESOURCE_SDU == RNS.Reticulum.MDU, f"RESOURCE_SDU != Reticulum.MDU"

    # Resource constants
    assert WINDOW == Resource.WINDOW
    assert WINDOW_MIN == Resource.WINDOW_MIN
    assert WINDOW_MAX_SLOW == Resource.WINDOW_MAX_SLOW
    assert WINDOW_MAX_VERY_SLOW == Resource.WINDOW_MAX_VERY_SLOW
    assert WINDOW_MAX_FAST == Resource.WINDOW_MAX_FAST
    assert WINDOW_MAX == Resource.WINDOW_MAX
    assert FAST_RATE_THRESHOLD == Resource.FAST_RATE_THRESHOLD
    assert VERY_SLOW_RATE_THRESHOLD == Resource.VERY_SLOW_RATE_THRESHOLD
    assert RATE_FAST == Resource.RATE_FAST
    assert RATE_VERY_SLOW == Resource.RATE_VERY_SLOW
    assert WINDOW_FLEXIBILITY == Resource.WINDOW_FLEXIBILITY
    assert MAPHASH_LEN == Resource.MAPHASH_LEN
    assert RANDOM_HASH_SIZE == Resource.RANDOM_HASH_SIZE
    assert MAX_EFFICIENT_SIZE == Resource.MAX_EFFICIENT_SIZE
    assert METADATA_MAX_SIZE == Resource.METADATA_MAX_SIZE
    assert AUTO_COMPRESS_MAX_SIZE == Resource.AUTO_COMPRESS_MAX_SIZE
    assert PART_TIMEOUT_FACTOR == Resource.PART_TIMEOUT_FACTOR
    assert PART_TIMEOUT_FACTOR_AFTER_RTT == Resource.PART_TIMEOUT_FACTOR_AFTER_RTT
    assert PROOF_TIMEOUT_FACTOR == Resource.PROOF_TIMEOUT_FACTOR
    assert MAX_RETRIES == Resource.MAX_RETRIES
    assert MAX_ADV_RETRIES == Resource.MAX_ADV_RETRIES
    assert SENDER_GRACE_TIME == Resource.SENDER_GRACE_TIME
    assert PROCESSING_GRACE == Resource.PROCESSING_GRACE
    assert RETRY_GRACE_TIME == Resource.RETRY_GRACE_TIME
    assert PER_RETRY_DELAY == Resource.PER_RETRY_DELAY
    assert WATCHDOG_MAX_SLEEP == Resource.WATCHDOG_MAX_SLEEP
    assert HASHMAP_IS_NOT_EXHAUSTED == Resource.HASHMAP_IS_NOT_EXHAUSTED
    assert HASHMAP_IS_EXHAUSTED == Resource.HASHMAP_IS_EXHAUSTED
    assert RESPONSE_MAX_GRACE_TIME == Resource.RESPONSE_MAX_GRACE_TIME

    # Status constants
    assert STATUS_NONE == Resource.NONE
    assert STATUS_QUEUED == Resource.QUEUED
    assert STATUS_ADVERTISED == Resource.ADVERTISED
    assert STATUS_TRANSFERRING == Resource.TRANSFERRING
    assert STATUS_AWAITING_PROOF == Resource.AWAITING_PROOF
    assert STATUS_ASSEMBLING == Resource.ASSEMBLING
    assert STATUS_COMPLETE == Resource.COMPLETE
    assert STATUS_FAILED == Resource.FAILED
    assert STATUS_CORRUPT == Resource.CORRUPT

    # ResourceAdvertisement constants
    assert OVERHEAD == ResourceAdvertisement.OVERHEAD
    assert HASHMAP_MAX_LEN == ResourceAdvertisement.HASHMAP_MAX_LEN
    assert COLLISION_GUARD_SIZE == ResourceAdvertisement.COLLISION_GUARD_SIZE

    print("  [OK] All library constants verified")


def main():
    print("Extracting resource transfer test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    # Load derived key from links.json (handshake scenario 0)
    links_data = load_links_json()
    hs0 = links_data["handshake_vectors"][0]
    derived_key = bytes.fromhex(hs0["step_2_lrproof"]["derived_key"])
    print(f"  Loaded derived_key from links.json ({len(derived_key)} bytes)")

    print("Extracting constants...")
    constants = extract_constants()

    print("Extracting metadata vectors...")
    metadata_vectors = extract_metadata_vectors()
    print(f"  Extracted {len(metadata_vectors)} metadata vectors")

    print("Extracting resource advertisement vectors...")
    resource_adv_vectors = build_resource_vectors(derived_key)
    print(f"  Extracted {len(resource_adv_vectors)} resource advertisement vectors")

    print("Extracting assembly vectors...")
    assembly_vectors = extract_assembly_vectors(resource_adv_vectors, derived_key)
    print(f"  Extracted {len(assembly_vectors)} assembly vectors")

    print("Extracting resource proof vectors...")
    proof_vectors = extract_proof_vectors(resource_adv_vectors)
    print(f"  Extracted {len(proof_vectors)} resource proof vectors")

    print("Extracting invalid metadata vector...")
    invalid_meta = extract_invalid_metadata_vector()

    output = {
        "description": "Reticulum v1.1.3 - resource transfer test vectors",
        "source": "RNS/Resource.py, RNS/Cryptography/Token.py",
        "constants": constants,
        "metadata_vectors": metadata_vectors,
        "resource_advertisement_vectors": resource_adv_vectors,
        "assembly_vectors": assembly_vectors,
        "resource_proof_vectors": proof_vectors,
        "invalid_metadata_vector": invalid_meta,
    }

    verify(output, derived_key)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
