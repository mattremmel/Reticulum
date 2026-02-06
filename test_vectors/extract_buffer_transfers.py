#!/usr/bin/env python3
"""
Extract buffer protocol transfer test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Channel/Link/Buffer objects) to avoid
Transport init. Pure computation using struct, bz2, and hashlib.

Simulates RawChannelWriter.write() segmentation/compression logic and
StreamDataMessage pack/unpack to produce deterministic message sequences
for given input data.

Covers:
  A. Buffer transfer constants
  B. Small transfers (1KB) — single/multi-message, compressed/raw
  C. Large transfers (50KB, 1MB) — message counts, spot-check hex
  D. Compression behavior — skip, try 1/2/3, fallback
  E. EOF signaling — normal, immediate, non-zero stream_id
  F. Bidirectional buffers — different stream IDs, both directions
  G. Reader reassembly — step-by-step unpacking and concatenation

Usage:
    python3 test_vectors/extract_buffer_transfers.py

Output:
    test_vectors/buffer_transfers.json
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

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "buffer_transfers.json")

# ============================================================
# Constants (reproduced from RNS sources to avoid Transport init)
# ============================================================

# From RNS/Reticulum.py
MTU = 500
HEADER_MINSIZE = 19
IFAC_MIN_SIZE = 1

# From RNS/Identity.py
TOKEN_OVERHEAD = 48
AES128_BLOCKSIZE = 16

# From RNS/Link.py
LINK_MDU = math.floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1

# From RNS/Channel.py
ENVELOPE_HEADER_SIZE = 6  # struct.pack('>HHH', msgtype, seq, len)
SMT_STREAM_DATA = 0xFF00

# From RNS/Buffer.py
STREAM_ID_MAX = 0x3FFF
STREAM_DATA_OVERHEAD = 2 + 6  # 2 for stream header, 6 for channel envelope
MAX_DATA_LEN = LINK_MDU - STREAM_DATA_OVERHEAD
MAX_CHUNK_LEN = 1024 * 16  # 16384
COMPRESSION_TRIES = 4


# ============================================================
# Helper functions
# ============================================================

def stream_data_pack(stream_id, data, eof=False, compressed=False):
    """Pack a StreamDataMessage: 2-byte header + data.

    Header format (big-endian uint16):
      bit 15: eof flag
      bit 14: compressed flag
      bits 0-13: stream_id (0-16383)
    """
    header_val = (0x3FFF & stream_id) | (0x8000 if eof else 0x0000) | (0x4000 if compressed else 0x0000)
    return struct.pack(">H", header_val) + (data if data else bytes())


def stream_data_unpack(raw):
    """Unpack a StreamDataMessage. Returns (stream_id, eof, compressed, data).

    Note: if compressed flag is set, data is bz2-decompressed before return.
    """
    header = struct.unpack(">H", raw[:2])[0]
    eof = (0x8000 & header) > 0
    compressed = (0x4000 & header) > 0
    stream_id = header & 0x3FFF
    data = raw[2:]
    if compressed:
        data = bz2.decompress(data)
    return stream_id, eof, compressed, data


def envelope_pack(msgtype, sequence, data):
    """Pack a channel envelope: struct.pack('>HHH', msgtype, seq, len(data)) + data"""
    return struct.pack(">HHH", msgtype, sequence, len(data)) + data


def simulate_write(input_data, stream_id, eof=False):
    """Simulate a single RawChannelWriter.write() call.

    Mirrors Buffer.py:229-264 exactly.

    Returns dict with:
      processed_length: how many bytes of input were consumed
      compressed: whether compression was used
      chunk_hex: the chunk data (compressed or raw) as hex
      stream_packed_hex: StreamDataMessage packed bytes as hex
      envelope_packed_hex: full envelope (6 + stream msg) as hex
      compression_attempts: list of dicts showing each try
    """
    comp_tries = COMPRESSION_TRIES
    comp_try = 1
    comp_success = False
    chunk_len = len(input_data)
    if chunk_len > MAX_CHUNK_LEN:
        chunk_len = MAX_CHUNK_LEN
        input_data = input_data[:MAX_CHUNK_LEN]
    chunk_segment = None
    compression_attempts = []

    while chunk_len > 32 and comp_try < comp_tries:
        chunk_segment_length = int(chunk_len / comp_try)
        compressed_chunk = bz2.compress(input_data[:chunk_segment_length])
        compressed_length = len(compressed_chunk)

        attempt = {
            "try": comp_try,
            "segment_length": chunk_segment_length,
            "compressed_length": compressed_length,
            "fits_max_data_len": compressed_length < MAX_DATA_LEN,
            "smaller_than_segment": compressed_length < chunk_segment_length,
        }

        if compressed_length < MAX_DATA_LEN and compressed_length < chunk_segment_length:
            comp_success = True
            attempt["result"] = "success"
            compression_attempts.append(attempt)
            break
        else:
            attempt["result"] = "failed"
            compression_attempts.append(attempt)
            comp_try += 1

    if comp_success:
        chunk = compressed_chunk
        processed_length = chunk_segment_length
    else:
        chunk = bytes(input_data[:MAX_DATA_LEN])
        processed_length = len(chunk)

    stream_packed = stream_data_pack(stream_id, chunk, eof=eof, compressed=comp_success)
    # Envelope uses sequence=0 as placeholder; actual sequence assigned by Channel
    # We don't assign sequence here — caller manages it for multi-message transfers
    envelope_packed = envelope_pack(SMT_STREAM_DATA, 0, stream_packed)

    return {
        "processed_length": processed_length,
        "compressed": comp_success,
        "chunk_hex": chunk.hex(),
        "chunk_length": len(chunk),
        "stream_packed_hex": stream_packed.hex(),
        "stream_packed_length": len(stream_packed),
        "envelope_packed_hex": envelope_packed.hex(),
        "envelope_packed_length": len(envelope_packed),
        "compression_attempts": compression_attempts,
        "compression_skipped": chunk_len <= 32,
    }


def simulate_transfer(full_data, stream_id):
    """Simulate a complete buffer transfer: write all data + close().

    Returns list of message dicts, each from simulate_write(),
    plus a final EOF message.
    """
    messages = []
    offset = 0
    seq = 0

    while offset < len(full_data):
        remaining = full_data[offset:]
        result = simulate_write(remaining, stream_id, eof=False)
        result["offset"] = offset
        result["sequence"] = seq

        # Re-pack envelope with correct sequence
        stream_packed = bytes.fromhex(result["stream_packed_hex"])
        envelope_packed = envelope_pack(SMT_STREAM_DATA, seq, stream_packed)
        result["envelope_packed_hex"] = envelope_packed.hex()
        result["envelope_packed_length"] = len(envelope_packed)

        messages.append(result)
        offset += result["processed_length"]
        seq += 1

    # EOF message: close() sets eof=True, writes empty bytes
    eof_result = simulate_write(b"", stream_id, eof=True)
    eof_result["offset"] = offset
    eof_result["sequence"] = seq
    eof_result["is_eof"] = True

    # Re-pack with correct sequence
    stream_packed = bytes.fromhex(eof_result["stream_packed_hex"])
    envelope_packed = envelope_pack(SMT_STREAM_DATA, seq, stream_packed)
    eof_result["envelope_packed_hex"] = envelope_packed.hex()
    eof_result["envelope_packed_length"] = len(envelope_packed)

    messages.append(eof_result)

    return messages


def deterministic_data(seed, length):
    """Generate deterministic data of given length via SHA-256 expansion.

    Uses seed string to generate initial hash, then expands with counter.
    """
    seed_hash = hashlib.sha256(b"reticulum_buffer_test_" + seed.encode()).digest()
    result = b""
    counter = 0
    while len(result) < length:
        chunk = hashlib.sha256(seed_hash + struct.pack(">I", counter)).digest()
        result += chunk
        counter += 1
    return result[:length]


def hex_prefix(data, max_bytes=64):
    """Return hex string, truncated with note if longer than max_bytes."""
    if len(data) <= max_bytes:
        return data.hex()
    return data[:max_bytes].hex() + f"... ({len(data)} bytes total)"


def data_sha256(data):
    """Return SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def compact_message(msg):
    """Create a compact summary of a message for large transfer vectors."""
    result = {
        "index": msg.get("sequence", 0),
        "offset": msg["offset"],
        "processed_length": msg["processed_length"],
        "compressed": msg["compressed"],
        "chunk_length": msg["chunk_length"],
    }
    if msg.get("is_eof"):
        result["is_eof"] = True
    return result


# ============================================================
# Extraction functions
# ============================================================

def extract_constants():
    """Extract buffer transfer-specific constants."""
    return {
        "MAX_CHUNK_LEN": MAX_CHUNK_LEN,
        "MAX_CHUNK_LEN_note": "Maximum input bytes consumed per write() call = 16384",
        "COMPRESSION_TRIES": COMPRESSION_TRIES,
        "COMPRESSION_TRIES_note": "Loop tries comp_try = 1, 2, 3 (comp_try < 4); segment = chunk_len/comp_try",
        "MAX_DATA_LEN": MAX_DATA_LEN,
        "MAX_DATA_LEN_derivation": f"LINK_MDU({LINK_MDU}) - STREAM_DATA_OVERHEAD({STREAM_DATA_OVERHEAD}) = {MAX_DATA_LEN}",
        "LINK_MDU": LINK_MDU,
        "STREAM_DATA_OVERHEAD": STREAM_DATA_OVERHEAD,
        "STREAM_DATA_OVERHEAD_note": "2 bytes StreamDataMessage header + 6 bytes Channel envelope",
        "STREAM_ID_MAX": STREAM_ID_MAX,
        "ENVELOPE_HEADER_SIZE": ENVELOPE_HEADER_SIZE,
        "SMT_STREAM_DATA": SMT_STREAM_DATA,
        "SMT_STREAM_DATA_hex": f"0x{SMT_STREAM_DATA:04x}",
        "compression_skip_threshold": 32,
        "compression_skip_note": "Compression loop only runs when chunk_len > 32",
    }


def extract_small_transfer_vectors():
    """Category B: Small transfers (xbd)."""
    vectors = []

    # Vector 0: Tiny (6 bytes "Hello\n") — single message, no compression (<=32 skip)
    data_0 = b"Hello\n"
    msgs_0 = simulate_transfer(data_0, stream_id=0)
    vectors.append({
        "index": 0,
        "description": "Tiny transfer (6 bytes 'Hello\\n') — compression skipped (<=32B), single data msg + EOF",
        "input_data_hex": data_0.hex(),
        "input_data_length": len(data_0),
        "input_sha256": data_sha256(data_0),
        "stream_id": 0,
        "message_count": len(msgs_0),
        "messages": msgs_0,
    })

    # Vector 1: Medium (200 bytes random) — single message, no compression (bz2 overhead > original)
    data_1 = deterministic_data("medium_200", 200)
    msgs_1 = simulate_transfer(data_1, stream_id=0)
    vectors.append({
        "index": 1,
        "description": "Medium transfer (200B random) — single data msg, compression attempted but fails (bz2 overhead > data)",
        "input_data_hex": data_1.hex(),
        "input_data_length": len(data_1),
        "input_sha256": data_sha256(data_1),
        "stream_id": 0,
        "data_seed": "medium_200",
        "message_count": len(msgs_1),
        "messages": msgs_1,
    })

    # Vector 2: 1KB incompressible — ~3 data messages + EOF (raw truncation at 423B each)
    data_2 = deterministic_data("incompressible_1k", 1024)
    msgs_2 = simulate_transfer(data_2, stream_id=0)
    vectors.append({
        "index": 2,
        "description": "1KB incompressible data — multiple data messages at MAX_DATA_LEN (423B) each + EOF",
        "input_data_hex": data_2.hex(),
        "input_data_length": len(data_2),
        "input_sha256": data_sha256(data_2),
        "stream_id": 0,
        "data_seed": "incompressible_1k",
        "message_count": len(msgs_2),
        "messages": msgs_2,
    })

    # Vector 3: 1KB compressible (repeated bytes) — 1 compressed message + EOF
    data_3 = b"A" * 1024
    msgs_3 = simulate_transfer(data_3, stream_id=0)
    vectors.append({
        "index": 3,
        "description": "1KB compressible data (repeated 'A') — 1 compressed data msg + EOF",
        "input_data_hex": hex_prefix(data_3, 32),
        "input_data_length": len(data_3),
        "input_sha256": data_sha256(data_3),
        "stream_id": 0,
        "message_count": len(msgs_3),
        "messages": msgs_3,
    })

    return vectors


def extract_large_transfer_vectors():
    """Category C: Large transfers (xbd)."""
    vectors = []

    # Vector 4: 50KB compressible
    data_4 = b"RETICULUM_COMPRESSIBLE_PATTERN_" * (50 * 1024 // 30 + 1)
    data_4 = data_4[:50 * 1024]
    msgs_4 = simulate_transfer(data_4, stream_id=0)

    # Spot-check messages: first, mid, last data msg, EOF
    data_msgs_4 = [m for m in msgs_4 if not m.get("is_eof")]
    eof_msg_4 = msgs_4[-1]
    mid_idx_4 = len(data_msgs_4) // 2

    vectors.append({
        "index": 4,
        "description": "50KB compressible data — compressed messages",
        "input_data_length": len(data_4),
        "input_sha256": data_sha256(data_4),
        "stream_id": 0,
        "message_count": len(msgs_4),
        "data_message_count": len(data_msgs_4),
        "total_wire_bytes": sum(m["envelope_packed_length"] for m in msgs_4),
        "compact_messages": [compact_message(m) for m in msgs_4],
        "spot_checks": {
            "first": msgs_4[0],
            "mid": msgs_4[mid_idx_4],
            "last_data": data_msgs_4[-1],
            "eof": eof_msg_4,
        },
    })

    # Vector 5: 50KB incompressible
    data_5 = deterministic_data("incompressible_50k", 50 * 1024)
    msgs_5 = simulate_transfer(data_5, stream_id=0)
    data_msgs_5 = [m for m in msgs_5 if not m.get("is_eof")]
    eof_msg_5 = msgs_5[-1]
    mid_idx_5 = len(data_msgs_5) // 2

    vectors.append({
        "index": 5,
        "description": "50KB incompressible data — raw truncation at MAX_DATA_LEN each",
        "input_data_length": len(data_5),
        "input_sha256": data_sha256(data_5),
        "stream_id": 0,
        "data_seed": "incompressible_50k",
        "message_count": len(msgs_5),
        "data_message_count": len(data_msgs_5),
        "total_wire_bytes": sum(m["envelope_packed_length"] for m in msgs_5),
        "compact_messages": [compact_message(m) for m in msgs_5],
        "spot_checks": {
            "first": msgs_5[0],
            "mid": msgs_5[mid_idx_5],
            "last_data": data_msgs_5[-1],
            "eof": eof_msg_5,
        },
    })

    # Vector 6: 1MB compressible
    data_6 = b"RETICULUM_1MB_COMPRESSIBLE_" * (1024 * 1024 // 26 + 1)
    data_6 = data_6[:1024 * 1024]
    msgs_6 = simulate_transfer(data_6, stream_id=0)
    data_msgs_6 = [m for m in msgs_6 if not m.get("is_eof")]
    eof_msg_6 = msgs_6[-1]
    mid_idx_6 = len(data_msgs_6) // 2

    vectors.append({
        "index": 6,
        "description": "1MB compressible data — compressed messages, summary only",
        "input_data_length": len(data_6),
        "input_sha256": data_sha256(data_6),
        "stream_id": 0,
        "message_count": len(msgs_6),
        "data_message_count": len(data_msgs_6),
        "total_wire_bytes": sum(m["envelope_packed_length"] for m in msgs_6),
        "compact_messages": [compact_message(m) for m in msgs_6],
        "spot_checks": {
            "first": msgs_6[0],
            "mid": msgs_6[mid_idx_6],
            "last_data": data_msgs_6[-1],
            "eof": eof_msg_6,
        },
    })

    # Vector 7: 1MB incompressible
    data_7 = deterministic_data("incompressible_1m", 1024 * 1024)
    msgs_7 = simulate_transfer(data_7, stream_id=0)
    data_msgs_7 = [m for m in msgs_7 if not m.get("is_eof")]
    eof_msg_7 = msgs_7[-1]
    mid_idx_7 = len(data_msgs_7) // 2

    vectors.append({
        "index": 7,
        "description": "1MB incompressible data — raw messages, summary only",
        "input_data_length": len(data_7),
        "input_sha256": data_sha256(data_7),
        "stream_id": 0,
        "data_seed": "incompressible_1m",
        "message_count": len(msgs_7),
        "data_message_count": len(data_msgs_7),
        "total_wire_bytes": sum(m["envelope_packed_length"] for m in msgs_7),
        "compact_messages": [compact_message(m) for m in msgs_7],
        "spot_checks": {
            "first": msgs_7[0],
            "mid": msgs_7[mid_idx_7],
            "last_data": data_msgs_7[-1],
            "eof": eof_msg_7,
        },
    })

    return vectors


def extract_compression_vectors():
    """Category D: Compression behavior (wi8)."""
    vectors = []

    # Vector 8: <=32 bytes — compression skipped entirely
    data_8 = b"Short data under 33 bytes!12345"  # exactly 30 bytes
    result_8 = simulate_write(data_8, stream_id=0, eof=False)
    vectors.append({
        "index": 8,
        "description": f"Compression skipped: {len(data_8)} bytes <= 32 threshold",
        "input_data_hex": data_8.hex(),
        "input_data_length": len(data_8),
        "stream_id": 0,
        "write_result": result_8,
    })

    # Vector 9: 500B highly compressible — compression succeeds on try 1
    data_9 = b"Z" * 500
    result_9 = simulate_write(data_9, stream_id=0, eof=False)
    vectors.append({
        "index": 9,
        "description": "500B highly compressible — compression succeeds on try 1",
        "input_data_hex": hex_prefix(data_9, 32),
        "input_data_length": len(data_9),
        "stream_id": 0,
        "write_result": result_9,
    })

    # Vector 10: 500B incompressible — all 3 tries fail, raw truncation
    data_10 = deterministic_data("incompressible_500", 500)
    result_10 = simulate_write(data_10, stream_id=0, eof=False)
    vectors.append({
        "index": 10,
        "description": "500B incompressible — all 3 compression tries fail, raw truncation at MAX_DATA_LEN",
        "input_data_hex": data_10.hex(),
        "input_data_length": len(data_10),
        "stream_id": 0,
        "data_seed": "incompressible_500",
        "write_result": result_10,
    })

    # Vector 11: 16384B (MAX_CHUNK_LEN) partially compressible
    # Use data that's partially compressible: half pattern, half random
    pattern_half = b"COMPRESS_ME_" * (8192 // 12 + 1)
    pattern_half = pattern_half[:8192]
    random_half = deterministic_data("partial_compress_half", 8192)
    data_11 = pattern_half + random_half
    result_11 = simulate_write(data_11, stream_id=0, eof=False)
    vectors.append({
        "index": 11,
        "description": "16384B (MAX_CHUNK_LEN) partially compressible — shows multi-try compression behavior",
        "input_data_length": len(data_11),
        "input_sha256": data_sha256(data_11),
        "stream_id": 0,
        "write_result": result_11,
    })

    # Vector 12: Exactly MAX_DATA_LEN (423B) — fits in one raw message
    data_12 = deterministic_data("exact_max_data_len", MAX_DATA_LEN)
    result_12 = simulate_write(data_12, stream_id=0, eof=False)
    vectors.append({
        "index": 12,
        "description": f"Exactly MAX_DATA_LEN ({MAX_DATA_LEN}B) — fits in one raw message, processed_length == input length",
        "input_data_hex": data_12.hex(),
        "input_data_length": len(data_12),
        "stream_id": 0,
        "data_seed": "exact_max_data_len",
        "write_result": result_12,
    })

    return vectors


def extract_eof_vectors():
    """Category E: EOF signaling (wi8)."""
    vectors = []

    # Vector 13: Normal EOF after data transfer
    data_13 = b"Some data before EOF"
    data_msgs = simulate_transfer(data_13, stream_id=0)
    eof_msg = data_msgs[-1]  # last message is EOF

    # Parse the EOF message's stream data header
    eof_stream_packed = bytes.fromhex(eof_msg["stream_packed_hex"])
    eof_header = struct.unpack(">H", eof_stream_packed[:2])[0]

    vectors.append({
        "index": 13,
        "description": "Normal EOF after data transfer — write data, then close()",
        "input_data_hex": data_13.hex(),
        "input_data_length": len(data_13),
        "stream_id": 0,
        "total_messages": len(data_msgs),
        "eof_message": eof_msg,
        "eof_header_value": eof_header,
        "eof_header_hex": f"0x{eof_header:04x}",
        "eof_header_breakdown": {
            "eof_bit_15": bool(eof_header & 0x8000),
            "compressed_bit_14": bool(eof_header & 0x4000),
            "stream_id_bits_0_13": eof_header & 0x3FFF,
        },
    })

    # Vector 14: Immediate EOF (no data) — just close()
    # close() sets _eof=True then calls write(bytes())
    eof_result = simulate_write(b"", stream_id=0, eof=True)
    stream_packed_14 = bytes.fromhex(eof_result["stream_packed_hex"])
    envelope_packed_14 = envelope_pack(SMT_STREAM_DATA, 0, stream_packed_14)
    eof_header_14 = struct.unpack(">H", stream_packed_14[:2])[0]

    vectors.append({
        "index": 14,
        "description": "Immediate EOF (no data) — just close() with no prior writes",
        "stream_id": 0,
        "eof_message": eof_result,
        "envelope_packed_hex": envelope_packed_14.hex(),
        "envelope_packed_length": len(envelope_packed_14),
        "eof_header_value": eof_header_14,
        "eof_header_hex": f"0x{eof_header_14:04x}",
        "eof_header_breakdown": {
            "eof_bit_15": bool(eof_header_14 & 0x8000),
            "compressed_bit_14": bool(eof_header_14 & 0x4000),
            "stream_id_bits_0_13": eof_header_14 & 0x3FFF,
        },
    })

    # Vector 15: EOF with non-zero stream_id
    eof_result_15 = simulate_write(b"", stream_id=42, eof=True)
    stream_packed_15 = bytes.fromhex(eof_result_15["stream_packed_hex"])
    envelope_packed_15 = envelope_pack(SMT_STREAM_DATA, 0, stream_packed_15)
    eof_header_15 = struct.unpack(">H", stream_packed_15[:2])[0]

    vectors.append({
        "index": 15,
        "description": "EOF with non-zero stream_id=42 — verify stream_id encoding preserved",
        "stream_id": 42,
        "eof_message": eof_result_15,
        "envelope_packed_hex": envelope_packed_15.hex(),
        "envelope_packed_length": len(envelope_packed_15),
        "eof_header_value": eof_header_15,
        "eof_header_hex": f"0x{eof_header_15:04x}",
        "eof_header_breakdown": {
            "eof_bit_15": bool(eof_header_15 & 0x8000),
            "compressed_bit_14": bool(eof_header_15 & 0x4000),
            "stream_id_bits_0_13": eof_header_15 & 0x3FFF,
        },
        "expected_stream_id": 42,
    })

    return vectors


def extract_bidirectional_vectors():
    """Category F: Bidirectional buffers (ouv)."""
    vectors = []

    # Vector 16: Small bidirectional — side A writes "Hello", side B writes "World"
    data_a_16 = b"Hello"
    data_b_16 = b"World"
    # In bidirectional: create_bidirectional_buffer(receive_stream_id, send_stream_id, channel)
    # Side A: sends on send_stream_id (e.g. 0), receives on receive_stream_id (e.g. 0)
    # Side B: the other direction uses different stream IDs
    # Typical setup: Side A tx_stream_id=0, Side B tx_stream_id=0 (same ID, direction-relative)
    # Or: Side A tx=0, Side B tx=1

    msgs_a = simulate_transfer(data_a_16, stream_id=0)
    msgs_b = simulate_transfer(data_b_16, stream_id=1)

    vectors.append({
        "index": 16,
        "description": "Small bidirectional — A writes 'Hello' (stream_id=0), B writes 'World' (stream_id=1)",
        "side_a": {
            "input_data_hex": data_a_16.hex(),
            "input_data_length": len(data_a_16),
            "stream_id": 0,
            "message_count": len(msgs_a),
            "messages": msgs_a,
        },
        "side_b": {
            "input_data_hex": data_b_16.hex(),
            "input_data_length": len(data_b_16),
            "stream_id": 1,
            "message_count": len(msgs_b),
            "messages": msgs_b,
        },
    })

    # Vector 17: Asymmetric sizes — 1KB one way, 100B the other
    data_a_17 = deterministic_data("bidir_1k", 1024)
    data_b_17 = deterministic_data("bidir_100", 100)
    msgs_a_17 = simulate_transfer(data_a_17, stream_id=0)
    msgs_b_17 = simulate_transfer(data_b_17, stream_id=1)

    vectors.append({
        "index": 17,
        "description": "Asymmetric bidirectional — A sends 1KB (stream_id=0), B sends 100B (stream_id=1)",
        "side_a": {
            "input_data_length": len(data_a_17),
            "input_sha256": data_sha256(data_a_17),
            "data_seed": "bidir_1k",
            "stream_id": 0,
            "message_count": len(msgs_a_17),
            "messages": msgs_a_17,
        },
        "side_b": {
            "input_data_length": len(data_b_17),
            "input_sha256": data_sha256(data_b_17),
            "data_seed": "bidir_100",
            "stream_id": 1,
            "message_count": len(msgs_b_17),
            "messages": msgs_b_17,
        },
    })

    # Vector 18: Same stream_id=0 both directions — stream_id is direction-relative
    data_a_18 = b"Direction A"
    data_b_18 = b"Direction B"
    msgs_a_18 = simulate_transfer(data_a_18, stream_id=0)
    msgs_b_18 = simulate_transfer(data_b_18, stream_id=0)

    vectors.append({
        "index": 18,
        "description": "Same stream_id=0 both directions — proves stream_id is direction-relative",
        "note": "In create_bidirectional_buffer, receive_stream_id and send_stream_id can both be 0 since direction disambiguates",
        "side_a": {
            "input_data_hex": data_a_18.hex(),
            "input_data_length": len(data_a_18),
            "stream_id": 0,
            "message_count": len(msgs_a_18),
            "messages": msgs_a_18,
        },
        "side_b": {
            "input_data_hex": data_b_18.hex(),
            "input_data_length": len(data_b_18),
            "stream_id": 0,
            "message_count": len(msgs_b_18),
            "messages": msgs_b_18,
        },
    })

    # Vector 19: Different stream IDs (tx=5)
    data_a_19 = b"Stream 5 data"
    msgs_a_19 = simulate_transfer(data_a_19, stream_id=5)

    vectors.append({
        "index": 19,
        "description": "Non-zero stream_id=5 — verify correct encoding in wire bytes",
        "side_a": {
            "input_data_hex": data_a_19.hex(),
            "input_data_length": len(data_a_19),
            "stream_id": 5,
            "message_count": len(msgs_a_19),
            "messages": msgs_a_19,
        },
    })

    return vectors


def extract_reassembly_vectors():
    """Category G: Reader reassembly (cross-cutting)."""
    vectors = []

    # Vector 20: Multi-message reassembly
    # Use 1KB incompressible data (same as vector 2) to show step-by-step
    data_20 = deterministic_data("incompressible_1k", 1024)
    msgs_20 = simulate_transfer(data_20, stream_id=0)

    # Step-by-step reassembly
    reassembly_steps = []
    assembled = b""
    for msg in msgs_20:
        stream_packed = bytes.fromhex(msg["stream_packed_hex"])
        sid, eof, comp, msg_data = stream_data_unpack(stream_packed)

        step = {
            "message_index": msg.get("sequence", 0),
            "stream_id": sid,
            "eof": eof,
            "compressed": comp,
            "data_length": len(msg_data),
            "assembled_length_before": len(assembled),
        }

        assembled += msg_data
        step["assembled_length_after"] = len(assembled)
        reassembly_steps.append(step)

    vectors.append({
        "index": 20,
        "description": "Multi-message reassembly — 1KB incompressible, step-by-step unpack and concatenation",
        "input_data_length": len(data_20),
        "input_sha256": data_sha256(data_20),
        "data_seed": "incompressible_1k",
        "stream_id": 0,
        "message_count": len(msgs_20),
        "reassembly_steps": reassembly_steps,
        "assembled_sha256": data_sha256(assembled),
        "reassembly_verified": data_sha256(assembled) == data_sha256(data_20),
    })

    # Vector 21: Mixed compression reassembly
    # Create data where some write calls compress and some don't.
    # 500B compressible + 500B incompressible + 500B compressible
    comp_part = b"X" * 500
    incomp_part = deterministic_data("mixed_incomp", 500)
    comp_part2 = b"Y" * 500
    data_21 = comp_part + incomp_part + comp_part2

    msgs_21 = simulate_transfer(data_21, stream_id=0)

    # Step-by-step reassembly
    reassembly_steps_21 = []
    assembled_21 = b""
    for msg in msgs_21:
        stream_packed = bytes.fromhex(msg["stream_packed_hex"])
        sid, eof, comp, msg_data = stream_data_unpack(stream_packed)

        step = {
            "message_index": msg.get("sequence", 0),
            "stream_id": sid,
            "eof": eof,
            "compressed": comp,
            "data_length": len(msg_data),
            "assembled_length_before": len(assembled_21),
        }

        assembled_21 += msg_data
        step["assembled_length_after"] = len(assembled_21)
        reassembly_steps_21.append(step)

    vectors.append({
        "index": 21,
        "description": "Mixed compression reassembly — some messages compressed, some raw",
        "input_data_description": "500B compressible ('X'*500) + 500B incompressible + 500B compressible ('Y'*500)",
        "input_data_length": len(data_21),
        "input_sha256": data_sha256(data_21),
        "stream_id": 0,
        "message_count": len(msgs_21),
        "reassembly_steps": reassembly_steps_21,
        "assembled_sha256": data_sha256(assembled_21),
        "reassembly_verified": data_sha256(assembled_21) == data_sha256(data_21),
    })

    return vectors


# ============================================================
# Verification
# ============================================================

def verify(output):
    """Cross-validate all vectors."""
    print("  Verifying...")

    # 1. Verify small transfer reassembly
    for sv in output["small_transfer_vectors"]:
        input_data_hex = sv["input_data_hex"]
        # Handle truncated hex
        if "..." in input_data_hex:
            # Regenerate from description
            if "repeated 'A'" in sv["description"]:
                original = b"A" * sv["input_data_length"]
            else:
                continue
        else:
            original = bytes.fromhex(input_data_hex)

        # Reassemble from messages
        assembled = b""
        for msg in sv["messages"]:
            stream_packed = bytes.fromhex(msg["stream_packed_hex"])
            sid, eof, comp, data = stream_data_unpack(stream_packed)
            assembled += data

        assert data_sha256(assembled) == sv["input_sha256"], \
            f"Small transfer {sv['index']}: reassembly SHA-256 mismatch"

    print(f"    [OK] {len(output['small_transfer_vectors'])} small transfer vectors verified")

    # 2. Verify large transfer spot-checks
    for lv in output["large_transfer_vectors"]:
        # Verify spot-check messages decode correctly
        for name, msg in lv["spot_checks"].items():
            stream_packed = bytes.fromhex(msg["stream_packed_hex"])
            sid, eof, comp, data = stream_data_unpack(stream_packed)
            assert sid == lv.get("stream_id", 0), f"Large transfer {lv['index']}.{name}: stream_id mismatch"

        # Verify compact_messages cover the full transfer
        compact = lv["compact_messages"]
        total_processed = sum(m["processed_length"] for m in compact if not m.get("is_eof"))
        assert total_processed == lv["input_data_length"], \
            f"Large transfer {lv['index']}: total processed {total_processed} != input {lv['input_data_length']}"

    print(f"    [OK] {len(output['large_transfer_vectors'])} large transfer vectors verified")

    # 3. Verify compression behavior vectors
    for cv in output["compression_vectors"]:
        wr = cv["write_result"]
        if cv["index"] == 8:
            # <=32 bytes: compression skipped
            assert wr["compression_skipped"] is True, f"Compression {cv['index']}: should be skipped"
            assert wr["compressed"] is False
        elif cv["index"] == 9:
            # Highly compressible: should succeed
            assert wr["compressed"] is True, f"Compression {cv['index']}: should succeed"
            assert len(wr["compression_attempts"]) == 1
            assert wr["compression_attempts"][0]["result"] == "success"
        elif cv["index"] == 10:
            # Incompressible: all tries fail
            assert wr["compressed"] is False, f"Compression {cv['index']}: should fail"
            assert all(a["result"] == "failed" for a in wr["compression_attempts"])
        elif cv["index"] == 12:
            # Exactly MAX_DATA_LEN: processed_length == MAX_DATA_LEN
            assert wr["processed_length"] == MAX_DATA_LEN, \
                f"Compression {cv['index']}: processed_length should be {MAX_DATA_LEN}, got {wr['processed_length']}"

    print(f"    [OK] {len(output['compression_vectors'])} compression vectors verified")

    # 4. Verify EOF vectors
    for ev in output["eof_vectors"]:
        header_val = ev["eof_header_value"]
        breakdown = ev["eof_header_breakdown"]
        assert breakdown["eof_bit_15"] is True, f"EOF {ev['index']}: eof bit should be set"
        assert breakdown["compressed_bit_14"] is False, f"EOF {ev['index']}: compressed bit should be clear"
        expected_sid = ev.get("expected_stream_id", ev.get("stream_id", 0))
        assert breakdown["stream_id_bits_0_13"] == expected_sid, \
            f"EOF {ev['index']}: stream_id should be {expected_sid}"

    print(f"    [OK] {len(output['eof_vectors'])} EOF vectors verified")

    # 5. Verify bidirectional vectors
    for bv in output["bidirectional_vectors"]:
        for side_key in ["side_a", "side_b"]:
            if side_key not in bv:
                continue
            side = bv[side_key]
            sid = side["stream_id"]
            for msg in side["messages"]:
                stream_packed = bytes.fromhex(msg["stream_packed_hex"])
                decoded_sid, eof, comp, data = stream_data_unpack(stream_packed)
                assert decoded_sid == sid, \
                    f"Bidirectional {bv['index']}.{side_key}: stream_id mismatch {decoded_sid} != {sid}"

    print(f"    [OK] {len(output['bidirectional_vectors'])} bidirectional vectors verified")

    # 6. Verify reassembly vectors
    for rv in output["reassembly_vectors"]:
        assert rv["reassembly_verified"] is True, f"Reassembly {rv['index']}: verification failed"

    print(f"    [OK] {len(output['reassembly_vectors'])} reassembly vectors verified")

    # 7. JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("    [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify our local constants match the actual RNS library values."""
    import RNS
    from RNS.Link import Link
    from RNS.Channel import Channel
    from RNS.Buffer import StreamDataMessage, RawChannelWriter

    assert LINK_MDU == Link.MDU, f"LINK_MDU: {LINK_MDU} != {Link.MDU}"
    assert MAX_DATA_LEN == StreamDataMessage.MAX_DATA_LEN, \
        f"MAX_DATA_LEN: {MAX_DATA_LEN} != {StreamDataMessage.MAX_DATA_LEN}"
    assert STREAM_DATA_OVERHEAD == StreamDataMessage.OVERHEAD, \
        f"STREAM_DATA_OVERHEAD: {STREAM_DATA_OVERHEAD} != {StreamDataMessage.OVERHEAD}"
    assert STREAM_ID_MAX == StreamDataMessage.STREAM_ID_MAX, \
        f"STREAM_ID_MAX: {STREAM_ID_MAX} != {StreamDataMessage.STREAM_ID_MAX}"
    assert MAX_CHUNK_LEN == RawChannelWriter.MAX_CHUNK_LEN, \
        f"MAX_CHUNK_LEN: {MAX_CHUNK_LEN} != {RawChannelWriter.MAX_CHUNK_LEN}"
    assert COMPRESSION_TRIES == RawChannelWriter.COMPRESSION_TRIES, \
        f"COMPRESSION_TRIES: {COMPRESSION_TRIES} != {RawChannelWriter.COMPRESSION_TRIES}"
    assert SMT_STREAM_DATA == 0xFF00

    print("  [OK] All library constants verified")


# ============================================================
# Main
# ============================================================

def main():
    print("Extracting buffer protocol transfer test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    print("Extracting constants...")
    constants = extract_constants()

    print("Extracting small transfer vectors...")
    small_vectors = extract_small_transfer_vectors()
    print(f"  Extracted {len(small_vectors)} small transfer vectors")

    print("Extracting large transfer vectors...")
    large_vectors = extract_large_transfer_vectors()
    print(f"  Extracted {len(large_vectors)} large transfer vectors")

    print("Extracting compression vectors...")
    compression_vectors = extract_compression_vectors()
    print(f"  Extracted {len(compression_vectors)} compression vectors")

    print("Extracting EOF vectors...")
    eof_vectors = extract_eof_vectors()
    print(f"  Extracted {len(eof_vectors)} EOF vectors")

    print("Extracting bidirectional vectors...")
    bidir_vectors = extract_bidirectional_vectors()
    print(f"  Extracted {len(bidir_vectors)} bidirectional vectors")

    print("Extracting reassembly vectors...")
    reassembly_vectors = extract_reassembly_vectors()
    print(f"  Extracted {len(reassembly_vectors)} reassembly vectors")

    output = {
        "description": "Reticulum v1.1.3 - buffer protocol transfer test vectors",
        "source": "RNS/Buffer.py, RNS/Channel.py",
        "constants": constants,
        "small_transfer_vectors": small_vectors,
        "large_transfer_vectors": large_vectors,
        "compression_vectors": compression_vectors,
        "eof_vectors": eof_vectors,
        "bidirectional_vectors": bidir_vectors,
        "reassembly_vectors": reassembly_vectors,
    }

    verify(output)

    total_vectors = (len(small_vectors) + len(large_vectors) + len(compression_vectors) +
                     len(eof_vectors) + len(bidir_vectors) + len(reassembly_vectors))
    print(f"\nTotal: {total_vectors} vectors across 6 categories")

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
