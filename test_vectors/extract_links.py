#!/usr/bin/env python3
"""
Extract link establishment test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Link/Transport objects) to avoid
Transport init. Real RNS crypto primitives are used for key derivation,
signing, and encryption.

Covers:
  - Link constants and modes
  - Signalling byte encoding/decoding
  - Link ID computation from LINKREQUEST packets
  - Full 3-packet handshake (LINKREQUEST → LRPROOF → LRRTT)
  - RTT measurement packet construction
  - Keepalive interval calculation
  - MDU computation
  - Mode rejection (AES-128-CBC)
  - Teardown/keepalive packet construction
  - Link identify packet construction
  - State machine specification

Usage:
    python3 test_vectors/extract_links.py

Output:
    test_vectors/links.json
"""

import hashlib
import json
import math
import os
import struct
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "links.json")
KEYPAIRS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")

# --- Constants (reproduced to avoid Transport init) ---

# Packet types
HEADER_1 = 0x00
DATA = 0x00
LINKREQUEST = 0x02
PROOF = 0x03

# Transport types
BROADCAST = 0x00

# Destination types
SINGLE = 0x00
LINK = 0x03

# Flags
FLAG_SET = 0x01
FLAG_UNSET = 0x00

# Context types
NONE_CONTEXT = 0x00
KEEPALIVE = 0xFA
LINKIDENTIFY = 0xFB
LINKCLOSE = 0xFC
LRRTT = 0xFE
LRPROOF = 0xFF

# Size constants
MTU = 500
TRUNCATED_HASHLENGTH_BYTES = 16
HEADER_MINSIZE = 19
HEADER_MAXSIZE = 35
IFAC_MIN_SIZE = 1
TOKEN_OVERHEAD = 48
AES128_BLOCKSIZE = 16
KEYSIZE_BYTES = 64
SIGLENGTH_BYTES = 64

# Link constants
ECPUBSIZE = 64  # 32 X25519 + 32 Ed25519
LINK_KEYSIZE = 32
LINK_MTU_SIZE = 3
MTU_BYTEMASK = 0x1FFFFF
MODE_BYTEMASK = 0xE0


def load_keypairs():
    with open(KEYPAIRS_PATH, "r") as f:
        data = json.load(f)
    return data["keypairs"]


def load_identity(kp):
    import RNS
    identity = RNS.Identity(create_keys=False)
    identity.load_private_key(bytes.fromhex(kp["private_key"]))
    return identity


def pack_flags(header_type, context_flag, transport_type, dest_type, packet_type):
    return (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (dest_type << 2) | packet_type


def build_header_1(flags_byte, hops, dest_hash, context_byte):
    header = struct.pack("!B", flags_byte)
    header += struct.pack("!B", hops)
    header += dest_hash
    header += bytes([context_byte])
    return header


def compute_hashable_part(raw_packet):
    """Compute hashable_part matching Packet.get_hashable_part()."""
    flags = raw_packet[0]
    header_type = (flags & 0b01000000) >> 6
    hashable_part = bytes([flags & 0x0F])
    if header_type == 0x01:  # HEADER_2
        hashable_part += raw_packet[TRUNCATED_HASHLENGTH_BYTES + 2:]
    else:
        hashable_part += raw_packet[2:]
    return hashable_part


def truncated_hash(data):
    return hashlib.sha256(data).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def full_hash(data):
    return hashlib.sha256(data).digest()


def signalling_bytes(mtu, mode):
    """Reproduce Link.signalling_bytes()."""
    signalling_value = (mtu & MTU_BYTEMASK) + (((mode << 5) & MODE_BYTEMASK) << 16)
    return struct.pack(">I", signalling_value)[1:]


def decode_signalling_bytes(sb):
    """Decode MTU and mode from 3 signalling bytes."""
    val = (sb[0] << 16) + (sb[1] << 8) + sb[2]
    mtu = val & MTU_BYTEMASK
    mode = (sb[0] & MODE_BYTEMASK) >> 5
    return mtu, mode


def make_name_hash(app_name, *aspects):
    name = app_name
    for aspect in aspects:
        name += "." + aspect
    return hashlib.sha256(name.encode("utf-8")).digest()[:10]


def make_identity_hash(public_key_bytes):
    return hashlib.sha256(public_key_bytes).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_destination_hash(name_hash, identity_hash):
    return hashlib.sha256(name_hash + identity_hash).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def generate_ephemeral_keys(count=4):
    """Generate deterministic ephemeral key pairs for test vectors."""
    from RNS.Cryptography.X25519 import X25519PrivateKey
    from RNS.Cryptography.Ed25519 import Ed25519PrivateKey

    eph_x25519 = []
    eph_ed25519 = []

    for i in range(count):
        x_seed = hashlib.sha256(b"reticulum_test_link_ephemeral_x25519_" + str(i).encode()).digest()
        e_seed = hashlib.sha256(b"reticulum_test_link_ephemeral_ed25519_" + str(i).encode()).digest()

        x_prv = X25519PrivateKey.from_private_bytes(x_seed)
        x_pub = x_prv.public_key()

        e_prv = Ed25519PrivateKey.from_private_bytes(e_seed)
        e_pub = e_prv.public_key()

        eph_x25519.append({
            "private_bytes": x_seed,
            "public_bytes": x_pub.public_bytes(),
            "private_key": x_prv,
            "public_key": x_pub,
        })
        eph_ed25519.append({
            "private_bytes": e_seed,
            "public_bytes": e_pub.public_bytes(),
            "private_key": e_prv,
            "public_key": e_pub,
        })

    return eph_x25519, eph_ed25519


# ============================================================
# Extraction functions
# ============================================================

def extract_constants():
    """Extract all Link constants."""
    from RNS.Link import Link
    import RNS

    return {
        "ECPUBSIZE": Link.ECPUBSIZE,
        "KEYSIZE": Link.KEYSIZE,
        "LINK_MTU_SIZE": Link.LINK_MTU_SIZE,
        "MTU_BYTEMASK": Link.MTU_BYTEMASK,
        "MODE_BYTEMASK": Link.MODE_BYTEMASK,
        "modes": {
            "MODE_AES128_CBC": Link.MODE_AES128_CBC,
            "MODE_AES256_CBC": Link.MODE_AES256_CBC,
            "MODE_AES256_GCM": Link.MODE_AES256_GCM,
            "MODE_OTP_RESERVED": Link.MODE_OTP_RESERVED,
            "MODE_PQ_RESERVED_1": Link.MODE_PQ_RESERVED_1,
            "MODE_PQ_RESERVED_2": Link.MODE_PQ_RESERVED_2,
            "MODE_PQ_RESERVED_3": Link.MODE_PQ_RESERVED_3,
            "MODE_PQ_RESERVED_4": Link.MODE_PQ_RESERVED_4,
        },
        "ENABLED_MODES": Link.ENABLED_MODES,
        "MODE_DEFAULT": Link.MODE_DEFAULT,
        "MODE_DESCRIPTIONS": {str(k): v for k, v in Link.MODE_DESCRIPTIONS.items()},
        "states": {
            "PENDING": Link.PENDING,
            "HANDSHAKE": Link.HANDSHAKE,
            "ACTIVE": Link.ACTIVE,
            "STALE": Link.STALE,
            "CLOSED": Link.CLOSED,
        },
        "teardown_reasons": {
            "TIMEOUT": Link.TIMEOUT,
            "INITIATOR_CLOSED": Link.INITIATOR_CLOSED,
            "DESTINATION_CLOSED": Link.DESTINATION_CLOSED,
        },
        "resource_strategies": {
            "ACCEPT_NONE": Link.ACCEPT_NONE,
            "ACCEPT_APP": Link.ACCEPT_APP,
            "ACCEPT_ALL": Link.ACCEPT_ALL,
        },
        "keepalive": {
            "KEEPALIVE_MAX_RTT": Link.KEEPALIVE_MAX_RTT,
            "KEEPALIVE_TIMEOUT_FACTOR": Link.KEEPALIVE_TIMEOUT_FACTOR,
            "KEEPALIVE_MAX": Link.KEEPALIVE_MAX,
            "KEEPALIVE_MIN": Link.KEEPALIVE_MIN,
            "KEEPALIVE": Link.KEEPALIVE,
            "STALE_FACTOR": Link.STALE_FACTOR,
            "STALE_TIME": Link.STALE_TIME,
            "STALE_GRACE": Link.STALE_GRACE,
            "TRAFFIC_TIMEOUT_MIN_MS": Link.TRAFFIC_TIMEOUT_MIN_MS,
            "TRAFFIC_TIMEOUT_FACTOR": Link.TRAFFIC_TIMEOUT_FACTOR,
        },
        "MDU": Link.MDU,
        "MDU_derivation": f"floor((MTU({MTU}) - IFAC_MIN_SIZE({IFAC_MIN_SIZE}) - HEADER_MINSIZE({HEADER_MINSIZE}) - TOKEN_OVERHEAD({TOKEN_OVERHEAD})) / AES128_BLOCKSIZE({AES128_BLOCKSIZE})) * AES128_BLOCKSIZE({AES128_BLOCKSIZE}) - 1 = {Link.MDU}",
        "ESTABLISHMENT_TIMEOUT_PER_HOP": Link.ESTABLISHMENT_TIMEOUT_PER_HOP,
        "context_bytes": {
            "KEEPALIVE": f"{KEEPALIVE:#04x}",
            "LINKIDENTIFY": f"{LINKIDENTIFY:#04x}",
            "LINKCLOSE": f"{LINKCLOSE:#04x}",
            "LRRTT": f"{LRRTT:#04x}",
            "LRPROOF": f"{LRPROOF:#04x}",
        },
        "packet_flags": {
            "LINKREQUEST": f"{pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST):#04x}",
            "LINKREQUEST_description": "HEADER_1 | FLAG_UNSET | BROADCAST | SINGLE | LINKREQUEST",
            "LRPROOF": f"{pack_flags(HEADER_1, FLAG_SET, BROADCAST, LINK, PROOF):#04x}",
            "LRPROOF_description": "HEADER_1 | FLAG_SET | BROADCAST | LINK | PROOF",
        },
    }


def extract_signalling_vectors():
    """Signalling byte encode/decode vectors."""
    from RNS.Link import Link

    vectors = []
    test_cases = [
        (500, Link.MODE_AES256_CBC, "Default MTU with AES-256-CBC"),
        (1000, Link.MODE_AES256_CBC, "1000-byte MTU with AES-256-CBC"),
        (1500, Link.MODE_AES256_CBC, "1500-byte MTU with AES-256-CBC"),
        (2097151, Link.MODE_AES256_CBC, "Max 21-bit MTU (2097151) with AES-256-CBC"),
        (0, Link.MODE_AES256_CBC, "Zero MTU with AES-256-CBC"),
        (500, Link.MODE_AES256_CBC, "500-byte MTU (standard)"),
    ]

    for mtu_val, mode, desc in test_cases:
        sb = signalling_bytes(mtu_val, mode)
        decoded_mtu, decoded_mode = decode_signalling_bytes(sb)

        # Also verify against Link.signalling_bytes
        lib_sb = Link.signalling_bytes(mtu_val, mode)
        assert sb == lib_sb, f"signalling_bytes mismatch for MTU={mtu_val}"

        vectors.append({
            "description": desc,
            "input_mtu": mtu_val,
            "input_mode": mode,
            "input_mode_name": Link.MODE_DESCRIPTIONS.get(mode, "unknown"),
            "signalling_bytes": sb.hex(),
            "decoded_mtu": decoded_mtu,
            "decoded_mode": decoded_mode,
            "round_trip_match": decoded_mtu == mtu_val and decoded_mode == mode,
            "formula": f"signalling_value = ({mtu_val} & 0x1FFFFF) + ((({mode}<<5) & 0xE0) << 16) = {(mtu_val & MTU_BYTEMASK) + (((mode << 5) & MODE_BYTEMASK) << 16)}",
        })

    return vectors


def extract_link_id_vectors(keypairs, eph_x25519, eph_ed25519):
    """Link ID computation from LINKREQUEST packets."""
    vectors = []

    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)

    # Vector 1: With signalling bytes
    kp = keypairs[0]
    identity_hash = bytes.fromhex(kp["identity_hash"])
    dest_hash = make_destination_hash(name_hash, identity_hash)

    eph_x_pub = eph_x25519[0]["public_bytes"]
    eph_e_pub = eph_ed25519[0]["public_bytes"]
    sb = signalling_bytes(500, 1)  # MODE_AES256_CBC

    request_data = eph_x_pub + eph_e_pub + sb
    assert len(request_data) == ECPUBSIZE + LINK_MTU_SIZE

    flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST)
    raw = build_header_1(flags, 0, dest_hash, NONE_CONTEXT) + request_data

    hashable_part = compute_hashable_part(raw)
    # Strip signalling bytes from hashable_part for link_id computation
    diff = len(request_data) - ECPUBSIZE  # = 3
    hashable_stripped = hashable_part[:-diff]
    link_id = truncated_hash(hashable_stripped)

    vectors.append({
        "description": "Link ID from LINKREQUEST with signalling bytes (MTU=500, MODE_AES256_CBC)",
        "keypair_index": 0,
        "ephemeral_index": 0,
        "destination_hash": dest_hash.hex(),
        "request_data": request_data.hex(),
        "request_data_length": len(request_data),
        "signalling_bytes": sb.hex(),
        "flags_byte": f"{flags:02x}",
        "raw_packet": raw.hex(),
        "hashable_part": hashable_part.hex(),
        "hashable_part_length": len(hashable_part),
        "signalling_diff": diff,
        "hashable_stripped": hashable_stripped.hex(),
        "hashable_stripped_length": len(hashable_stripped),
        "link_id": link_id.hex(),
        "algorithm": "link_id = SHA256(hashable_part_stripped)[:16]; hashable_part_stripped = hashable_part[:-diff] where diff = len(data) - ECPUBSIZE",
    })

    # Vector 2: Without signalling bytes (legacy)
    request_data_legacy = eph_x_pub + eph_e_pub
    assert len(request_data_legacy) == ECPUBSIZE

    raw_legacy = build_header_1(flags, 0, dest_hash, NONE_CONTEXT) + request_data_legacy
    hashable_legacy = compute_hashable_part(raw_legacy)
    # No stripping needed: data length == ECPUBSIZE
    link_id_legacy = truncated_hash(hashable_legacy)

    vectors.append({
        "description": "Link ID from LINKREQUEST without signalling bytes (legacy)",
        "keypair_index": 0,
        "ephemeral_index": 0,
        "destination_hash": dest_hash.hex(),
        "request_data": request_data_legacy.hex(),
        "request_data_length": len(request_data_legacy),
        "flags_byte": f"{flags:02x}",
        "raw_packet": raw_legacy.hex(),
        "hashable_part": hashable_legacy.hex(),
        "hashable_part_length": len(hashable_legacy),
        "signalling_diff": 0,
        "link_id": link_id_legacy.hex(),
        "algorithm": "link_id = SHA256(hashable_part)[:16]; no stripping because len(data) == ECPUBSIZE",
    })

    # Vector 3: Same ephemeral keys, different MTU → same link_id
    sb_1000 = signalling_bytes(1000, 1)
    request_data_1000 = eph_x_pub + eph_e_pub + sb_1000
    raw_1000 = build_header_1(flags, 0, dest_hash, NONE_CONTEXT) + request_data_1000
    hashable_1000 = compute_hashable_part(raw_1000)
    diff_1000 = len(request_data_1000) - ECPUBSIZE
    hashable_stripped_1000 = hashable_1000[:-diff_1000]
    link_id_1000 = truncated_hash(hashable_stripped_1000)

    # The link IDs should match because signalling bytes are stripped
    assert link_id == link_id_1000, "Link IDs should match regardless of signalling bytes"

    vectors.append({
        "description": "Same ephemeral keys + different MTU signalling → same link_id (signalling stripped)",
        "link_id_mtu_500": link_id.hex(),
        "link_id_mtu_1000": link_id_1000.hex(),
        "link_id_legacy": link_id_legacy.hex(),
        "all_match": link_id == link_id_1000 == link_id_legacy,
        "note": "link_id is computed from hashable_part with signalling bytes stripped, so MTU value does not affect link_id",
    })

    return vectors


def extract_handshake_vectors(keypairs, eph_x25519, eph_ed25519):
    """Full 3-packet handshake vectors."""
    import RNS
    from RNS.Cryptography import hkdf
    from RNS.Cryptography.Token import Token as TokenClass
    from RNS.Cryptography import HMAC, PKCS7, AES
    from RNS.Cryptography.AES import AES_256_CBC
    import RNS.vendor.umsgpack as umsgpack

    vectors = []

    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)

    scenarios = [
        {
            "description": "Keypair 0→1, MTU=500, MODE_AES256_CBC (default)",
            "initiator_kp_idx": 0,
            "responder_kp_idx": 1,
            "initiator_eph_idx": 0,
            "responder_eph_idx": 1,
            "mtu": 500,
            "mode": 1,  # MODE_AES256_CBC
            "use_signalling": True,
        },
        {
            "description": "Keypair 1→0, MTU=500, MODE_AES256_CBC (reverse direction)",
            "initiator_kp_idx": 1,
            "responder_kp_idx": 0,
            "initiator_eph_idx": 1,
            "responder_eph_idx": 0,
            "mtu": 500,
            "mode": 1,
            "use_signalling": True,
        },
        {
            "description": "Keypair 2→3, MTU=1000, MODE_AES256_CBC (non-default MTU)",
            "initiator_kp_idx": 2,
            "responder_kp_idx": 3,
            "initiator_eph_idx": 2,
            "responder_eph_idx": 3,
            "mtu": 1000,
            "mode": 1,
            "use_signalling": True,
        },
        {
            "description": "Keypair 0→2, no signalling bytes (legacy)",
            "initiator_kp_idx": 0,
            "responder_kp_idx": 2,
            "initiator_eph_idx": 0,
            "responder_eph_idx": 2,
            "mtu": 500,
            "mode": 1,
            "use_signalling": False,
        },
    ]

    for scenario in scenarios:
        init_kp = keypairs[scenario["initiator_kp_idx"]]
        resp_kp = keypairs[scenario["responder_kp_idx"]]
        init_eph_x = eph_x25519[scenario["initiator_eph_idx"]]
        init_eph_e = eph_ed25519[scenario["initiator_eph_idx"]]
        resp_eph_x = eph_x25519[scenario["responder_eph_idx"]]

        resp_identity = load_identity(resp_kp)

        # Responder destination
        resp_identity_hash = bytes.fromhex(resp_kp["identity_hash"])
        resp_dest_hash = make_destination_hash(name_hash, resp_identity_hash)

        mtu_val = scenario["mtu"]
        mode = scenario["mode"]

        # ============================================================
        # Step 1: LINKREQUEST (initiator → responder)
        # ============================================================
        init_x_pub = init_eph_x["public_bytes"]
        init_e_pub = init_eph_e["public_bytes"]

        if scenario["use_signalling"]:
            sb = signalling_bytes(mtu_val, mode)
            request_data = init_x_pub + init_e_pub + sb
        else:
            sb = b""
            request_data = init_x_pub + init_e_pub

        lr_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST)
        lr_raw = build_header_1(lr_flags, 0, resp_dest_hash, NONE_CONTEXT) + request_data

        # Compute link_id
        hashable_part = compute_hashable_part(lr_raw)
        if len(request_data) > ECPUBSIZE:
            diff = len(request_data) - ECPUBSIZE
            hashable_stripped = hashable_part[:-diff]
        else:
            diff = 0
            hashable_stripped = hashable_part
        link_id = truncated_hash(hashable_stripped)

        # ============================================================
        # Step 2: LRPROOF (responder → initiator)
        # ============================================================
        # Responder ECDH: shared_key = X25519(responder_eph_prv, initiator_eph_pub)
        resp_x_prv = resp_eph_x["private_key"]
        resp_x_pub_bytes = resp_eph_x["public_bytes"]
        shared_key = resp_x_prv.exchange(init_eph_x["public_key"])

        # For AES-256-CBC mode, derived key length = 64
        if mode == 1:  # MODE_AES256_CBC
            derived_key_length = 64
        else:
            derived_key_length = 32

        derived_key = hkdf(
            length=derived_key_length,
            derive_from=shared_key,
            salt=link_id,
            context=None,
        )

        signing_key = derived_key[:32]
        encryption_key = derived_key[32:]

        # Responder signs: signed_data = link_id + resp_eph_x_pub + resp_identity_ed25519_pub + signalling
        resp_sig_pub_bytes = bytes.fromhex(resp_kp["public_key"])[32:]  # Ed25519 pub

        if scenario["use_signalling"]:
            resp_sb = signalling_bytes(mtu_val, mode)
        else:
            resp_sb = b""

        signed_data = link_id + resp_x_pub_bytes + resp_sig_pub_bytes + resp_sb
        signature = resp_identity.sign(signed_data)

        proof_data = signature + resp_x_pub_bytes + resp_sb

        # LRPROOF flags: HEADER_1 | FLAG_SET | BROADCAST | LINK | PROOF
        lp_flags = pack_flags(HEADER_1, FLAG_SET, BROADCAST, LINK, PROOF)
        # For LRPROOF, destination in header = link_id, context = LRPROOF (0xFF)
        lp_raw = build_header_1(lp_flags, 0, link_id, LRPROOF) + proof_data

        # ============================================================
        # Step 3: Verify initiator computes same session keys
        # ============================================================
        init_x_prv = init_eph_x["private_key"]
        shared_key_initiator = init_x_prv.exchange(resp_eph_x["public_key"])
        assert shared_key == shared_key_initiator, "ECDH shared keys must be symmetric"

        derived_key_initiator = hkdf(
            length=derived_key_length,
            derive_from=shared_key_initiator,
            salt=link_id,
            context=None,
        )
        assert derived_key == derived_key_initiator, "Derived keys must match"

        # Verify signature
        assert resp_identity.validate(signature, signed_data), "Signature validation failed"

        # ============================================================
        # Step 4: LRRTT packet (initiator → responder)
        # ============================================================
        # Use a fixed RTT value for deterministic output
        fixed_rtt = 0.125
        rtt_packed = umsgpack.packb(fixed_rtt)

        # Encrypt with Token using fixed IV for determinism
        fixed_iv = hashlib.sha256(b"reticulum_test_link_rtt_iv_" + str(scenario["initiator_eph_idx"]).encode()).digest()[:16]

        padded_rtt = PKCS7.pad(rtt_packed)
        rtt_ciphertext = AES_256_CBC.encrypt(plaintext=padded_rtt, key=encryption_key, iv=fixed_iv)
        rtt_signed_parts = fixed_iv + rtt_ciphertext
        rtt_hmac = HMAC.new(signing_key, rtt_signed_parts).digest()
        rtt_token = rtt_signed_parts + rtt_hmac

        # Verify Token can decrypt
        token_obj = TokenClass(key=derived_key)
        decrypted_rtt = token_obj.decrypt(rtt_token)
        assert decrypted_rtt == rtt_packed, "RTT token round-trip failed"

        # Build vector
        vec = {
            "description": scenario["description"],
            "initiator_keypair_index": scenario["initiator_kp_idx"],
            "responder_keypair_index": scenario["responder_kp_idx"],
            "initiator_ephemeral_index": scenario["initiator_eph_idx"],
            "responder_ephemeral_index": scenario["responder_eph_idx"],
            "mtu": mtu_val,
            "mode": mode,
            "mode_name": "AES_256_CBC",
            "use_signalling": scenario["use_signalling"],

            "step_1_linkrequest": {
                "initiator_eph_x25519_public": init_x_pub.hex(),
                "initiator_eph_ed25519_public": init_e_pub.hex(),
                "signalling_bytes": sb.hex() if sb else None,
                "request_data": request_data.hex(),
                "request_data_length": len(request_data),
                "responder_destination_hash": resp_dest_hash.hex(),
                "flags_byte": f"{lr_flags:02x}",
                "context_byte": f"{NONE_CONTEXT:02x}",
                "raw_packet": lr_raw.hex(),
                "raw_packet_length": len(lr_raw),
                "hashable_part": hashable_part.hex(),
                "signalling_diff": diff,
                "hashable_stripped": hashable_stripped.hex(),
                "link_id": link_id.hex(),
            },

            "step_2_lrproof": {
                "responder_eph_x25519_public": resp_x_pub_bytes.hex(),
                "responder_identity_ed25519_public": resp_sig_pub_bytes.hex(),
                "shared_key": shared_key.hex(),
                "shared_key_length": len(shared_key),
                "hkdf_salt": link_id.hex(),
                "hkdf_context": None,
                "hkdf_length": derived_key_length,
                "derived_key": derived_key.hex(),
                "signing_key": signing_key.hex(),
                "encryption_key": encryption_key.hex(),
                "signalling_bytes": resp_sb.hex() if resp_sb else None,
                "signed_data": signed_data.hex(),
                "signed_data_layout": "link_id(16) + responder_eph_x25519_pub(32) + responder_identity_ed25519_pub(32)" + (" + signalling(3)" if resp_sb else ""),
                "signature": signature.hex(),
                "proof_data": proof_data.hex(),
                "proof_data_layout": "signature(64) + responder_eph_x25519_pub(32)" + (" + signalling(3)" if resp_sb else ""),
                "proof_data_length": len(proof_data),
                "flags_byte": f"{lp_flags:02x}",
                "context_byte": f"{LRPROOF:02x}",
                "header_destination": link_id.hex(),
                "header_destination_note": "LRPROOF uses link_id as destination in header, not destination hash",
                "raw_packet": lp_raw.hex(),
                "raw_packet_length": len(lp_raw),
            },

            "step_3_verify": {
                "initiator_shared_key": shared_key_initiator.hex(),
                "ecdh_symmetric": shared_key == shared_key_initiator,
                "initiator_derived_key": derived_key_initiator.hex(),
                "derived_keys_match": derived_key == derived_key_initiator,
                "signature_valid": True,
            },

            "step_4_lrrtt": {
                "rtt_value": fixed_rtt,
                "rtt_msgpack": rtt_packed.hex(),
                "fixed_iv": fixed_iv.hex(),
                "padded_plaintext": padded_rtt.hex(),
                "ciphertext": rtt_ciphertext.hex(),
                "hmac": rtt_hmac.hex(),
                "encrypted_rtt_token": rtt_token.hex(),
                "encrypted_rtt_token_length": len(rtt_token),
                "context_byte": f"{LRRTT:02x}",
                "note": "Encrypted with link's derived_key using Token (modified Fernet). IV is fixed for determinism.",
            },
        }

        vectors.append(vec)

    return vectors


def extract_rtt_vectors():
    """RTT msgpack encoding vectors."""
    import RNS.vendor.umsgpack as umsgpack

    vectors = []
    rtt_values = [0.001, 0.05, 0.125, 0.5, 1.0, 1.75]

    for rtt in rtt_values:
        packed = umsgpack.packb(rtt)
        unpacked = umsgpack.unpackb(packed)

        vectors.append({
            "description": f"RTT value {rtt}",
            "rtt_float": rtt,
            "msgpack_bytes": packed.hex(),
            "msgpack_length": len(packed),
            "round_trip_value": unpacked,
            "round_trip_match": abs(unpacked - rtt) < 1e-15,
        })

    return vectors


def extract_keepalive_vectors():
    """Keepalive interval calculation vectors."""
    from RNS.Link import Link

    vectors = []
    rtt_values = [0.001, 0.01, 0.1, 0.5, 1.0, 1.75, 2.0, 5.0]

    for rtt in rtt_values:
        keepalive = max(min(rtt * (Link.KEEPALIVE_MAX / Link.KEEPALIVE_MAX_RTT), Link.KEEPALIVE_MAX), Link.KEEPALIVE_MIN)
        stale_time = keepalive * Link.STALE_FACTOR

        vectors.append({
            "description": f"Keepalive for RTT={rtt}s",
            "rtt": rtt,
            "keepalive": keepalive,
            "stale_time": stale_time,
            "formula": f"keepalive = max(min({rtt} * ({Link.KEEPALIVE_MAX} / {Link.KEEPALIVE_MAX_RTT}), {Link.KEEPALIVE_MAX}), {Link.KEEPALIVE_MIN})",
            "formula_simplified": f"keepalive = max(min({rtt} * {Link.KEEPALIVE_MAX / Link.KEEPALIVE_MAX_RTT:.6f}, {Link.KEEPALIVE_MAX}), {Link.KEEPALIVE_MIN})",
            "stale_formula": f"stale_time = {keepalive} * {Link.STALE_FACTOR}",
        })

    return vectors


def extract_mdu_vectors():
    """MDU computation for different MTU values."""
    import RNS

    vectors = []
    mtu_values = [500, 1000, 1500]

    for mtu_val in mtu_values:
        mdu = math.floor((mtu_val - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1

        vectors.append({
            "description": f"MDU for MTU={mtu_val}",
            "mtu": mtu_val,
            "ifac_min_size": IFAC_MIN_SIZE,
            "header_minsize": HEADER_MINSIZE,
            "token_overhead": TOKEN_OVERHEAD,
            "aes128_blocksize": AES128_BLOCKSIZE,
            "mdu": mdu,
            "formula": f"floor(({mtu_val} - {IFAC_MIN_SIZE} - {HEADER_MINSIZE} - {TOKEN_OVERHEAD}) / {AES128_BLOCKSIZE}) * {AES128_BLOCKSIZE} - 1",
            "intermediate": f"floor({mtu_val - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD} / {AES128_BLOCKSIZE}) * {AES128_BLOCKSIZE} - 1 = floor({(mtu_val - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE}) * {AES128_BLOCKSIZE} - 1 = {mdu}",
        })

    return vectors


def extract_mode_rejection_vectors():
    """Mode encoding vectors and AES-128-CBC rejection."""
    from RNS.Link import Link

    vectors = []

    # Show mode extraction for all mode values 0-7
    mode_encodings = []
    for mode_val in range(8):
        mode_byte = (mode_val << 5) & MODE_BYTEMASK
        mode_encodings.append({
            "mode_value": mode_val,
            "mode_name": Link.MODE_DESCRIPTIONS.get(mode_val, f"UNKNOWN_{mode_val}"),
            "mode_byte": f"{mode_byte:02x}",
            "enabled": mode_val in Link.ENABLED_MODES,
        })

    # Document AES-128-CBC rejection
    aes128_rejected = False
    try:
        Link.signalling_bytes(500, Link.MODE_AES128_CBC)
    except TypeError:
        aes128_rejected = True

    vectors.append({
        "description": "Mode encoding for all 8 mode values (3-bit field)",
        "mode_encodings": mode_encodings,
        "encoding_formula": "mode_byte = (mode << 5) & 0xE0",
        "extraction_formula": "mode = (byte >> 5) & 0x07",
    })

    vectors.append({
        "description": "AES-128-CBC (mode=0) rejection",
        "mode_value": Link.MODE_AES128_CBC,
        "mode_name": Link.MODE_DESCRIPTIONS[Link.MODE_AES128_CBC],
        "is_enabled": Link.MODE_AES128_CBC in Link.ENABLED_MODES,
        "signalling_bytes_raises_TypeError": aes128_rejected,
        "note": "signalling_bytes() raises TypeError for modes not in ENABLED_MODES. AES-128-CBC is defined but not enabled.",
    })

    # Show what signalling bytes would look like if AES-128-CBC were encoded
    # (manually compute without the check)
    mode_0_val = (500 & MTU_BYTEMASK) + (((0 << 5) & MODE_BYTEMASK) << 16)
    mode_0_bytes = struct.pack(">I", mode_0_val)[1:]
    decoded_mtu, decoded_mode = decode_signalling_bytes(mode_0_bytes)

    vectors.append({
        "description": "Hypothetical AES-128-CBC signalling encoding (mode=0, for testing decoders)",
        "mode_value": 0,
        "mtu": 500,
        "hypothetical_signalling_bytes": mode_0_bytes.hex(),
        "decoded_mtu": decoded_mtu,
        "decoded_mode": decoded_mode,
        "note": "This encoding is never produced by the reference implementation but decoders should be able to parse it",
    })

    return vectors


def extract_teardown_vectors(keypairs, eph_x25519, eph_ed25519):
    """Teardown and keepalive packet construction using handshake vector #1's keys."""
    from RNS.Cryptography import HMAC, PKCS7
    from RNS.Cryptography.AES import AES_256_CBC
    from RNS.Cryptography import hkdf

    # Recreate handshake #1's derived key
    init_eph_x = eph_x25519[0]
    resp_eph_x = eph_x25519[1]

    kp_init = keypairs[0]
    kp_resp = keypairs[1]
    resp_identity_hash = bytes.fromhex(kp_resp["identity_hash"])
    name_hash = make_name_hash("rns_unit_tests", "link", "establish")
    resp_dest_hash = make_destination_hash(name_hash, resp_identity_hash)

    init_x_pub = init_eph_x["public_bytes"]
    init_e_pub = eph_ed25519[0]["public_bytes"]
    sb = signalling_bytes(500, 1)
    request_data = init_x_pub + init_e_pub + sb

    lr_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST)
    lr_raw = build_header_1(lr_flags, 0, resp_dest_hash, NONE_CONTEXT) + request_data
    hashable_part = compute_hashable_part(lr_raw)
    diff = len(request_data) - ECPUBSIZE
    hashable_stripped = hashable_part[:-diff]
    link_id = truncated_hash(hashable_stripped)

    shared_key = resp_eph_x["private_key"].exchange(init_eph_x["public_key"])
    derived_key = hkdf(length=64, derive_from=shared_key, salt=link_id, context=None)
    signing_key = derived_key[:32]
    encryption_key = derived_key[32:]

    vectors = []

    # Fixed IVs for determinism
    keepalive_req_iv = hashlib.sha256(b"reticulum_test_keepalive_request_iv").digest()[:16]
    keepalive_resp_iv = hashlib.sha256(b"reticulum_test_keepalive_response_iv").digest()[:16]
    teardown_iv = hashlib.sha256(b"reticulum_test_teardown_iv").digest()[:16]

    def make_token(plaintext, iv):
        padded = PKCS7.pad(plaintext)
        ct = AES_256_CBC.encrypt(plaintext=padded, key=encryption_key, iv=iv)
        signed = iv + ct
        hmac_val = HMAC.new(signing_key, signed).digest()
        return signed + hmac_val

    # Keepalive request: initiator sends 0xFF
    ka_req_plaintext = bytes([0xFF])
    ka_req_token = make_token(ka_req_plaintext, keepalive_req_iv)

    vectors.append({
        "description": "Keepalive request (initiator → responder)",
        "handshake_reference": "handshake_vectors[0]",
        "link_id": link_id.hex(),
        "plaintext": ka_req_plaintext.hex(),
        "plaintext_note": "0xFF = keepalive request marker",
        "fixed_iv": keepalive_req_iv.hex(),
        "encrypted_token": ka_req_token.hex(),
        "encrypted_token_length": len(ka_req_token),
        "context_byte": f"{KEEPALIVE:02x}",
        "context_name": "KEEPALIVE",
    })

    # Keepalive response: responder sends 0xFE
    ka_resp_plaintext = bytes([0xFE])
    ka_resp_token = make_token(ka_resp_plaintext, keepalive_resp_iv)

    vectors.append({
        "description": "Keepalive response (responder → initiator)",
        "handshake_reference": "handshake_vectors[0]",
        "link_id": link_id.hex(),
        "plaintext": ka_resp_plaintext.hex(),
        "plaintext_note": "0xFE = keepalive response marker",
        "fixed_iv": keepalive_resp_iv.hex(),
        "encrypted_token": ka_resp_token.hex(),
        "encrypted_token_length": len(ka_resp_token),
        "context_byte": f"{KEEPALIVE:02x}",
        "context_name": "KEEPALIVE",
    })

    # Teardown: encrypt link_id
    teardown_token = make_token(link_id, teardown_iv)

    vectors.append({
        "description": "Teardown packet (LINKCLOSE)",
        "handshake_reference": "handshake_vectors[0]",
        "link_id": link_id.hex(),
        "plaintext": link_id.hex(),
        "plaintext_note": "Teardown plaintext is the link_id itself",
        "fixed_iv": teardown_iv.hex(),
        "encrypted_token": teardown_token.hex(),
        "encrypted_token_length": len(teardown_token),
        "context_byte": f"{LINKCLOSE:02x}",
        "context_name": "LINKCLOSE",
    })

    return vectors


def extract_identify_vectors(keypairs, eph_x25519, eph_ed25519):
    """Link identify packet construction using handshake vector #1's keys."""
    from RNS.Cryptography import HMAC, PKCS7
    from RNS.Cryptography.AES import AES_256_CBC
    from RNS.Cryptography import hkdf

    # Recreate handshake #1's derived key
    init_eph_x = eph_x25519[0]
    resp_eph_x = eph_x25519[1]

    kp_init = keypairs[0]
    kp_resp = keypairs[1]
    resp_identity_hash = bytes.fromhex(kp_resp["identity_hash"])
    name_hash = make_name_hash("rns_unit_tests", "link", "establish")
    resp_dest_hash = make_destination_hash(name_hash, resp_identity_hash)

    init_x_pub = init_eph_x["public_bytes"]
    init_e_pub = eph_ed25519[0]["public_bytes"]
    sb = signalling_bytes(500, 1)
    request_data = init_x_pub + init_e_pub + sb

    lr_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST)
    lr_raw = build_header_1(lr_flags, 0, resp_dest_hash, NONE_CONTEXT) + request_data
    hashable_part = compute_hashable_part(lr_raw)
    diff = len(request_data) - ECPUBSIZE
    hashable_stripped = hashable_part[:-diff]
    link_id = truncated_hash(hashable_stripped)

    shared_key = resp_eph_x["private_key"].exchange(init_eph_x["public_key"])
    derived_key = hkdf(length=64, derive_from=shared_key, salt=link_id, context=None)
    signing_key = derived_key[:32]
    encryption_key = derived_key[32:]

    # Identify: initiator reveals identity over encrypted link
    init_identity = load_identity(kp_init)
    init_public_key = init_identity.get_public_key()

    signed_data = link_id + init_public_key
    signature = init_identity.sign(signed_data)
    proof_data = init_public_key + signature

    assert len(proof_data) == KEYSIZE_BYTES + SIGLENGTH_BYTES  # 128 bytes

    # Encrypt with Token using fixed IV
    identify_iv = hashlib.sha256(b"reticulum_test_identify_iv").digest()[:16]
    padded = PKCS7.pad(proof_data)
    ct = AES_256_CBC.encrypt(plaintext=padded, key=encryption_key, iv=identify_iv)
    signed_parts = identify_iv + ct
    hmac_val = HMAC.new(signing_key, signed_parts).digest()
    identify_token = signed_parts + hmac_val

    vectors = [{
        "description": "Link identify packet (initiator reveals identity)",
        "handshake_reference": "handshake_vectors[0]",
        "link_id": link_id.hex(),
        "initiator_keypair_index": 0,
        "initiator_public_key": init_public_key.hex(),
        "signed_data": signed_data.hex(),
        "signed_data_layout": "link_id(16) + identity_public_key(64)",
        "signature": signature.hex(),
        "proof_data": proof_data.hex(),
        "proof_data_layout": "public_key(64) + signature(64) = 128 bytes",
        "proof_data_length": len(proof_data),
        "fixed_iv": identify_iv.hex(),
        "encrypted_token": identify_token.hex(),
        "encrypted_token_length": len(identify_token),
        "context_byte": f"{LINKIDENTIFY:02x}",
        "context_name": "LINKIDENTIFY",
    }]

    return vectors


def extract_state_machine_spec():
    """State machine specification."""
    return {
        "states": {
            "PENDING": {"value": 0x00, "description": "Link request sent/received, awaiting proof"},
            "HANDSHAKE": {"value": 0x01, "description": "Handshake in progress (ECDH computed)"},
            "ACTIVE": {"value": 0x02, "description": "Link established and active"},
            "STALE": {"value": 0x03, "description": "No traffic received within stale_time"},
            "CLOSED": {"value": 0x04, "description": "Link torn down"},
        },
        "teardown_reasons": {
            "TIMEOUT": {"value": 0x01, "description": "No response within establishment timeout or keepalive timeout"},
            "INITIATOR_CLOSED": {"value": 0x02, "description": "Initiator called teardown()"},
            "DESTINATION_CLOSED": {"value": 0x03, "description": "Destination/responder called teardown() or received teardown packet"},
        },
        "valid_transitions": [
            {"from": "PENDING", "to": "HANDSHAKE", "condition": "ECDH exchange completed (prv.exchange(peer_pub))"},
            {"from": "PENDING", "to": "CLOSED", "condition": "Establishment timeout"},
            {"from": "HANDSHAKE", "to": "ACTIVE", "condition": "Link proof validated (initiator) or RTT packet received (responder)"},
            {"from": "HANDSHAKE", "to": "CLOSED", "condition": "Establishment timeout or proof validation failure"},
            {"from": "ACTIVE", "to": "STALE", "condition": "No inbound traffic for stale_time seconds"},
            {"from": "ACTIVE", "to": "CLOSED", "condition": "teardown() called"},
            {"from": "STALE", "to": "ACTIVE", "condition": "Traffic received while stale"},
            {"from": "STALE", "to": "CLOSED", "condition": "Teardown packet sent after entering STALE (immediate in watchdog)"},
        ],
        "notes": [
            "CLOSED is a terminal state; keys are purged",
            "STALE → ACTIVE recovery happens when any packet is received on the link",
            "In the current implementation, STALE immediately transitions to CLOSED in the watchdog",
            "The initiator creates ephemeral Ed25519 keys; the responder uses its identity Ed25519 key for signing",
        ],
    }


def verify(output, keypairs, eph_x25519, eph_ed25519):
    """Cross-check all vectors."""
    from RNS.Cryptography import hkdf
    from RNS.Cryptography.Token import Token as TokenClass
    import RNS

    print("  Verifying...")

    # 1. Verify signalling bytes round-trip
    for vec in output["signalling_bytes_vectors"]:
        sb = bytes.fromhex(vec["signalling_bytes"])
        mtu, mode = decode_signalling_bytes(sb)
        assert mtu == vec["decoded_mtu"], f"Signalling MTU mismatch: {vec['description']}"
        assert mode == vec["decoded_mode"], f"Signalling mode mismatch: {vec['description']}"
    print(f"    [OK] {len(output['signalling_bytes_vectors'])} signalling vectors verified")

    # 2. Verify link_id vectors
    for vec in output["link_id_vectors"]:
        if "raw_packet" in vec:
            raw = bytes.fromhex(vec["raw_packet"])
            hp = compute_hashable_part(raw)
            assert hp.hex() == vec["hashable_part"], f"Hashable part mismatch: {vec['description']}"
            if vec["signalling_diff"] > 0:
                stripped = hp[:-vec["signalling_diff"]]
            else:
                stripped = hp
            lid = truncated_hash(stripped)
            assert lid.hex() == vec["link_id"], f"Link ID mismatch: {vec['description']}"
    print(f"    [OK] {len(output['link_id_vectors'])} link_id vectors verified")

    # 3. Verify handshake vectors
    for vec in output["handshake_vectors"]:
        s2 = vec["step_2_lrproof"]
        s3 = vec["step_3_verify"]

        # ECDH symmetry
        assert s3["ecdh_symmetric"], f"ECDH not symmetric: {vec['description']}"
        assert s3["derived_keys_match"], f"Derived keys don't match: {vec['description']}"

        # Signature validation
        resp_kp_idx = vec["responder_keypair_index"]
        resp_identity = load_identity(keypairs[resp_kp_idx])
        signed_data = bytes.fromhex(s2["signed_data"])
        signature = bytes.fromhex(s2["signature"])
        assert resp_identity.validate(signature, signed_data), f"Signature invalid: {vec['description']}"

        # Token round-trip for LRRTT
        s4 = vec["step_4_lrrtt"]
        derived_key = bytes.fromhex(s2["derived_key"])
        token_obj = TokenClass(key=derived_key)
        decrypted = token_obj.decrypt(bytes.fromhex(s4["encrypted_rtt_token"]))
        assert decrypted == bytes.fromhex(s4["rtt_msgpack"]), f"RTT token decrypt failed: {vec['description']}"

    print(f"    [OK] {len(output['handshake_vectors'])} handshake vectors verified")

    # 4. Verify teardown vectors - Token round-trip
    for vec in output["teardown_vectors"]:
        # Get derived_key from handshake #1
        hs = output["handshake_vectors"][0]
        derived_key = bytes.fromhex(hs["step_2_lrproof"]["derived_key"])
        token_obj = TokenClass(key=derived_key)
        decrypted = token_obj.decrypt(bytes.fromhex(vec["encrypted_token"]))
        assert decrypted == bytes.fromhex(vec["plaintext"]), f"Teardown token decrypt failed: {vec['description']}"
    print(f"    [OK] {len(output['teardown_vectors'])} teardown vectors verified")

    # 5. Verify identify vectors - Token round-trip + signature
    for vec in output["identify_vectors"]:
        hs = output["handshake_vectors"][0]
        derived_key = bytes.fromhex(hs["step_2_lrproof"]["derived_key"])
        token_obj = TokenClass(key=derived_key)
        decrypted = token_obj.decrypt(bytes.fromhex(vec["encrypted_token"]))
        assert decrypted == bytes.fromhex(vec["proof_data"]), f"Identify token decrypt failed: {vec['description']}"

        # Verify identify signature
        proof_data = bytes.fromhex(vec["proof_data"])
        public_key = proof_data[:KEYSIZE_BYTES]
        signature = proof_data[KEYSIZE_BYTES:]
        signed_data = bytes.fromhex(vec["signed_data"])
        ident = RNS.Identity(create_keys=False)
        ident.load_public_key(public_key)
        assert ident.validate(signature, signed_data), f"Identify signature invalid: {vec['description']}"
    print(f"    [OK] {len(output['identify_vectors'])} identify vectors verified")

    # 6. Verify keepalive calculations
    from RNS.Link import Link
    for vec in output["keepalive_calculation_vectors"]:
        rtt = vec["rtt"]
        expected = max(min(rtt * (Link.KEEPALIVE_MAX / Link.KEEPALIVE_MAX_RTT), Link.KEEPALIVE_MAX), Link.KEEPALIVE_MIN)
        assert abs(vec["keepalive"] - expected) < 1e-10, f"Keepalive mismatch for RTT={rtt}"
    print(f"    [OK] {len(output['keepalive_calculation_vectors'])} keepalive vectors verified")

    # 7. Verify MDU calculations
    for vec in output["mdu_vectors"]:
        mtu_val = vec["mtu"]
        expected_mdu = math.floor((mtu_val - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1
        assert vec["mdu"] == expected_mdu, f"MDU mismatch for MTU={mtu_val}"
    print(f"    [OK] {len(output['mdu_vectors'])} MDU vectors verified")

    # 8. Cross-check HKDF with hkdf.json if it exists
    hkdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hkdf.json")
    if os.path.exists(hkdf_path):
        with open(hkdf_path) as f:
            hkdf_data = json.load(f)
        # Just verify our HKDF implementation matches the test vectors
        for hv in hkdf_data.get("hkdf_vectors", []):
            derive_from = bytes.fromhex(hv["derive_from"])
            salt = bytes.fromhex(hv["salt"]) if hv.get("salt") else None
            context = bytes.fromhex(hv["context"]) if hv.get("context") else None
            length = hv["length"]
            expected = bytes.fromhex(hv["derived_key"])
            result = hkdf(length=length, derive_from=derive_from, salt=salt, context=context)
            assert result == expected, f"HKDF cross-check failed"
        print(f"    [OK] HKDF cross-checked against hkdf.json")
    else:
        print("    [--] hkdf.json not found, skipping HKDF cross-check")

    # 9. JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("    [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify our local constants match the actual RNS library values."""
    import RNS
    from RNS.Link import Link

    assert MTU == RNS.Reticulum.MTU
    assert HEADER_MINSIZE == RNS.Reticulum.HEADER_MINSIZE
    assert HEADER_MAXSIZE == RNS.Reticulum.HEADER_MAXSIZE
    assert IFAC_MIN_SIZE == RNS.Reticulum.IFAC_MIN_SIZE
    assert TOKEN_OVERHEAD == RNS.Identity.TOKEN_OVERHEAD
    assert AES128_BLOCKSIZE == RNS.Identity.AES128_BLOCKSIZE
    assert TRUNCATED_HASHLENGTH_BYTES == RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
    assert KEYSIZE_BYTES == RNS.Identity.KEYSIZE // 8
    assert SIGLENGTH_BYTES == RNS.Identity.SIGLENGTH // 8

    assert ECPUBSIZE == Link.ECPUBSIZE
    assert LINK_KEYSIZE == Link.KEYSIZE
    assert LINK_MTU_SIZE == Link.LINK_MTU_SIZE
    assert MTU_BYTEMASK == Link.MTU_BYTEMASK
    assert MODE_BYTEMASK == Link.MODE_BYTEMASK

    print("  [OK] All library constants verified")


def main():
    print("Extracting link establishment test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    keypairs = load_keypairs()
    print(f"  Loaded {len(keypairs)} keypairs")

    print("Generating deterministic ephemeral keys...")
    eph_x25519, eph_ed25519 = generate_ephemeral_keys(4)
    print(f"  Generated {len(eph_x25519)} ephemeral X25519 + {len(eph_ed25519)} Ed25519 key pairs")

    # Build ephemeral key info for output
    ephemeral_keys = []
    for i in range(len(eph_x25519)):
        ephemeral_keys.append({
            "index": i,
            "x25519_seed": f"SHA256(b'reticulum_test_link_ephemeral_x25519_{i}')",
            "x25519_private": eph_x25519[i]["private_bytes"].hex(),
            "x25519_public": eph_x25519[i]["public_bytes"].hex(),
            "ed25519_seed": f"SHA256(b'reticulum_test_link_ephemeral_ed25519_{i}')",
            "ed25519_private": eph_ed25519[i]["private_bytes"].hex(),
            "ed25519_public": eph_ed25519[i]["public_bytes"].hex(),
        })

    print("Extracting constants...")
    constants = extract_constants()

    print("Extracting signalling byte vectors...")
    signalling_vecs = extract_signalling_vectors()
    print(f"  Extracted {len(signalling_vecs)} signalling vectors")

    print("Extracting link ID vectors...")
    link_id_vecs = extract_link_id_vectors(keypairs, eph_x25519, eph_ed25519)
    print(f"  Extracted {len(link_id_vecs)} link ID vectors")

    print("Extracting handshake vectors...")
    handshake_vecs = extract_handshake_vectors(keypairs, eph_x25519, eph_ed25519)
    print(f"  Extracted {len(handshake_vecs)} handshake vectors")

    print("Extracting RTT vectors...")
    rtt_vecs = extract_rtt_vectors()
    print(f"  Extracted {len(rtt_vecs)} RTT vectors")

    print("Extracting keepalive calculation vectors...")
    keepalive_vecs = extract_keepalive_vectors()
    print(f"  Extracted {len(keepalive_vecs)} keepalive vectors")

    print("Extracting MDU vectors...")
    mdu_vecs = extract_mdu_vectors()
    print(f"  Extracted {len(mdu_vecs)} MDU vectors")

    print("Extracting mode rejection vectors...")
    mode_vecs = extract_mode_rejection_vectors()
    print(f"  Extracted {len(mode_vecs)} mode rejection vectors")

    print("Extracting teardown vectors...")
    teardown_vecs = extract_teardown_vectors(keypairs, eph_x25519, eph_ed25519)
    print(f"  Extracted {len(teardown_vecs)} teardown vectors")

    print("Extracting identify vectors...")
    identify_vecs = extract_identify_vectors(keypairs, eph_x25519, eph_ed25519)
    print(f"  Extracted {len(identify_vecs)} identify vectors")

    print("Extracting state machine spec...")
    state_spec = extract_state_machine_spec()

    output = {
        "description": "Reticulum v1.1.3 - link establishment test vectors",
        "source": "RNS/Link.py, RNS/Packet.py",
        "constants": constants,
        "ephemeral_keys": ephemeral_keys,
        "signalling_bytes_vectors": signalling_vecs,
        "link_id_vectors": link_id_vecs,
        "handshake_vectors": handshake_vecs,
        "rtt_vectors": rtt_vecs,
        "keepalive_calculation_vectors": keepalive_vecs,
        "mdu_vectors": mdu_vecs,
        "mode_rejection_vectors": mode_vecs,
        "teardown_vectors": teardown_vecs,
        "identify_vectors": identify_vecs,
        "state_machine_spec": state_spec,
    }

    verify(output, keypairs, eph_x25519, eph_ed25519)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
