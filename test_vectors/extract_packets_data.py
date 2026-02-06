#!/usr/bin/env python3
"""
Extract data packet and proof test vectors from the Reticulum reference
implementation into a JSON file for consumption by alternative implementations.

All vectors are computed manually (no live Link/Transport/Packet objects) to
avoid Transport init. Real RNS crypto primitives are used for encryption,
signing, and verification.

Covers:
  - DATA packets encrypted with Token(derived_key) over a link
  - Packet hash computation from wire format
  - Explicit proof generation (packet_hash + Ed25519 signature = 96 bytes)
  - Proof validation with correct peer signing key
  - Invalid proof detection (tampered hash, tampered sig, wrong key)
  - Bidirectional data+proof (asymmetric signing keys per direction)
  - Proof strategy and receipt state constants

Usage:
    python3 test_vectors/extract_packets_data.py

Output:
    test_vectors/packets_data.json
"""

import hashlib
import json
import math
import os
import struct
import sys

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, repo_root)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packets_data.json")
KEYPAIRS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keypairs.json")
LINKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "links.json")

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
LRPROOF = 0xFF

# Size constants
MTU = 500
TRUNCATED_HASHLENGTH_BYTES = 16
HEADER_MINSIZE = 19
IFAC_MIN_SIZE = 1
TOKEN_OVERHEAD = 48
AES128_BLOCKSIZE = 16
KEYSIZE_BYTES = 64
SIGLENGTH_BYTES = 64
HASHLENGTH_BYTES = 32

# Link constants
ECPUBSIZE = 64
LINK_KEYSIZE = 32
LINK_MTU_SIZE = 3
MTU_BYTEMASK = 0x1FFFFF
MODE_BYTEMASK = 0xE0

# Link MDU for standard MTU=500
LINK_MDU = math.floor((MTU - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1

# Proof constants
EXPL_LENGTH = HASHLENGTH_BYTES + SIGLENGTH_BYTES  # 96
IMPL_LENGTH = SIGLENGTH_BYTES                      # 64

# Proof strategy constants (from Destination.py)
PROVE_NONE = 0x21
PROVE_APP = 0x22
PROVE_ALL = 0x23

# Receipt state constants (from PacketReceipt)
RECEIPT_FAILED = 0x00
RECEIPT_SENT = 0x01
RECEIPT_DELIVERED = 0x02
RECEIPT_CULLED = 0xFF

# Receipt timeout constants (from Link.py, Reticulum.py, Transport.py, Packet.py)
TRAFFIC_TIMEOUT_FACTOR = 6
TRAFFIC_TIMEOUT_MIN_MS = 5
DEFAULT_PER_HOP_TIMEOUT = 6
TIMEOUT_PER_HOP = DEFAULT_PER_HOP_TIMEOUT
MAX_RECEIPTS = 1024
PATHFINDER_M = 128


# --- Helper functions ---

def load_keypairs():
    with open(KEYPAIRS_PATH, "r") as f:
        data = json.load(f)
    return data["keypairs"]


def load_links_json():
    with open(LINKS_PATH, "r") as f:
        return json.load(f)


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


def make_name_hash(app_name, *aspects):
    name = app_name
    for aspect in aspects:
        name += "." + aspect
    return hashlib.sha256(name.encode("utf-8")).digest()[:10]


def make_identity_hash(public_key_bytes):
    return hashlib.sha256(public_key_bytes).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def make_destination_hash(name_hash, identity_hash):
    return hashlib.sha256(name_hash + identity_hash).digest()[:TRUNCATED_HASHLENGTH_BYTES]


def signalling_bytes(mtu, mode):
    signalling_value = (mtu & MTU_BYTEMASK) + (((mode << 5) & MODE_BYTEMASK) << 16)
    return struct.pack(">I", signalling_value)[1:]


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


def deterministic_burst_plaintext(index, length):
    """Generate deterministic plaintext for burst packet at given index.

    Uses SHA-256 expansion: seed = SHA256(b"reticulum_test_burst_plaintext_" + str(index)),
    then concatenates SHA256(seed + big-endian uint32 counter) chunks until length bytes.
    """
    seed = hashlib.sha256(b"reticulum_test_burst_plaintext_" + str(index).encode()).digest()
    result = b""
    counter = 0
    while len(result) < length:
        chunk = hashlib.sha256(seed + struct.pack(">I", counter)).digest()
        result += chunk
        counter += 1
    return result[:length]


def reconstruct_handshake_keys(keypairs, eph_x25519, eph_ed25519, scenario_idx=0):
    """Reconstruct link keys from handshake scenario 0 (keypair 0→1)."""
    from RNS.Cryptography import hkdf

    init_kp = keypairs[0]
    resp_kp = keypairs[1]
    init_eph_x = eph_x25519[0]
    init_eph_e = eph_ed25519[0]
    resp_eph_x = eph_x25519[1]

    # Responder destination
    app_name = "rns_unit_tests"
    aspects = ["link", "establish"]
    name_hash = make_name_hash(app_name, *aspects)
    resp_identity_hash = bytes.fromhex(resp_kp["identity_hash"])
    resp_dest_hash = make_destination_hash(name_hash, resp_identity_hash)

    # Build LINKREQUEST to compute link_id
    init_x_pub = init_eph_x["public_bytes"]
    init_e_pub = init_eph_e["public_bytes"]
    sb = signalling_bytes(500, 1)  # MODE_AES256_CBC
    request_data = init_x_pub + init_e_pub + sb

    lr_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, SINGLE, LINKREQUEST)
    lr_raw = build_header_1(lr_flags, 0, resp_dest_hash, NONE_CONTEXT) + request_data
    hashable_part = compute_hashable_part(lr_raw)
    diff = len(request_data) - ECPUBSIZE
    hashable_stripped = hashable_part[:-diff]
    link_id = truncated_hash(hashable_stripped)

    # ECDH + HKDF
    shared_key = resp_eph_x["private_key"].exchange(init_eph_x["public_key"])
    derived_key = hkdf(length=64, derive_from=shared_key, salt=link_id, context=None)

    return {
        "link_id": link_id,
        "derived_key": derived_key,
        "init_kp": init_kp,
        "resp_kp": resp_kp,
        "init_eph_e": init_eph_e,
        "resp_eph_x": resp_eph_x,
    }


# ============================================================
# Extraction functions
# ============================================================

def extract_constants():
    """Extract packet data and proof constants."""
    return {
        "packet_types": {
            "DATA": DATA,
            "PROOF": PROOF,
        },
        "destination_types": {
            "LINK": LINK,
        },
        "context_types": {
            "NONE": NONE_CONTEXT,
        },
        "proof_constants": {
            "EXPL_LENGTH": EXPL_LENGTH,
            "EXPL_LENGTH_note": f"HASHLENGTH_BYTES({HASHLENGTH_BYTES}) + SIGLENGTH_BYTES({SIGLENGTH_BYTES}) = {EXPL_LENGTH}",
            "IMPL_LENGTH": IMPL_LENGTH,
            "IMPL_LENGTH_note": f"SIGLENGTH_BYTES({SIGLENGTH_BYTES}) = {IMPL_LENGTH}",
        },
        "link_mdu": LINK_MDU,
        "link_mdu_derivation": f"floor((MTU({MTU}) - IFAC_MIN_SIZE({IFAC_MIN_SIZE}) - HEADER_MINSIZE({HEADER_MINSIZE}) - TOKEN_OVERHEAD({TOKEN_OVERHEAD})) / AES128_BLOCKSIZE({AES128_BLOCKSIZE})) * AES128_BLOCKSIZE({AES128_BLOCKSIZE}) - 1 = {LINK_MDU}",
        "data_packet_flags": f"{pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, DATA):02x}",
        "data_packet_flags_description": "HEADER_1 | FLAG_UNSET | BROADCAST | LINK | DATA",
        "proof_packet_flags": f"{pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, PROOF):02x}",
        "proof_packet_flags_description": "HEADER_1 | FLAG_UNSET | BROADCAST | LINK | PROOF",
        "proof_not_encrypted_note": "PROOF packets over LINK destinations are NOT encrypted (Packet.py:198-200). self.ciphertext = self.data",
        "data_encrypted_note": "DATA packets over LINK destinations ARE encrypted via destination.encrypt() → Token(derived_key).encrypt()",
    }


def extract_proof_strategies():
    """Document proof strategy constants."""
    return {
        "PROVE_NONE": {
            "value": PROVE_NONE,
            "hex": f"{PROVE_NONE:#04x}",
            "behavior": "Never generate proofs automatically. Application must explicitly call packet.prove().",
        },
        "PROVE_APP": {
            "value": PROVE_APP,
            "hex": f"{PROVE_APP:#04x}",
            "behavior": "Call the proof_requested callback. If it returns True, generate and send a proof.",
        },
        "PROVE_ALL": {
            "value": PROVE_ALL,
            "hex": f"{PROVE_ALL:#04x}",
            "behavior": "Always generate and send proofs for all incoming packets automatically.",
        },
        "proof_flow": [
            "1. Receiver gets a DATA packet over a link",
            "2. Check destination.proof_strategy",
            "3. If PROVE_NONE: do nothing",
            "4. If PROVE_APP: call proof_requested callback, prove if True",
            "5. If PROVE_ALL: always prove",
            "6. To prove: call link.prove_packet(packet)",
            "7. prove_packet computes: signature = link.sign(packet.packet_hash)",
            "8. proof_data = packet_hash(32) + signature(64) = 96 bytes (always explicit)",
            "9. Send proof as Packet(link, proof_data, PROOF) with context=NONE",
            "10. Proof packet is NOT encrypted (passthrough for PROOF on LINK)",
        ],
    }


def extract_receipt_states():
    """Document receipt state constants."""
    return {
        "FAILED": {
            "value": RECEIPT_FAILED,
            "hex": f"{RECEIPT_FAILED:#04x}",
            "description": "Proof not received within timeout period",
        },
        "SENT": {
            "value": RECEIPT_SENT,
            "hex": f"{RECEIPT_SENT:#04x}",
            "description": "Packet sent, awaiting proof",
        },
        "DELIVERED": {
            "value": RECEIPT_DELIVERED,
            "hex": f"{RECEIPT_DELIVERED:#04x}",
            "description": "Valid proof received, delivery confirmed",
        },
        "CULLED": {
            "value": RECEIPT_CULLED,
            "hex": f"{RECEIPT_CULLED:#04x}",
            "description": "Receipt culled (timeout set to -1)",
        },
    }


def extract_data_packet_vectors(hs_keys):
    """Generate DATA packets for various plaintext sizes."""
    from RNS.Cryptography import HMAC, PKCS7
    from RNS.Cryptography.AES import AES_256_CBC
    from RNS.Cryptography.Token import Token as TokenClass

    link_id = hs_keys["link_id"]
    derived_key = hs_keys["derived_key"]
    signing_key = derived_key[:32]
    encryption_key = derived_key[32:]

    data_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, DATA)

    test_cases = [
        {
            "description": "Empty plaintext",
            "plaintext": b"",
        },
        {
            "description": "Single byte 0x42",
            "plaintext": bytes([0x42]),
        },
        {
            "description": "Hello, Reticulum! (17 bytes)",
            "plaintext": b"Hello, Reticulum!",
        },
        {
            "description": "Exact AES block (16 bytes of 0xAA)",
            "plaintext": bytes([0xAA] * 16),
        },
        {
            "description": f"Full link MDU ({LINK_MDU} bytes)",
            "plaintext": bytes(range(256)) * (LINK_MDU // 256) + bytes(range(LINK_MDU % 256)),
        },
    ]

    vectors = []

    for idx, tc in enumerate(test_cases):
        plaintext = tc["plaintext"]

        # Deterministic IV
        iv = hashlib.sha256(b"reticulum_test_packet_data_iv_" + str(idx).encode()).digest()[:16]

        # Encrypt: Token format = IV(16) + ciphertext + HMAC(32)
        padded = PKCS7.pad(plaintext)
        ciphertext_aes = AES_256_CBC.encrypt(plaintext=padded, key=encryption_key, iv=iv)
        signed_parts = iv + ciphertext_aes
        hmac_val = HMAC.new(signing_key, signed_parts).digest()
        token_ciphertext = signed_parts + hmac_val

        # Verify with Token class
        token_obj = TokenClass(key=derived_key)
        decrypted = token_obj.decrypt(token_ciphertext)
        assert decrypted == plaintext, f"Token round-trip failed for test case {idx}"

        # Build wire packet: flags(1) + hops(1) + link_id(16) + context(1) + token_ciphertext
        raw_packet = build_header_1(data_flags, 0, link_id, NONE_CONTEXT) + token_ciphertext

        # Compute packet hash
        hashable_part = compute_hashable_part(raw_packet)
        packet_hash = full_hash(hashable_part)

        vectors.append({
            "index": idx,
            "description": tc["description"],
            "handshake_reference": "handshake_vectors[0] from links.json (keypair 0→1)",
            "link_id": link_id.hex(),
            "plaintext": plaintext.hex(),
            "plaintext_length": len(plaintext),
            "deterministic_iv": iv.hex(),
            "deterministic_iv_seed": f"SHA256(b'reticulum_test_packet_data_iv_{idx}')[:16]",
            "padded_plaintext": padded.hex(),
            "padded_plaintext_length": len(padded),
            "aes_ciphertext": ciphertext_aes.hex(),
            "aes_ciphertext_length": len(ciphertext_aes),
            "hmac": hmac_val.hex(),
            "token_ciphertext": token_ciphertext.hex(),
            "token_ciphertext_length": len(token_ciphertext),
            "token_layout": f"IV({len(iv)}) + AES_ciphertext({len(ciphertext_aes)}) + HMAC({len(hmac_val)}) = {len(token_ciphertext)}",
            "flags_byte": f"{data_flags:02x}",
            "context_byte": f"{NONE_CONTEXT:02x}",
            "raw_packet": raw_packet.hex(),
            "raw_packet_length": len(raw_packet),
            "hashable_part": hashable_part.hex(),
            "packet_hash": packet_hash.hex(),
            "packet_hash_note": "Full 32-byte SHA-256 (not truncated)",
        })

    return vectors


def extract_proof_generation_vectors(data_vectors, hs_keys):
    """Generate proof for each data packet (responder signs with identity Ed25519)."""
    from RNS.Cryptography.Ed25519 import Ed25519PrivateKey

    link_id = hs_keys["link_id"]
    resp_kp = hs_keys["resp_kp"]

    # Responder's sig_prv = identity Ed25519 private key (Link.py:279)
    resp_sig_prv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(resp_kp["ed25519_private"]))

    proof_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, PROOF)

    vectors = []

    for dv in data_vectors:
        packet_hash = bytes.fromhex(dv["packet_hash"])

        # Signature = Ed25519.sign(sig_prv, packet_hash)
        signature = resp_sig_prv.sign(packet_hash)

        # proof_data = packet_hash(32) + signature(64) = 96 bytes (always explicit)
        proof_data = packet_hash + signature
        assert len(proof_data) == EXPL_LENGTH, f"Proof data length {len(proof_data)} != {EXPL_LENGTH}"

        # Build proof wire packet: NOT encrypted (Packet.py:198-200)
        # flags(1) + hops(1) + link_id(16) + context(1) + proof_data
        raw_proof = build_header_1(proof_flags, 0, link_id, NONE_CONTEXT) + proof_data

        # Compute proof packet hash
        proof_hashable = compute_hashable_part(raw_proof)
        proof_packet_hash = full_hash(proof_hashable)

        vectors.append({
            "data_packet_index": dv["index"],
            "description": f"Proof for data packet {dv['index']}: {dv['description']}",
            "link_id": link_id.hex(),
            "original_packet_hash": packet_hash.hex(),
            "signer": "responder_identity_ed25519",
            "signer_private_key": resp_kp["ed25519_private"],
            "signer_note": "Responder signs with identity Ed25519 private key (Link.py:279: self.sig_prv = self.owner.identity.sig_prv)",
            "signature": signature.hex(),
            "signature_length": len(signature),
            "proof_data": proof_data.hex(),
            "proof_data_length": len(proof_data),
            "proof_data_layout": f"packet_hash({HASHLENGTH_BYTES}) + signature({SIGLENGTH_BYTES}) = {EXPL_LENGTH} bytes (explicit proof)",
            "not_encrypted": True,
            "not_encrypted_note": "Proof packets over LINK destinations skip encryption (Packet.py:198-200)",
            "flags_byte": f"{proof_flags:02x}",
            "context_byte": f"{NONE_CONTEXT:02x}",
            "context_note": "prove_packet() creates Packet(self, proof_data, PROOF) with default context=NONE",
            "raw_proof_packet": raw_proof.hex(),
            "raw_proof_packet_length": len(raw_proof),
            "proof_packet_hash": proof_packet_hash.hex(),
        })

    return vectors


def extract_proof_validation_vectors(proof_vectors, hs_keys):
    """Demonstrate validation of each proof."""
    from RNS.Cryptography.Ed25519 import Ed25519PublicKey

    resp_kp = hs_keys["resp_kp"]

    # Initiator's peer_sig_pub = responder's identity Ed25519 public key
    # (Link.py:412: peer_sig_pub_bytes = self.destination.identity.get_public_key()[ECPUBSIZE//2:ECPUBSIZE])
    peer_sig_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(resp_kp["ed25519_public"]))

    vectors = []

    for pv in proof_vectors:
        proof_data = bytes.fromhex(pv["proof_data"])
        original_hash = bytes.fromhex(pv["original_packet_hash"])

        # Extract components
        proof_hash = proof_data[:HASHLENGTH_BYTES]
        signature = proof_data[HASHLENGTH_BYTES:HASHLENGTH_BYTES + SIGLENGTH_BYTES]

        # Step 1: Check proof_hash matches original packet hash
        hash_match = proof_hash == original_hash

        # Step 2: Verify signature
        try:
            peer_sig_pub.verify(signature, original_hash)
            sig_valid = True
        except Exception:
            sig_valid = False

        assert hash_match, f"Proof hash mismatch for data packet {pv['data_packet_index']}"
        assert sig_valid, f"Proof signature invalid for data packet {pv['data_packet_index']}"

        vectors.append({
            "data_packet_index": pv["data_packet_index"],
            "description": f"Validate proof for data packet {pv['data_packet_index']}",
            "proof_data": pv["proof_data"],
            "proof_hash_extracted": proof_hash.hex(),
            "signature_extracted": signature.hex(),
            "validator_public_key": resp_kp["ed25519_public"],
            "validator_note": "Initiator validates with peer_sig_pub = responder's identity Ed25519 public key (Link.py:412)",
            "step_1_hash_match": hash_match,
            "step_2_signature_valid": sig_valid,
            "expected_receipt_status": "DELIVERED",
            "expected_receipt_status_value": RECEIPT_DELIVERED,
        })

    return vectors


def extract_invalid_proof_vectors(data_vectors, hs_keys):
    """Generate three failure cases for proof validation."""
    from RNS.Cryptography.Ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    link_id = hs_keys["link_id"]
    resp_kp = hs_keys["resp_kp"]

    # Use first data packet for all invalid proof tests
    dv = data_vectors[0]
    packet_hash = bytes.fromhex(dv["packet_hash"])

    # Generate valid proof first
    resp_sig_prv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(resp_kp["ed25519_private"]))
    valid_signature = resp_sig_prv.sign(packet_hash)
    valid_proof_data = packet_hash + valid_signature

    # Initiator's validation key
    peer_sig_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(resp_kp["ed25519_public"]))

    vectors = []

    # --- Case 1: Tampered hash ---
    tampered_hash = bytearray(packet_hash)
    tampered_hash[0] ^= 0xFF  # Flip first byte
    tampered_hash = bytes(tampered_hash)
    tampered_hash_proof = tampered_hash + valid_signature

    # Validation: hash mismatch → fails before signature check
    hash_match_1 = tampered_hash[:HASHLENGTH_BYTES] == packet_hash

    vectors.append({
        "description": "Invalid proof: tampered hash (first byte flipped)",
        "data_packet_index": 0,
        "original_packet_hash": packet_hash.hex(),
        "tampered_proof_data": tampered_hash_proof.hex(),
        "tampered_proof_hash": tampered_hash.hex(),
        "signature": valid_signature.hex(),
        "failure_reason": "proof_hash != original_packet_hash (hash mismatch, fails at step 1)",
        "hash_match": hash_match_1,
        "signature_check_reached": False,
        "expected_result": False,
    })

    # --- Case 2: Tampered signature ---
    tampered_sig = bytearray(valid_signature)
    tampered_sig[0] ^= 0xFF  # Flip first byte
    tampered_sig = bytes(tampered_sig)
    tampered_sig_proof = packet_hash + tampered_sig

    # Validation: hash matches, but signature verification fails
    try:
        peer_sig_pub.verify(tampered_sig, packet_hash)
        sig_valid_2 = True
    except Exception:
        sig_valid_2 = False

    vectors.append({
        "description": "Invalid proof: tampered signature (first byte flipped)",
        "data_packet_index": 0,
        "original_packet_hash": packet_hash.hex(),
        "tampered_proof_data": tampered_sig_proof.hex(),
        "proof_hash": packet_hash.hex(),
        "tampered_signature": tampered_sig.hex(),
        "failure_reason": "Ed25519 signature verification fails (valid hash, invalid signature)",
        "hash_match": True,
        "signature_check_reached": True,
        "signature_valid": sig_valid_2,
        "expected_result": False,
    })

    # --- Case 3: Wrong signing key ---
    # Sign with keypair[2]'s Ed25519 key instead of responder's
    keypairs = load_keypairs()
    wrong_kp = keypairs[2]
    wrong_sig_prv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(wrong_kp["ed25519_private"]))
    wrong_signature = wrong_sig_prv.sign(packet_hash)
    wrong_key_proof = packet_hash + wrong_signature

    # Validation: hash matches, signature is valid for wrong key, fails with correct key
    try:
        peer_sig_pub.verify(wrong_signature, packet_hash)
        sig_valid_3 = True
    except Exception:
        sig_valid_3 = False

    # Verify it IS valid for the wrong key
    wrong_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(wrong_kp["ed25519_public"]))
    try:
        wrong_pub.verify(wrong_signature, packet_hash)
        sig_valid_wrong_key = True
    except Exception:
        sig_valid_wrong_key = False

    vectors.append({
        "description": "Invalid proof: signed with wrong key (keypair[2] instead of responder keypair[1])",
        "data_packet_index": 0,
        "original_packet_hash": packet_hash.hex(),
        "wrong_key_proof_data": wrong_key_proof.hex(),
        "proof_hash": packet_hash.hex(),
        "wrong_signature": wrong_signature.hex(),
        "wrong_signer_keypair_index": 2,
        "wrong_signer_ed25519_public": wrong_kp["ed25519_public"],
        "failure_reason": "Signature valid for wrong key, fails verification with correct peer_sig_pub",
        "hash_match": True,
        "signature_check_reached": True,
        "signature_valid_with_correct_key": sig_valid_3,
        "signature_valid_with_wrong_key": sig_valid_wrong_key,
        "expected_result": False,
    })

    return vectors


def extract_bidirectional_vectors(hs_keys):
    """One vector pair showing asymmetric signing keys per direction."""
    from RNS.Cryptography import HMAC, PKCS7
    from RNS.Cryptography.AES import AES_256_CBC
    from RNS.Cryptography.Token import Token as TokenClass
    from RNS.Cryptography.Ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    link_id = hs_keys["link_id"]
    derived_key = hs_keys["derived_key"]
    signing_key = derived_key[:32]
    encryption_key = derived_key[32:]
    init_kp = hs_keys["init_kp"]
    resp_kp = hs_keys["resp_kp"]
    init_eph_e = hs_keys["init_eph_e"]

    token_obj = TokenClass(key=derived_key)

    data_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, DATA)
    proof_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, PROOF)

    vectors = []

    # --- Direction 1: Initiator → Responder ---
    # Data: encrypted with same derived_key
    # Proof: responder signs with identity Ed25519 (Link.py:279)
    # Initiator validates with peer_sig_pub = responder identity Ed25519 pub (Link.py:412)

    plaintext_i2r = b"initiator to responder"
    iv_i2r = hashlib.sha256(b"reticulum_test_bidir_i2r_iv").digest()[:16]

    padded_i2r = PKCS7.pad(plaintext_i2r)
    ct_i2r = AES_256_CBC.encrypt(plaintext=padded_i2r, key=encryption_key, iv=iv_i2r)
    signed_parts_i2r = iv_i2r + ct_i2r
    hmac_i2r = HMAC.new(signing_key, signed_parts_i2r).digest()
    token_i2r = signed_parts_i2r + hmac_i2r

    assert token_obj.decrypt(token_i2r) == plaintext_i2r

    raw_data_i2r = build_header_1(data_flags, 0, link_id, NONE_CONTEXT) + token_i2r
    hashable_i2r = compute_hashable_part(raw_data_i2r)
    packet_hash_i2r = full_hash(hashable_i2r)

    # Responder proof (identity Ed25519)
    resp_sig_prv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(resp_kp["ed25519_private"]))
    sig_i2r = resp_sig_prv.sign(packet_hash_i2r)
    proof_data_i2r = packet_hash_i2r + sig_i2r
    raw_proof_i2r = build_header_1(proof_flags, 0, link_id, NONE_CONTEXT) + proof_data_i2r

    # Verify
    resp_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(resp_kp["ed25519_public"]))
    resp_pub.verify(sig_i2r, packet_hash_i2r)

    vectors.append({
        "direction": "initiator_to_responder",
        "description": "Initiator sends DATA, responder generates proof (signs with identity Ed25519)",
        "plaintext": plaintext_i2r.hex(),
        "deterministic_iv": iv_i2r.hex(),
        "token_ciphertext": token_i2r.hex(),
        "raw_data_packet": raw_data_i2r.hex(),
        "packet_hash": packet_hash_i2r.hex(),
        "proof_signer": "responder_identity_ed25519",
        "proof_signer_private": resp_kp["ed25519_private"],
        "proof_signer_note": "Link.py:279 — responder: self.sig_prv = self.owner.identity.sig_prv",
        "proof_signature": sig_i2r.hex(),
        "proof_data": proof_data_i2r.hex(),
        "raw_proof_packet": raw_proof_i2r.hex(),
        "proof_validator_public": resp_kp["ed25519_public"],
        "proof_validator_note": "Link.py:412 — initiator: peer_sig_pub = destination.identity.get_public_key()[32:64] (responder identity Ed25519 pub)",
    })

    # --- Direction 2: Responder → Initiator ---
    # Data: encrypted with SAME derived_key (symmetric encryption)
    # Proof: initiator signs with EPHEMERAL Ed25519 (Link.py:286)
    # Responder validates with peer_sig_pub = initiator's ephemeral Ed25519 pub (Link.py:189)

    plaintext_r2i = b"responder to initiator"
    iv_r2i = hashlib.sha256(b"reticulum_test_bidir_r2i_iv").digest()[:16]

    padded_r2i = PKCS7.pad(plaintext_r2i)
    ct_r2i = AES_256_CBC.encrypt(plaintext=padded_r2i, key=encryption_key, iv=iv_r2i)
    signed_parts_r2i = iv_r2i + ct_r2i
    hmac_r2i = HMAC.new(signing_key, signed_parts_r2i).digest()
    token_r2i = signed_parts_r2i + hmac_r2i

    assert token_obj.decrypt(token_r2i) == plaintext_r2i

    raw_data_r2i = build_header_1(data_flags, 0, link_id, NONE_CONTEXT) + token_r2i
    hashable_r2i = compute_hashable_part(raw_data_r2i)
    packet_hash_r2i = full_hash(hashable_r2i)

    # Initiator proof (ephemeral Ed25519)
    init_sig_prv = Ed25519PrivateKey.from_private_bytes(init_eph_e["private_bytes"])
    sig_r2i = init_sig_prv.sign(packet_hash_r2i)
    proof_data_r2i = packet_hash_r2i + sig_r2i
    raw_proof_r2i = build_header_1(proof_flags, 0, link_id, NONE_CONTEXT) + proof_data_r2i

    # Verify
    init_eph_pub = Ed25519PublicKey.from_public_bytes(init_eph_e["public_bytes"])
    init_eph_pub.verify(sig_r2i, packet_hash_r2i)

    vectors.append({
        "direction": "responder_to_initiator",
        "description": "Responder sends DATA, initiator generates proof (signs with ephemeral Ed25519)",
        "plaintext": plaintext_r2i.hex(),
        "deterministic_iv": iv_r2i.hex(),
        "token_ciphertext": token_r2i.hex(),
        "raw_data_packet": raw_data_r2i.hex(),
        "packet_hash": packet_hash_r2i.hex(),
        "proof_signer": "initiator_ephemeral_ed25519",
        "proof_signer_private": init_eph_e["private_bytes"].hex(),
        "proof_signer_note": "Link.py:286 — initiator: self.sig_prv = Ed25519PrivateKey.generate() (ephemeral, sent in LINKREQUEST)",
        "proof_signature": sig_r2i.hex(),
        "proof_data": proof_data_r2i.hex(),
        "raw_proof_packet": raw_proof_r2i.hex(),
        "proof_validator_public": init_eph_e["public_bytes"].hex(),
        "proof_validator_note": "Link.py:189 — responder: peer_sig_pub_bytes = data[ECPUBSIZE//2:ECPUBSIZE] (initiator ephemeral Ed25519 pub from LINKREQUEST)",
    })

    return {
        "description": "Bidirectional data+proof vectors demonstrating asymmetric signing keys",
        "encryption_note": "Encryption is symmetric — both directions use the same derived_key/Token",
        "signing_note": "Signing is asymmetric — responder uses identity Ed25519, initiator uses ephemeral Ed25519",
        "link_id": link_id.hex(),
        "derived_key": derived_key.hex(),
        "vectors": vectors,
    }


def extract_burst_vectors(hs_keys):
    """Generate a burst of 10 sequential DATA packets over the same link.

    Each packet uses deterministic plaintext and IV, with full round-trip
    verification (encrypt → wire packet → hash → proof → verify).
    """
    from RNS.Cryptography import HMAC, PKCS7
    from RNS.Cryptography.AES import AES_256_CBC
    from RNS.Cryptography.Token import Token as TokenClass
    from RNS.Cryptography.Ed25519 import Ed25519PrivateKey

    link_id = hs_keys["link_id"]
    derived_key = hs_keys["derived_key"]
    signing_key = derived_key[:32]
    encryption_key = derived_key[32:]
    resp_kp = hs_keys["resp_kp"]

    token_obj = TokenClass(key=derived_key)
    data_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, DATA)
    proof_flags = pack_flags(HEADER_1, FLAG_UNSET, BROADCAST, LINK, PROOF)
    resp_sig_prv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(resp_kp["ed25519_private"]))

    burst_count = 10
    packet_size = 431  # bytes of plaintext per burst packet

    vectors = []
    all_packet_hashes = set()
    all_ivs = set()
    all_ciphertexts = set()

    for i in range(burst_count):
        plaintext = deterministic_burst_plaintext(i, packet_size)

        # Deterministic IV
        iv = hashlib.sha256(b"reticulum_test_burst_iv_" + str(i).encode()).digest()[:16]

        # Token encryption: PKCS7 pad → AES-256-CBC → HMAC
        padded = PKCS7.pad(plaintext)
        ciphertext_aes = AES_256_CBC.encrypt(plaintext=padded, key=encryption_key, iv=iv)
        signed_parts = iv + ciphertext_aes
        hmac_val = HMAC.new(signing_key, signed_parts).digest()
        token_ciphertext = signed_parts + hmac_val

        # Verify decrypt round-trip
        decrypted = token_obj.decrypt(token_ciphertext)
        assert decrypted == plaintext, f"Burst packet {i} decrypt round-trip failed"

        # Build wire packet
        raw_packet = build_header_1(data_flags, 0, link_id, NONE_CONTEXT) + token_ciphertext

        # Compute packet hash
        hashable_part = compute_hashable_part(raw_packet)
        packet_hash = full_hash(hashable_part)

        # Generate proof
        signature = resp_sig_prv.sign(packet_hash)
        proof_data = packet_hash + signature
        assert len(proof_data) == EXPL_LENGTH
        raw_proof = build_header_1(proof_flags, 0, link_id, NONE_CONTEXT) + proof_data
        proof_hashable = compute_hashable_part(raw_proof)
        proof_packet_hash = full_hash(proof_hashable)

        # Track uniqueness
        all_packet_hashes.add(packet_hash.hex())
        all_ivs.add(iv.hex())
        all_ciphertexts.add(token_ciphertext.hex())

        vectors.append({
            "burst_index": i,
            "plaintext": plaintext.hex(),
            "deterministic_iv": iv.hex(),
            "token_ciphertext": token_ciphertext.hex(),
            "raw_packet": raw_packet.hex(),
            "packet_hash": packet_hash.hex(),
            "proof_signature": signature.hex(),
            "proof_data": proof_data.hex(),
            "raw_proof_packet": raw_proof.hex(),
            "proof_packet_hash": proof_packet_hash.hex(),
        })

    assert len(all_packet_hashes) == burst_count, "Not all packet hashes are unique"
    assert len(all_ivs) == burst_count, "Not all IVs are unique"
    assert len(all_ciphertexts) == burst_count, "Not all ciphertexts are unique"

    return {
        "description": "Burst of 10 sequential DATA packets over same link with proofs",
        "link_id": link_id.hex(),
        "burst_count": burst_count,
        "packet_size": packet_size,
        "ordering_note": "DATA packets have no ordering at this layer; sequence is application-level",
        "receipt_independence_note": "Each packet produces an independent PacketReceipt with its own timeout and proof tracking",
        "vectors": vectors,
        "uniqueness_verification": {
            "all_packet_hashes_unique": len(all_packet_hashes) == burst_count,
            "all_ivs_unique": len(all_ivs) == burst_count,
            "all_ciphertexts_unique": len(all_ciphertexts) == burst_count,
        },
    }


def extract_receipt_timeout_constants():
    """Document receipt timeout computation constants."""
    return {
        "description": "Constants governing PacketReceipt timeout computation",
        "TRAFFIC_TIMEOUT_FACTOR": {
            "value": TRAFFIC_TIMEOUT_FACTOR,
            "source": "Link.py:82",
            "usage": "Multiplier for link RTT in timeout computation",
        },
        "TRAFFIC_TIMEOUT_MIN_MS": {
            "value": TRAFFIC_TIMEOUT_MIN_MS,
            "source": "Link.py:81",
            "usage": "Minimum timeout in milliseconds for link-based receipts",
        },
        "DEFAULT_PER_HOP_TIMEOUT": {
            "value": DEFAULT_PER_HOP_TIMEOUT,
            "source": "Reticulum.py:144",
            "usage": "Seconds added per hop for non-link receipt timeout",
        },
        "TIMEOUT_PER_HOP": {
            "value": TIMEOUT_PER_HOP,
            "source": "Packet.py:115 (= RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT)",
            "usage": "Alias used in PacketReceipt timeout computation",
        },
        "MAX_RECEIPTS": {
            "value": MAX_RECEIPTS,
            "source": "Transport.py:90",
            "usage": "Maximum receipts tracked; overflow causes FIFO culling",
        },
        "PATHFINDER_M": {
            "value": PATHFINDER_M,
            "source": "Transport.py:62",
            "usage": "Max hops; used as default when hop count unknown",
        },
    }


def extract_receipt_timeout_scenarios():
    """Compute receipt timeout for various scenarios.

    Link-based:  timeout = max(rtt * TRAFFIC_TIMEOUT_FACTOR, TRAFFIC_TIMEOUT_MIN_MS / 1000)
    Non-link:    timeout = first_hop_timeout + TIMEOUT_PER_HOP * hops_to(dest)
    """
    link_scenarios = []
    non_link_scenarios = []

    # Link scenarios: varying RTT
    rtts_ms = [50, 1, 0.1, 2000]
    for rtt_ms in rtts_ms:
        rtt_s = rtt_ms / 1000.0
        timeout = max(rtt_s * TRAFFIC_TIMEOUT_FACTOR, TRAFFIC_TIMEOUT_MIN_MS / 1000.0)
        link_scenarios.append({
            "description": f"Link with RTT={rtt_ms}ms",
            "rtt_ms": rtt_ms,
            "rtt_seconds": rtt_s,
            "formula": f"max({rtt_s} * {TRAFFIC_TIMEOUT_FACTOR}, {TRAFFIC_TIMEOUT_MIN_MS}/1000)",
            "timeout_seconds": timeout,
        })

    # Non-link scenarios: varying hop counts
    # first_hop_timeout: without latency info = DEFAULT_PER_HOP_TIMEOUT
    hop_cases = [
        (0, "Direct (0 hops, path known)"),
        (3, "3-hop path"),
        (PATHFINDER_M, f"Unknown path ({PATHFINDER_M} hops default)"),
    ]
    for hops, desc in hop_cases:
        first_hop_timeout = DEFAULT_PER_HOP_TIMEOUT  # no latency info
        timeout = first_hop_timeout + TIMEOUT_PER_HOP * hops
        non_link_scenarios.append({
            "description": desc,
            "hops": hops,
            "first_hop_timeout": first_hop_timeout,
            "first_hop_timeout_note": "DEFAULT_PER_HOP_TIMEOUT (no next-hop latency info)",
            "formula": f"{first_hop_timeout} + {TIMEOUT_PER_HOP} * {hops}",
            "timeout_seconds": timeout,
        })

    return {
        "description": "Receipt timeout computation scenarios",
        "link_formula": "max(rtt * TRAFFIC_TIMEOUT_FACTOR, TRAFFIC_TIMEOUT_MIN_MS / 1000)",
        "link_formula_source": "Packet.py:430",
        "non_link_formula": "first_hop_timeout + TIMEOUT_PER_HOP * hops_to(destination)",
        "non_link_formula_source": "Packet.py:432-433",
        "link_scenarios": link_scenarios,
        "non_link_scenarios": non_link_scenarios,
    }


def extract_receipt_state_machine():
    """Document the full PacketReceipt state machine."""
    return {
        "description": "PacketReceipt state machine: states, transitions, and proof validation flow",
        "states": {
            "SENT": {
                "value": RECEIPT_SENT,
                "hex": f"{RECEIPT_SENT:#04x}",
                "description": "Initial state after packet transmission",
            },
            "DELIVERED": {
                "value": RECEIPT_DELIVERED,
                "hex": f"{RECEIPT_DELIVERED:#04x}",
                "description": "Valid proof received, delivery confirmed",
            },
            "FAILED": {
                "value": RECEIPT_FAILED,
                "hex": f"{RECEIPT_FAILED:#04x}",
                "description": "Timeout expired without valid proof",
            },
            "CULLED": {
                "value": RECEIPT_CULLED,
                "hex": f"{RECEIPT_CULLED:#04x}",
                "description": "Receipt removed due to MAX_RECEIPTS overflow (FIFO)",
            },
        },
        "transitions": [
            {
                "from": "SENT",
                "to": "DELIVERED",
                "trigger": "Valid proof received",
                "condition": "proof_hash == packet_hash AND signature validates with peer_sig_pub",
                "callback": "delivery callback (if set)",
                "side_effects": ["proved = True", "concluded_at = time.time()", "link.last_proof updated"],
            },
            {
                "from": "SENT",
                "to": "FAILED",
                "trigger": "Timeout expires (check_timeout called periodically)",
                "condition": "timeout >= 0 AND time.time() > sent_at + timeout",
                "callback": "timeout callback (if set, in new thread)",
                "side_effects": ["concluded_at = time.time()"],
            },
            {
                "from": "SENT",
                "to": "CULLED",
                "trigger": "MAX_RECEIPTS overflow in Transport job loop",
                "condition": "timeout set to -1 by Transport, then check_timeout detects -1",
                "callback": "timeout callback (if set, in new thread)",
                "side_effects": ["concluded_at = time.time()"],
            },
        ],
        "proof_validation_flow": [
            "1. Receive proof packet (PROOF type on LINK destination)",
            "2. Proof is NOT encrypted (passthrough for PROOF on LINK)",
            "3. Extract proof_data from packet",
            "4. If link proof: call validate_link_proof(proof_data, link)",
            "5. Extract proof_hash = proof_data[:32], signature = proof_data[32:96]",
            "6. Check proof_hash == receipt.hash (full 32-byte packet hash)",
            "7. Validate signature via link.validate(signature, receipt.hash)",
            "8. link.validate uses peer_sig_pub.verify(signature, message)",
            "9. If valid: status → DELIVERED, proved = True",
        ],
        "culling_behavior": {
            "trigger": f"len(Transport.receipts) > MAX_RECEIPTS ({MAX_RECEIPTS})",
            "mechanism": "FIFO: oldest receipt popped, timeout set to -1, check_timeout() called",
            "result": "Status becomes CULLED (0xFF), timeout callback fires",
            "source": "Transport.py:504-508",
        },
    }


def extract_receipt_proof_matching_vectors(data_vectors, hs_keys):
    """Generate vectors showing proof matching uses full 32-byte hash, not truncated 16-byte."""
    link_id = hs_keys["link_id"]

    vectors = []

    for dv in data_vectors[:3]:
        packet_hash = bytes.fromhex(dv["packet_hash"])
        truncated = packet_hash[:TRUNCATED_HASHLENGTH_BYTES]

        vectors.append({
            "data_packet_index": dv["index"],
            "description": f"Proof matching for data packet {dv['index']}: {dv['description']}",
            "full_packet_hash": packet_hash.hex(),
            "full_packet_hash_length": len(packet_hash),
            "truncated_hash": truncated.hex(),
            "truncated_hash_length": len(truncated),
            "truncated_is_prefix": packet_hash[:TRUNCATED_HASHLENGTH_BYTES] == truncated,
            "matching_note": "Proof matching uses full 32-byte hash (PacketReceipt.hash), NOT truncated 16-byte",
            "source": "Packet.py:455 — proof_hash == self.hash (both 32 bytes)",
        })

    return {
        "description": "Proof matching uses full 32-byte packet_hash, not truncated 16-byte destination hash",
        "link_id": link_id.hex(),
        "full_hash_length": HASHLENGTH_BYTES,
        "truncated_hash_length": TRUNCATED_HASHLENGTH_BYTES,
        "vectors": vectors,
    }


def verify(output, hs_keys):
    """Cross-validate all vectors."""
    from RNS.Cryptography.Token import Token as TokenClass
    from RNS.Cryptography.Ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    print("  Verifying...")

    derived_key = hs_keys["derived_key"]
    link_id = hs_keys["link_id"]
    resp_kp = hs_keys["resp_kp"]
    token_obj = TokenClass(key=derived_key)

    # 1. Verify data packet vectors: decrypt and check plaintext
    for dv in output["data_packet_vectors"]:
        token_ct = bytes.fromhex(dv["token_ciphertext"])
        expected_pt = bytes.fromhex(dv["plaintext"])
        decrypted = token_obj.decrypt(token_ct)
        assert decrypted == expected_pt, f"Decrypt failed: {dv['description']}"

        # Verify packet hash
        raw = bytes.fromhex(dv["raw_packet"])
        hp = compute_hashable_part(raw)
        assert hp.hex() == dv["hashable_part"], f"Hashable part mismatch: {dv['description']}"
        ph = full_hash(hp)
        assert ph.hex() == dv["packet_hash"], f"Packet hash mismatch: {dv['description']}"

    print(f"    [OK] {len(output['data_packet_vectors'])} data packet vectors verified (decrypt + hash)")

    # 2. Verify proof generation vectors: signature validity
    peer_sig_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(resp_kp["ed25519_public"]))
    for pv in output["proof_generation_vectors"]:
        packet_hash = bytes.fromhex(pv["original_packet_hash"])
        signature = bytes.fromhex(pv["signature"])
        peer_sig_pub.verify(signature, packet_hash)

        # Verify proof data structure
        proof_data = bytes.fromhex(pv["proof_data"])
        assert len(proof_data) == EXPL_LENGTH
        assert proof_data[:HASHLENGTH_BYTES] == packet_hash
        assert proof_data[HASHLENGTH_BYTES:] == signature

    print(f"    [OK] {len(output['proof_generation_vectors'])} proof generation vectors verified")

    # 3. Verify proof validation vectors
    for vv in output["proof_validation_vectors"]:
        assert vv["step_1_hash_match"] is True
        assert vv["step_2_signature_valid"] is True
        assert vv["expected_receipt_status_value"] == RECEIPT_DELIVERED
    print(f"    [OK] {len(output['proof_validation_vectors'])} proof validation vectors verified")

    # 4. Verify invalid proof vectors all fail
    for iv in output["invalid_proof_vectors"]:
        assert iv["expected_result"] is False, f"Invalid proof should fail: {iv['description']}"
    print(f"    [OK] {len(output['invalid_proof_vectors'])} invalid proof vectors verified")

    # 5. Verify bidirectional vectors
    bidir = output["bidirectional_vectors"]
    for bv in bidir["vectors"]:
        # Decrypt
        token_ct = bytes.fromhex(bv["token_ciphertext"])
        expected_pt = bytes.fromhex(bv["plaintext"])
        decrypted = token_obj.decrypt(token_ct)
        assert decrypted == expected_pt, f"Bidir decrypt failed: {bv['direction']}"

        # Verify proof signature
        packet_hash = bytes.fromhex(bv["packet_hash"])
        signature = bytes.fromhex(bv["proof_signature"])
        validator_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(bv["proof_validator_public"]))
        validator_pub.verify(signature, packet_hash)

    print(f"    [OK] {len(bidir['vectors'])} bidirectional vectors verified")

    # 6. Verify burst vectors: decrypt round-trip + hash + proof signature + uniqueness
    burst = output["burst_vectors"]
    resp_sig_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(hs_keys["resp_kp"]["ed25519_public"]))
    burst_hashes = set()
    for bv in burst["vectors"]:
        # Decrypt round-trip
        token_ct = bytes.fromhex(bv["token_ciphertext"])
        expected_pt = bytes.fromhex(bv["plaintext"])
        decrypted = token_obj.decrypt(token_ct)
        assert decrypted == expected_pt, f"Burst decrypt failed: index {bv['burst_index']}"

        # Verify packet hash
        raw = bytes.fromhex(bv["raw_packet"])
        hp = compute_hashable_part(raw)
        ph = full_hash(hp)
        assert ph.hex() == bv["packet_hash"], f"Burst hash mismatch: index {bv['burst_index']}"

        # Verify proof signature
        packet_hash = bytes.fromhex(bv["packet_hash"])
        signature = bytes.fromhex(bv["proof_signature"])
        resp_sig_pub.verify(signature, packet_hash)

        burst_hashes.add(bv["packet_hash"])

    assert len(burst_hashes) == burst["burst_count"], "Burst packet hashes not all unique"
    print(f"    [OK] {len(burst['vectors'])} burst vectors verified (decrypt + hash + proof + uniqueness)")

    # 7. Verify timeout scenarios: recompute each formula and compare
    scenarios = output["receipt_timeout_scenarios"]
    for ls in scenarios["link_scenarios"]:
        rtt_s = ls["rtt_ms"] / 1000.0
        expected = max(rtt_s * TRAFFIC_TIMEOUT_FACTOR, TRAFFIC_TIMEOUT_MIN_MS / 1000.0)
        assert ls["timeout_seconds"] == expected, f"Link timeout mismatch for RTT={ls['rtt_ms']}ms"
    for ns in scenarios["non_link_scenarios"]:
        expected = ns["first_hop_timeout"] + TIMEOUT_PER_HOP * ns["hops"]
        assert ns["timeout_seconds"] == expected, f"Non-link timeout mismatch for hops={ns['hops']}"
    print(f"    [OK] {len(scenarios['link_scenarios'])} link + {len(scenarios['non_link_scenarios'])} non-link timeout scenarios verified")

    # 8. Verify state machine constant values
    sm = output["receipt_state_machine"]
    assert sm["states"]["SENT"]["value"] == RECEIPT_SENT
    assert sm["states"]["DELIVERED"]["value"] == RECEIPT_DELIVERED
    assert sm["states"]["FAILED"]["value"] == RECEIPT_FAILED
    assert sm["states"]["CULLED"]["value"] == RECEIPT_CULLED
    print("    [OK] State machine constants verified")

    # 9. Verify proof matching: truncated hash is prefix of full hash
    pm = output["receipt_proof_matching_vectors"]
    for pmv in pm["vectors"]:
        full_h = pmv["full_packet_hash"]
        trunc_h = pmv["truncated_hash"]
        assert full_h.startswith(trunc_h), f"Truncated hash not prefix of full hash for index {pmv['data_packet_index']}"
        assert pmv["truncated_is_prefix"] is True
    print(f"    [OK] {len(pm['vectors'])} proof matching vectors verified")

    # 10. Cross-check link_id and derived_key against links.json
    links_data = load_links_json()
    hs0 = links_data["handshake_vectors"][0]
    links_link_id = hs0["step_1_linkrequest"]["link_id"]
    links_derived_key = hs0["step_2_lrproof"]["derived_key"]
    assert link_id.hex() == links_link_id, f"link_id mismatch: {link_id.hex()} != {links_link_id}"
    assert derived_key.hex() == links_derived_key, f"derived_key mismatch"
    print("    [OK] link_id and derived_key cross-validated against links.json")

    # 11. JSON round-trip
    json_str = json.dumps(output, indent=2)
    assert json.loads(json_str) == output, "JSON round-trip failed"
    print("    [OK] JSON round-trip integrity verified")


def verify_library_constants():
    """Verify our local constants match the actual RNS library values."""
    import RNS
    from RNS.Link import Link
    from RNS.Packet import Packet, PacketReceipt

    assert MTU == RNS.Reticulum.MTU
    assert HEADER_MINSIZE == RNS.Reticulum.HEADER_MINSIZE
    assert IFAC_MIN_SIZE == RNS.Reticulum.IFAC_MIN_SIZE
    assert TOKEN_OVERHEAD == RNS.Identity.TOKEN_OVERHEAD
    assert AES128_BLOCKSIZE == RNS.Identity.AES128_BLOCKSIZE
    assert TRUNCATED_HASHLENGTH_BYTES == RNS.Reticulum.TRUNCATED_HASHLENGTH // 8
    assert KEYSIZE_BYTES == RNS.Identity.KEYSIZE // 8
    assert SIGLENGTH_BYTES == RNS.Identity.SIGLENGTH // 8
    assert HASHLENGTH_BYTES == RNS.Identity.HASHLENGTH // 8

    assert LINK_MDU == Link.MDU, f"LINK_MDU mismatch: {LINK_MDU} != {Link.MDU}"

    assert EXPL_LENGTH == PacketReceipt.EXPL_LENGTH
    assert IMPL_LENGTH == PacketReceipt.IMPL_LENGTH

    assert RECEIPT_FAILED == PacketReceipt.FAILED
    assert RECEIPT_SENT == PacketReceipt.SENT
    assert RECEIPT_DELIVERED == PacketReceipt.DELIVERED
    assert RECEIPT_CULLED == PacketReceipt.CULLED

    from RNS.Destination import Destination
    assert PROVE_NONE == Destination.PROVE_NONE
    assert PROVE_APP == Destination.PROVE_APP
    assert PROVE_ALL == Destination.PROVE_ALL

    assert TRAFFIC_TIMEOUT_FACTOR == Link.TRAFFIC_TIMEOUT_FACTOR
    assert TRAFFIC_TIMEOUT_MIN_MS == Link.TRAFFIC_TIMEOUT_MIN_MS
    assert DEFAULT_PER_HOP_TIMEOUT == RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
    assert TIMEOUT_PER_HOP == Packet.TIMEOUT_PER_HOP

    from RNS.Transport import Transport
    assert MAX_RECEIPTS == Transport.MAX_RECEIPTS
    assert PATHFINDER_M == Transport.PATHFINDER_M

    print("  [OK] All library constants verified")


def main():
    print("Extracting data packet and proof test vectors...")

    print("Verifying library constants...")
    verify_library_constants()

    keypairs = load_keypairs()
    print(f"  Loaded {len(keypairs)} keypairs")

    print("Generating deterministic ephemeral keys...")
    eph_x25519, eph_ed25519 = generate_ephemeral_keys(4)
    print(f"  Generated {len(eph_x25519)} ephemeral X25519 + {len(eph_ed25519)} Ed25519 key pairs")

    print("Reconstructing handshake keys (scenario 0: keypair 0→1)...")
    hs_keys = reconstruct_handshake_keys(keypairs, eph_x25519, eph_ed25519)
    print(f"  link_id = {hs_keys['link_id'].hex()}")

    print("Extracting constants...")
    constants = extract_constants()

    print("Extracting proof strategies...")
    proof_strategies = extract_proof_strategies()

    print("Extracting receipt states...")
    receipt_states = extract_receipt_states()

    print("Extracting data packet vectors...")
    data_vectors = extract_data_packet_vectors(hs_keys)
    print(f"  Extracted {len(data_vectors)} data packet vectors")

    print("Extracting proof generation vectors...")
    proof_gen_vectors = extract_proof_generation_vectors(data_vectors, hs_keys)
    print(f"  Extracted {len(proof_gen_vectors)} proof generation vectors")

    print("Extracting proof validation vectors...")
    proof_val_vectors = extract_proof_validation_vectors(proof_gen_vectors, hs_keys)
    print(f"  Extracted {len(proof_val_vectors)} proof validation vectors")

    print("Extracting invalid proof vectors...")
    invalid_vectors = extract_invalid_proof_vectors(data_vectors, hs_keys)
    print(f"  Extracted {len(invalid_vectors)} invalid proof vectors")

    print("Extracting bidirectional vectors...")
    bidir_vectors = extract_bidirectional_vectors(hs_keys)
    print(f"  Extracted {len(bidir_vectors['vectors'])} bidirectional vectors")

    print("Extracting burst vectors...")
    burst_vectors = extract_burst_vectors(hs_keys)
    print(f"  Extracted {len(burst_vectors['vectors'])} burst vectors")

    print("Extracting receipt timeout constants...")
    timeout_constants = extract_receipt_timeout_constants()

    print("Extracting receipt timeout scenarios...")
    timeout_scenarios = extract_receipt_timeout_scenarios()
    print(f"  Extracted {len(timeout_scenarios['link_scenarios'])} link + {len(timeout_scenarios['non_link_scenarios'])} non-link scenarios")

    print("Extracting receipt state machine...")
    state_machine = extract_receipt_state_machine()

    print("Extracting receipt proof matching vectors...")
    proof_matching = extract_receipt_proof_matching_vectors(data_vectors, hs_keys)
    print(f"  Extracted {len(proof_matching['vectors'])} proof matching vectors")

    output = {
        "description": "Reticulum v1.1.3 - data packet and proof test vectors",
        "source": "RNS/Packet.py, RNS/Link.py, RNS/Destination.py, RNS/Transport.py",
        "constants": constants,
        "proof_strategies": proof_strategies,
        "receipt_states": receipt_states,
        "data_packet_vectors": data_vectors,
        "proof_generation_vectors": proof_gen_vectors,
        "proof_validation_vectors": proof_val_vectors,
        "invalid_proof_vectors": invalid_vectors,
        "bidirectional_vectors": bidir_vectors,
        "burst_vectors": burst_vectors,
        "receipt_timeout_constants": timeout_constants,
        "receipt_timeout_scenarios": timeout_scenarios,
        "receipt_state_machine": state_machine,
        "receipt_proof_matching_vectors": proof_matching,
    }

    verify(output, hs_keys)

    print(f"Writing {OUTPUT_PATH}...")
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
        f.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
