# Comprehensive Review of Out-of-Band Test Vectors

## Scope

Review of all 8 JSON test vector files, 8 extraction scripts, and supporting documentation for correctness against the Reticulum v1.1.3 reference implementation.

---

## Verdict: Test Vectors Are Correct

All 8 test vector JSON files and all 8 extraction scripts have been thoroughly cross-referenced against the reference source code. **No bugs found in the test vectors or extraction scripts.** Every extraction script includes inline verification (assertions, library round-trips, cross-file references).

### Files Reviewed

| File                                   | Size | Status  |
| -------------------------------------- | ---- | ------- |
| `test_vectors/keypairs.json`           | 12K  | Correct |
| `test_vectors/hashes.json`             | 4.0M | Correct |
| `test_vectors/token.json`              | 11K  | Correct |
| `test_vectors/hkdf.json`               | 3.4K | Correct |
| `test_vectors/destination_hashes.json` | 9.0K | Correct |
| `test_vectors/packet_headers.json`     | 74K  | Correct |
| `test_vectors/announces.json`          | 61K  | Correct |
| `test_vectors/links.json`              | 43K  | Correct |

---

## Documentation Bugs Found (CLAUDE.md + TESTING_PLAN.md)

Both `CLAUDE.md` and `TESTING_PLAN.md` have **incorrect constant values** that do NOT match the source code. The test vector JSON files have the correct values.

### Bug 1: HEADER_MAXSIZE

- **CLAUDE.md line 31**: `HEADER_MAXSIZE = 37 bytes`
- **TESTING_PLAN.md line 171**: `HEADER_MAXSIZE = 37 bytes`
- **Actual (Reticulum.py:150)**: `2 + 1 + (128//8)*2 = 2 + 1 + 32 = 35`
- **Fix**: Change to `35 bytes`

### Bug 2: MDU (Reticulum.MDU / Packet.MDU)

- **CLAUDE.md line 32**: `MDU = 462 bytes`
- **TESTING_PLAN.md line 173**: `MDU = 462 bytes`
- **Actual (Reticulum.py:154)**: `500 - 35 - 1 = 464`
- **Fix**: Change to `464 bytes`

### Bug 3: PLAIN_MDU formula and value (TESTING_PLAN.md only)

- **TESTING_PLAN.md line 191**: `PLAIN_MDU = MTU - HEADER_MINSIZE - IFAC_MIN_SIZE ≈ 480 bytes`
- **Actual (Packet.py:110)**: `PLAIN_MDU = MDU = 464`
- **Fix**: Change formula to `MDU` and value to `464 bytes`

### Bug 4: ENCRYPTED_MDU formula (TESTING_PLAN.md only)

- **TESTING_PLAN.md line 192**: formula uses `MTU` instead of `MDU`
- **Actual (Packet.py:106)**: `floor((MDU - TOKEN_OVERHEAD - KEYSIZE//16) / AES128_BLOCKSIZE) * AES128_BLOCKSIZE - 1`
- The listed value of ~383 is correct despite the wrong formula
- **Fix**: Change `MTU` to `MDU` in the formula

### Bug 5: Link.MDU value (TESTING_PLAN.md only)

- **TESTING_PLAN.md line 193**: `Link.MDU ≈ 264 bytes (AES-256-CBC)`
- **Actual (Link.py:73)**: `floor((500 - 1 - 19 - 48) / 16) * 16 - 1 = 431`
- **Fix**: Change to `431 bytes` and update description

---

## Action Plan

### Step 1: Fix CLAUDE.md (2 lines)

- **File**: `/Users/matthew/workspace/personal/Reticulum/CLAUDE.md`
- Line 31: `HEADER_MAXSIZE` → `35 bytes`
- Line 32: `MDU` → `464 bytes`

### Step 2: Fix TESTING_PLAN.md (5 lines)

- **File**: `/Users/matthew/workspace/personal/Reticulum/TESTING_PLAN.md`
- Line 171: `HEADER_MAXSIZE` → `35 bytes`, update notes to `2 + 1 + 16*2`
- Line 173: `MDU` → `464 bytes`
- Line 191: `PLAIN_MDU` → formula `= MDU`, value `464 bytes`
- Line 192: `ENCRYPTED_MDU` → change `MTU` to `MDU` in formula, keep `383 bytes`
- Line 193: `Link.MDU` → value `431 bytes`

### Step 3: Re-run all extraction scripts to verify round-trips

Run each script to confirm generated JSON matches committed JSON:

```bash
cd /Users/matthew/workspace/personal/Reticulum
python3 test_vectors/extract_keypairs.py
python3 test_vectors/extract_hashes.py
python3 test_vectors/extract_token.py
python3 test_vectors/extract_hkdf.py
python3 test_vectors/extract_destinations.py
python3 test_vectors/extract_packets.py
python3 test_vectors/extract_announces.py
python3 test_vectors/extract_links.py
```

Then diff each generated JSON against the committed version.

### Step 4: Commit and sync

---

## Detailed Verification Notes

### keypairs.json - All Correct

- Key split: first 32 bytes = X25519, last 32 = Ed25519 (Identity.py:609-611)
- Identity hash = SHA256(pub_key)[:16] (Identity.py:648-649, 256)
- Signature test: message is UTF-8 encoding of hex string literal (tests/identity.py:35 uses `.encode("utf-8")`)
- Encryption decomposition: ephemeral_pub(32) + fernet_token(rest) (Identity.py:726-728)
- All 5 keypairs match tests/identity.py fixed_keys
- ECDH vectors: 4 combinations, symmetry verified
- Signature vectors: 5 keypairs with common + unique messages

### token.json - All Correct

- Token format: IV(16) || ciphertext || HMAC(32) (Token.py:89-97)
- Key split: signing=key[:32], encryption=key[32:] (Token.py:67-70)
- PKCS7: all 5 edge cases verified against PKCS7.py:35-39
- HMAC over (IV || ciphertext) with signing_key (Token.py:96-97)
- 3 deterministic Fernet vectors with known IVs, all round-trip verified
- Fixed token decomposition matches tests/identity.py exactly

### hkdf.json - All Correct

- RFC 5869 Test Cases 1-3 match published standard
- Counter: `(i+1) % 256` matches HKDF.py:59
- Empty salt: 32 zero bytes (HKDF.py:47-48)
- Reticulum vector: salt=id_hash of keypair 0, shared_key matches ecdh_vectors[0]

### destination_hashes.json - All Correct

- name_hash = SHA256(base_name.encode('utf-8'))[:10] (Destination.py:120)
- addr_hash_material = name_hash + identity_hash for SINGLE (Destination.py:121-124)
- addr_hash_material = name_hash only for PLAIN
- 9 SINGLE + 2 PLAIN destinations, all cross-verified

### packet_headers.json - All Correct

- Flag packing formula matches Packet.py:168-173 exactly
- All 128 flag byte combinations enumerated
- MDU=464, ENCRYPTED_MDU=383, PLAIN_MDU=464 (all correct vs source)
- Packet hash: mask with 0x0F, skip bytes 0-1 (Packet.py:354-361)

### announces.json - All Correct

- signed_data = dest_hash + pub_key + name_hash + random_hash [+ ratchet] [+ app_data]
- random_hash = 5 random bytes + 5-byte BE timestamp (Destination.py:282)
- Context flag: 0x01 if ratchet, 0x00 otherwise
- Max app_data: 333 (no ratchet), 301 (with ratchet)
- 9 valid, 7 invalid, 5 app_data, 4 ratchet vectors
- Packet hash invariant across hop count changes (correct)

### links.json - All Correct

- Link.MDU = 431 (Link.py:73) - different from Reticulum.MDU (464)
- MODE_DEFAULT = 1 (AES_256_CBC) (Link.py:134)
- Signalling bytes encode mode in top 3 bits, MTU in lower 21 bits
- Link ID strips signalling bytes before hashing (Link.py:341-347)
- LRPROOF signed_data includes responder's identity Ed25519 pub key
- HKDF: salt=link_id, context=None, length=64 for AES_256_CBC
- All keepalive constants verified

### Extraction Scripts - All Correct

All 8 scripts include runtime verification:

- Library constants checked at startup
- Every vector verified via round-trip through reference APIs
- Cross-file consistency checks (e.g., destination hashes vs keypairs)
- JSON written only after all assertions pass

### Minor Note

- `hashes.json` is 4MB due to 1MB test inputs encoded as hex. Consumers should regenerate from `input_length` field rather than parsing huge hex strings.
