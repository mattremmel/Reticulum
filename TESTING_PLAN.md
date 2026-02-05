# Reticulum Reference Implementation - Out-of-Band Test Guide

> **WARNING: DO NOT MODIFY ANY PYTHON CODE IN THIS REPOSITORY.**
> This is the reference implementation of the Reticulum networking stack (v1.1.3).
> It is the source of truth. If a test fails against this implementation, the test is wrong.
> All test infrastructure must be out-of-band (separate project/repository).

---

## Purpose

This document contains everything needed to build a comprehensive, out-of-band conformance
test suite that can be run against **both** this reference implementation and alternative
implementations deployed as real services (e.g., in Docker). The goal is to verify behavioral
compatibility between implementations.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Running the Reference Implementation](#running-the-reference-implementation)
3. [Architecture Overview](#architecture-overview)
4. [Core Constants](#core-constants)
5. [Cryptographic Primitives](#cryptographic-primitives)
6. [Wire Format: Packet Structure](#wire-format-packet-structure)
7. [Destination Addressing](#destination-addressing)
8. [Announce Protocol](#announce-protocol)
9. [Link Establishment Protocol](#link-establishment-protocol)
10. [Packet Delivery and Proofs](#packet-delivery-and-proofs)
11. [Resource Transfer Protocol](#resource-transfer-protocol)
12. [Channel Protocol](#channel-protocol)
13. [Buffer Protocol](#buffer-protocol)
14. [Request/Response Protocol](#requestresponse-protocol)
15. [Transport and Routing](#transport-and-routing)
16. [Interface Layer](#interface-layer)
17. [Known Test Vectors](#known-test-vectors)
18. [Test Categories and Strategy](#test-categories-and-strategy)
19. [Docker Deployment Guide](#docker-deployment-guide)
20. [API Quick Reference](#api-quick-reference)
21. [Key Source Files](#key-source-files)

---

## Project Overview

Reticulum is a cryptography-based networking stack that:
- Does NOT rely on IP (but can tunnel over IP networks)
- Uses cryptographic addressing (destination hashes derived from identity keys)
- Encrypts all communication by default at the protocol level
- Supports extreme latency (5 bps) to high bandwidth (500 Mbps)
- Is fully decentralized with no central authority
- Provides initiator anonymity (no source addresses in packets)
- Supports multi-hop routing over heterogeneous mediums

**Version:** 1.1.3
**Python:** >= 3.7
**Dependencies:** `cryptography>=3.4.7`, `pyserial>=3.5` (or zero deps with `rnspure`)

---

## Running the Reference Implementation

### Installation
```bash
pip install rns          # Standard (with OpenSSL via PyCA)
pip install rnspure      # Pure Python fallback (no native deps)
```

### From Source
```bash
cd /path/to/Reticulum
pip install -e .
```

### CLI Entry Points
| Command      | Purpose                        |
|-------------|-------------------------------|
| `rnsd`      | Daemon / network service       |
| `rnstatus`  | Interface status display       |
| `rnprobe`   | Connectivity diagnostics       |
| `rnpath`    | Path lookup and management     |
| `rnid`      | Identity management            |
| `rncp`      | File transfer                  |
| `rnx`       | Remote command execution       |

### Running Built-in Tests
```bash
make test
# Or directly:
python3 -m tests.all
```

### Configuration
Default config directory: `~/.reticulum/`

Minimal test config (from `tests/rnsconfig/config`):
```ini
[reticulum]
  enable_transport = no
  share_instance = Yes
  instance_name = testrunner
  shared_instance_port = 55905
  instance_control_port = 55906
  panic_on_interface_error = No

[logging]
  loglevel = 1

[interfaces]
  # No interfaces defined = local-only traffic
```

### Shared Instance Model
The default deployment uses a shared instance architecture:
- First process starts the RNS daemon on port **37428** (data) / **37429** (control)
- Subsequent processes connect via IPC (Unix socket or TCP)
- Configurable via `shared_instance_port` and `instance_control_port`

### Programmatic Initialization
```python
import RNS
reticulum = RNS.Reticulum(configdir="/path/to/config")
# Or None for default config location
```

---

## Architecture Overview

```
Application Layer
  Destination / Link / Resource / Channel / Buffer / Packet APIs
    |
Transport Layer (routing, path discovery, announce propagation)
    |
Interface Layer (hardware/network abstraction)
    |
Physical Mediums (TCP, UDP, serial, LoRa, I2P, etc.)
```

### Key Relationships
```
Reticulum (singleton)
 ├── Transport (static/singleton) - routing, path tables, announce tables
 │    ├── Interface instances (TCP, UDP, Auto, Local, etc.)
 │    ├── Destination registrations
 │    └── Link tracking
 ├── Identity - cryptographic keypair (X25519 + Ed25519)
 ├── Destination - named endpoint with identity + app_name + aspects
 │    ├── Can create/accept Links
 │    └── Can receive/send Packets
 ├── Link - encrypted bidirectional channel between destinations
 │    ├── Channel - message-based communication over link
 │    ├── Buffer - stream-based communication over channel
 │    └── Resource - large data transfer over link
 └── Packet - single unit of data transmission
```

---

## Core Constants

Source: `RNS/Reticulum.py`, `RNS/Packet.py`, `RNS/Link.py`, `RNS/Identity.py`

### Fundamental Sizes
| Constant                  | Value     | Notes |
|--------------------------|-----------|-------|
| `MTU`                    | 500 bytes | Base maximum transmission unit |
| `HEADER_MINSIZE`         | 19 bytes  | 2 (flags+hops) + 1 (context) + 16 (dest hash) |
| `HEADER_MAXSIZE`         | 37 bytes  | 2 + 1 + 16*2 (with transport ID) |
| `IFAC_MIN_SIZE`          | 1 byte    | Minimum interface access code |
| `MDU`                    | 462 bytes | MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE |
| `TRUNCATED_HASHLENGTH`   | 128 bits (16 bytes) | Destination/identity hash length |
| `HASHLENGTH`             | 256 bits (32 bytes) | Full SHA-256 hash |
| `KEYSIZE`                | 512 bits (64 bytes) | Full identity keypair (32 enc + 32 sig) |
| `SIGLENGTH`              | 512 bits (64 bytes) | Ed25519 signature length |
| `NAME_HASH_LENGTH`       | 80 bits (10 bytes)  | App name hash truncation |
| `RATCHETSIZE`            | 256 bits (32 bytes) | X25519 ratchet key |

### Encryption Overhead
| Constant                 | Value      | Notes |
|--------------------------|------------|-------|
| `TOKEN_OVERHEAD`         | 48 bytes   | IV(16) + HMAC-SHA256(32) |
| `AES128_BLOCKSIZE`       | 16 bytes   | AES block size |
| `ECPUBSIZE`              | 64 bytes   | Ephemeral key exchange (32 X25519 + 32 Ed25519) |

### Derived MDU Values
| Constant           | Derivation | Approx Value |
|--------------------|-----------|-------------|
| `PLAIN_MDU`        | MTU - HEADER_MINSIZE - IFAC_MIN_SIZE | ~480 bytes |
| `ENCRYPTED_MDU`    | floor((MTU - TOKEN_OVERHEAD - KEYSIZE//16) / 16) * 16 - 1 | ~383 bytes |
| `Link.MDU`         | Negotiated per-link, depends on encryption mode | ~264 bytes (AES-256-CBC) |

### Timing Constants
| Constant                    | Value | Source |
|-----------------------------|-------|--------|
| `DEFAULT_PER_HOP_TIMEOUT`   | 6 seconds | `Reticulum.py` |
| `PATHFINDER_E`              | 7 days | Path expiration (Transport.py) |
| `AP_PATH_TIME`              | 1 day | Access point path TTL |
| `ROAMING_PATH_TIME`         | 6 hours | Roaming mode path TTL |
| `REVERSE_TIMEOUT`           | 8 minutes | Reverse table entry TTL |
| `PATH_REQUEST_TIMEOUT`      | 15 seconds | Path request timeout |
| `PATH_REQUEST_GRACE`        | 0.4 seconds | Grace for direct responses |
| `LINK_KEEPALIVE_MAX`        | 360 seconds | Max keepalive interval |
| `LINK_KEEPALIVE_MIN`        | 5 seconds | Min keepalive interval |
| `LINK_STALE_FACTOR`         | 2 | Stale = keepalive * 2 |
| `RESOURCE_CACHE`            | 1 day | Resource cache lifetime |
| `ANNOUNCE_CAP`              | 2% | Max announce bandwidth fraction |
| `QUEUED_ANNOUNCE_LIFE`      | 1 day | Announce queue lifetime |
| `MAX_QUEUED_ANNOUNCES`      | 16384 | Max queued announces |

---

## Cryptographic Primitives

### Algorithms
| Operation         | Algorithm      | Key/Output Size |
|-------------------|---------------|----------------|
| Key Exchange      | X25519 (ECDH) | 32-byte keys, 32-byte shared secret |
| Signatures        | Ed25519        | 32-byte keys, 64-byte signatures |
| Symmetric Encrypt | AES-256-CBC    | 32-byte key, PKCS7 padding |
| MAC               | HMAC-SHA256    | 32-byte output |
| Hash              | SHA-256        | 32-byte output |
| Key Derivation    | HKDF-SHA256    | Variable output length |

### Identity Key Structure (64 bytes total)
```
Offset 0-31:  X25519 private key (encryption)
Offset 32-63: Ed25519 private seed (signing)
```

Public key (64 bytes):
```
Offset 0-31:  X25519 public key
Offset 32-63: Ed25519 public key (verify key)
```

### Identity Hash Derivation
```
identity_hash = SHA256(public_key)[0:16]    # 16 bytes (TRUNCATED_HASHLENGTH//8)
```

### Token Encryption (Modified Fernet)
Modified Fernet without VERSION or TIMESTAMP fields (reduces overhead, prevents metadata leakage).

Encryption with 64-byte derived key:
```
signing_key   = derived_key[0:32]
encryption_key = derived_key[32:64]

iv = random(16 bytes)
ciphertext = AES-256-CBC(encryption_key, iv, PKCS7_pad(plaintext))
hmac = HMAC-SHA256(signing_key, iv + ciphertext)

token = iv + ciphertext + hmac
```

TOKEN_OVERHEAD = 48 bytes (16 IV + 32 HMAC)

### HKDF Key Derivation
```
HKDF-SHA256(
    length=output_bytes,
    derive_from=input_key_material,
    salt=salt_bytes,          # Default: 32 zero bytes if None
    context=context_bytes     # Default: empty bytes if None
)
```

### Encryption Envelope (to a Destination)
```
ephemeral_prv = X25519PrivateKey.generate()
ephemeral_pub = ephemeral_prv.public_key_bytes()  # 32 bytes

shared_secret = X25519_DH(ephemeral_prv, target_public_key)

derived_key = HKDF(length=64, derive_from=shared_secret, salt=identity_hash)

token = Token(derived_key).encrypt(plaintext)  # iv + ciphertext + hmac

encrypted_payload = ephemeral_pub(32) + token(variable)
```

### Crypto Provider System
Two backends supported transparently:
- **PyCA** (`cryptography` library) - OpenSSL-based, preferred
- **Internal** - Pure Python fallback (slower, no native deps)

Detection: `RNS.Cryptography.backend()` returns `"internal"` or `"openssl, PyCA <version>"`

---

## Wire Format: Packet Structure

Source: `RNS/Packet.py`

### Flags Byte (offset 0)
```
Bit 7 (MSB): HEADER_TYPE    (0=HEADER_1, 1=HEADER_2)
Bit 6:       CONTEXT_FLAG   (0=FLAG_UNSET, 1=FLAG_SET)
Bit 5:       TRANSPORT_TYPE (0=BROADCAST, 1=TRANSPORT)
Bits 4-3:    DESTINATION_TYPE
  00 = SINGLE
  01 = GROUP
  10 = PLAIN
  11 = LINK
Bits 1-0:    PACKET_TYPE
  00 = DATA (0x00)
  01 = ANNOUNCE (0x01)
  10 = LINKREQUEST (0x02)
  11 = PROOF (0x03)
```

### HEADER_1 (Normal Packet)
```
Offset 0:              Flags (1 byte)
Offset 1:              Hops (1 byte)
Offset 2:              Destination Hash (16 bytes)
Offset 18:             Context (1 byte)
Offset 19+:            Data/Ciphertext (variable)
```

### HEADER_2 (Transport Packet)
```
Offset 0:              Flags (1 byte)
Offset 1:              Hops (1 byte)
Offset 2:              Transport ID (16 bytes)
Offset 18:             Destination Hash (16 bytes)
Offset 34:             Context (1 byte)
Offset 35+:            Data/Ciphertext (variable)
```

### Packet Types
| Type         | Value | Description |
|-------------|-------|-------------|
| `DATA`       | 0x00 | Regular data packet |
| `ANNOUNCE`   | 0x01 | Destination announcement |
| `LINKREQUEST`| 0x02 | Link establishment request |
| `PROOF`      | 0x03 | Delivery/link proof |

### Context Types
| Context          | Value | Description |
|-----------------|-------|-------------|
| `NONE`           | 0x00 | No specific context |
| `RESOURCE`       | 0x01 | Resource data |
| `RESOURCE_ADV`   | 0x02 | Resource advertisement |
| `RESOURCE_REQ`   | 0x03 | Resource request |
| `RESOURCE_HMU`   | 0x04 | Resource hashmap update |
| `RESOURCE_PRF`   | 0x05 | Resource proof |
| `RESOURCE_ICL`   | 0x06 | Resource initiator cancel |
| `RESOURCE_RCL`   | 0x07 | Resource receiver cancel |
| `CACHE_REQUEST`  | 0x08 | Cache lookup request |
| `REQUEST`        | 0x09 | Application request |
| `RESPONSE`       | 0x0A | Application response |
| `PATH_RESPONSE`  | 0x0B | Path query response |
| `COMMAND`        | 0x0C | Remote command |
| `COMMAND_STATUS` | 0x0D | Command status |
| `CHANNEL`        | 0x0E | Channel data |
| `KEEPALIVE`      | 0xFA | Link keepalive |
| `LINKIDENTIFY`   | 0xFB | Link identity verification |
| `LINKCLOSE`      | 0xFC | Link close |
| `LINKPROOF`      | 0xFD | Link proof |
| `LRRTT`          | 0xFE | Link RTT measurement |
| `LRPROOF`        | 0xFF | Link request proof |

### Proof Format
**Explicit Proof** (96 bytes):
```
Offset 0-31:  Packet Hash (32 bytes)
Offset 32-95: Ed25519 Signature (64 bytes)
```

**Implicit Proof** (64 bytes):
```
Offset 0-63: Ed25519 Signature (64 bytes)
```

---

## Destination Addressing

Source: `RNS/Destination.py`

### Destination Types
| Type    | Value | Description |
|---------|-------|-------------|
| `SINGLE` | 0x00 | Unicast to single identity |
| `GROUP`  | 0x01 | Multicast with shared key |
| `PLAIN`  | 0x02 | Unencrypted |
| `LINK`   | 0x03 | Link-specific endpoint |

### Direction
| Direction | Value | Description |
|-----------|-------|-------------|
| `IN`      | 0x00 | Listening/server |
| `OUT`     | 0x01 | Sending/client |

### Hash Derivation Algorithm
```python
# Step 1: Name hash from app name + aspects (without identity)
full_name = "app_name.aspect1.aspect2"
name_hash = SHA256(full_name.encode("utf-8"))[0:10]

# Step 2: Identity hash
identity_hash = SHA256(identity_public_key)[0:16]

# Step 3: Destination hash combines name + identity
addr_hash_material = name_hash + identity_hash
destination_hash = SHA256(addr_hash_material)[0:16]
```

**Important:** The name hash is 10 bytes, identity hash is 16 bytes, and destination hash is 16 bytes.

### Proof Strategies
| Strategy     | Value | Behavior |
|-------------|-------|----------|
| `PROVE_NONE` | 0x21 | Never generate proofs |
| `PROVE_APP`  | 0x22 | Application decides |
| `PROVE_ALL`  | 0x23 | Auto-prove all packets |

### Request Policies
| Policy       | Value | Behavior |
|-------------|-------|----------|
| `ALLOW_NONE` | 0x00 | Reject all requests |
| `ALLOW_ALL`  | 0x01 | Accept all requests |
| `ALLOW_LIST` | 0x02 | Accept from identified peers in list |

---

## Announce Protocol

Source: `RNS/Destination.py`, `RNS/Identity.py`

### Announce Packet (without ratchet, context_flag=0)
```
Packet Type: ANNOUNCE (0x01)
Destination Type: SINGLE (0x00)

Data payload:
  Offset 0-63:   Identity Public Key (64 bytes: 32 X25519 + 32 Ed25519)
  Offset 64-73:  Name Hash (10 bytes)
  Offset 74-83:  Random Hash (10 bytes)
  Offset 84-147: Ed25519 Signature (64 bytes)
  Offset 148+:   App Data (optional, variable)
```

### Announce Packet (with ratchet, context_flag=1)
```
Data payload:
  Offset 0-63:   Identity Public Key (64 bytes)
  Offset 64-73:  Name Hash (10 bytes)
  Offset 74-83:  Random Hash (10 bytes)
  Offset 84-115: Ratchet Public Key (32 bytes)
  Offset 116-179: Ed25519 Signature (64 bytes)
  Offset 180+:   App Data (optional, variable)
```

### Random Hash Construction
```python
random_hash = os.urandom(5) + int(time.time()).to_bytes(5, "big")
```

### Announce Signature
```python
# Without ratchet:
signed_data = destination_hash + public_key + name_hash + random_hash + app_data
signature = identity.sign(signed_data)

# With ratchet:
signed_data = destination_hash + public_key + name_hash + random_hash + ratchet_pub + app_data
signature = identity.sign(signed_data)
```

### Announce Validation
```python
RNS.Identity.validate_announce(packet)  # Returns True/False
```

### Ratchet Management
- `RATCHET_COUNT = 512` retained ratchets per destination
- `RATCHET_INTERVAL = 1800` seconds (30 min) between rotations
- `RATCHET_EXPIRY = 2592000` seconds (30 days)
- Ratchets are X25519 private keys (32 bytes each)
- Ratchet ID = `SHA256(ratchet_public_key)[0:10]`

---

## Link Establishment Protocol

Source: `RNS/Link.py`

### Link States
| State       | Value | Description |
|------------|-------|-------------|
| `PENDING`   | 0x00 | Awaiting response |
| `HANDSHAKE` | 0x01 | Proof exchanged, key derived |
| `ACTIVE`    | 0x02 | Fully established |
| `STALE`     | 0x03 | Keepalive timeout approaching |
| `CLOSED`    | 0x04 | Terminated |

### Encryption Modes
| Mode             | Value | Status |
|-----------------|-------|--------|
| `MODE_AES128_CBC` | 0x00 | DISABLED (raises TypeError) |
| `MODE_AES256_CBC` | 0x01 | Default and only enabled mode |
| `MODE_AES256_GCM` | 0x02 | Reserved, not yet implemented |

### Three-Packet Handshake

**Packet 1: LINKREQUEST (Initiator -> Responder)**
```
Packet Type: LINKREQUEST (0x02)
Destination: Target destination hash

Data:
  Offset 0-31:  Ephemeral X25519 Public Key (32 bytes)
  Offset 32-63: Ephemeral Ed25519 Signing Key (32 bytes)
  Offset 64-66: [OPTIONAL] MTU Signalling (3 bytes)
```

Link ID derivation:
```python
link_id = truncated_hash(packet.get_hashable_part())[0:16]
```

**Packet 2: LRPROOF (Responder -> Initiator)**
```
Packet Type: PROOF (0x03), Context: LRPROOF (0xFF)
Destination: Link ID

Data:
  Offset 0-63:  Ed25519 Signature (64 bytes)
  Offset 64-95: Responder X25519 Public Key (32 bytes)
  Offset 96-98: [OPTIONAL] MTU Signalling (3 bytes)

Signature covers:
  signed_data = link_id + responder_pub + responder_sig_pub + [signalling_bytes]
```

**Packet 3: LRRTT (Initiator -> Responder)**
```
Packet Type: DATA (0x00), Context: LRRTT (0xFE)
Destination: Link ID
Encrypted: Yes (with derived link key)

Data: umsgpack.packb(measured_rtt_float)
```

### Key Derivation for Links
```python
shared_secret = X25519_DH(initiator_ephemeral_prv, responder_pub)

# For MODE_AES256_CBC:
derived_key = HKDF(
    length=64,
    derive_from=shared_secret,
    salt=link_id,
    context=None
)

link_token = Token(derived_key)  # AES-256-CBC encryption with HMAC-SHA256
```

### MTU Signalling (3 bytes)
```python
signalling_bytes = struct.pack(">I", (mtu & 0x1FFFFF) + (((mode << 5) & 0xE0) << 16))[1:]
# Byte 0: (mode << 5) | (mtu >> 16)
# Byte 1: (mtu >> 8) & 0xFF
# Byte 2: mtu & 0xFF
```

### Keepalive Protocol
```
Keepalive interval = max(min(rtt * (360 / 1.75), 360), 5) seconds
Stale time = keepalive_interval * 2

Keepalive packet:
  Type: DATA (0x00), Context: KEEPALIVE (0xFA)
  Data: bytes([0xFF]) or bytes([0xFE])
  Encrypted with link Token
```

### Link Teardown
```
Type: DATA, Context: LINKCLOSE (0xFC)
Encrypted with link Token
```

### Link Identification
```
Type: DATA, Context: LINKIDENTIFY (0xFB)
Data: identity_public_key + identity.sign(link_id)
Encrypted with link Token
```

---

## Packet Delivery and Proofs

### Packet Hash
```python
packet_hash = SHA256(packet.get_hashable_part())
# hashable_part = raw packet bytes excluding hops field and transport-specific headers
```

### Delivery Proof
When proof strategy is `PROVE_ALL`:
```python
proof_data = packet_hash + identity.sign(packet_hash)  # 32 + 64 = 96 bytes
```

### Receipt States
| State       | Description |
|------------|-------------|
| `SENT`      | Packet transmitted |
| `DELIVERED` | Proof received |
| `FAILED`    | Timeout or error |

---

## Resource Transfer Protocol

Source: `RNS/Resource.py`

### Resource States
| State            | Value | Description |
|-----------------|-------|-------------|
| `NONE`           | 0x00 | Not initialized |
| `QUEUED`         | 0x01 | Waiting to start |
| `ADVERTISED`     | 0x02 | Advertisement sent |
| `TRANSFERRING`   | 0x03 | Data transfer in progress |
| `AWAITING_PROOF` | 0x04 | Transfer complete, awaiting verification |
| `ASSEMBLING`     | 0x05 | Reassembling parts |
| `COMPLETE`       | 0x06 | Successfully transferred |
| `FAILED`         | 0x07 | Transfer failed |
| `CORRUPT`        | 0x08 | Data integrity failure |

### Resource Advertisement Format (msgpack dictionary)
```python
{
    "t": transfer_size,     # int: total bytes to transfer
    "d": data_size,         # int: original data size
    "n": num_parts,         # int: number of parts
    "h": resource_hash,     # bytes(32): SHA-256 of resource
    "r": random_hash,       # bytes(4): random identifier
    "o": original_hash,     # bytes(32): hash of first segment
    "i": segment_index,     # int: segment index (for split resources)
    "l": total_segments,    # int: total segment count
    "q": request_id,        # bytes or None: associated request ID
    "f": flags,             # int: resource flags
    "m": hashmap,           # bytes: part hash map
}
```

### Resource Flags
```
Bit 0 (0x01): Encrypted
Bit 1 (0x02): Compressed
Bit 2 (0x04): Split across segments
Bit 3 (0x08): Is request
Bit 4 (0x10): Is response
Bit 5 (0x20): Has metadata
```

### Hashmap
- 4 bytes per entry: `SHA256(part_data + random_hash)[0:4]`
- Maximum entries per advertisement: `floor((Link.MDU - 134) / 4)`
- `HASHMAP_IS_NOT_EXHAUSTED = 0x00` (first byte of hashmap update)
- `HASHMAP_IS_EXHAUSTED = 0xFF` (first byte when no more parts)

### Windowing
| Parameter            | Value |
|---------------------|-------|
| Initial window       | 4 parts |
| `WINDOW_MIN`         | 2 parts |
| `WINDOW_MAX_FAST`    | 75 parts (> 50 Kbps) |
| `WINDOW_MAX_SLOW`    | 10 parts (< 50 Kbps) |
| `WINDOW_MAX_VERY_SLOW` | 4 parts (< 2 Kbps) |
| `WINDOW_FLEXIBILITY` | 4 |
| `RATE_FAST`          | 6250 bytes/sec (50 Kbps) |
| `RATE_VERY_SLOW`     | 250 bytes/sec (2 Kbps) |

### Resource Constants
| Constant              | Value |
|----------------------|-------|
| `MAPHASH_LEN`         | 4 bytes |
| `RANDOM_HASH_SIZE`    | 4 bytes |
| `MAX_EFFICIENT_SIZE`  | 1 MB - 1 |
| `METADATA_MAX_SIZE`   | 16 MB - 1 |
| `AUTO_COMPRESS_MAX_SIZE` | 64 MB |
| `MAX_RETRIES`         | 16 |
| `MAX_ADV_RETRIES`     | 4 |

### Resource Proof Format
```
resource_proof = SHA256(assembled_data + resource_hash)  # 32 bytes
```

### Metadata Format
```
[3 bytes: big-endian size prefix]
[variable: msgpack-encoded metadata dictionary]
```

---

## Channel Protocol

Source: `RNS/Channel.py`

### Message Envelope Format (over link)
```
Offset 0-1:  Message Type (2 bytes, big-endian)
Offset 2-3:  Sequence Number (2 bytes, big-endian)
Offset 4-5:  Payload Length (2 bytes, big-endian)
Offset 6+:   Packed Message Data (variable)
```

Total overhead: 6 bytes

### Sequence Numbers
- Range: 0 to 65535 (`SEQ_MAX = 0xFFFF`)
- Modulus: 65536 (`SEQ_MODULUS = 0x10000`)
- Wraps around after 65535

### Message Type Ranges
- `0x0000 - 0xefff`: User message types
- `0xf000 - 0xffff`: System reserved
- `0xff00`: `SMT_STREAM_DATA` (used by Buffer protocol)

### Window Control
| Condition | Window Max |
|-----------|-----------|
| RTT < 0.18s (fast) | 48 messages |
| RTT < 0.75s (medium) | 12 messages |
| RTT < 1.45s (slow) | 5 messages |
| RTT >= 1.45s | 1 message |

- Window adaptation: +1 on delivery, -1 on timeout
- After 10 fast deliveries: upgrade window_max

### Channel Exception Types
| Type                  | Value |
|----------------------|-------|
| `ME_NO_MSG_TYPE`      | 0 |
| `ME_INVALID_MSG_TYPE` | 1 |
| `ME_NOT_REGISTERED`   | 2 |
| `ME_LINK_NOT_READY`   | 3 |
| `ME_ALREADY_SENT`     | 4 |
| `ME_TOO_BIG`          | 5 |

### Retry Behavior
- Maximum 5 retries per message (channel level)
- Timeout increases with each retry
- On final failure: message state -> `MSGSTATE_FAILED`

---

## Buffer Protocol

Source: `RNS/Buffer.py`

### Stream Data Message Header (2 bytes)
```
Bit 15:   EOF flag (0x8000)
Bit 14:   Compression flag (0x4000)
Bits 13-0: Stream ID (0x3fff mask)
```

### Constants
| Constant          | Value |
|-------------------|-------|
| `STREAM_ID_MAX`   | 16383 (0x3fff) |
| `OVERHEAD`        | 8 bytes (2 stream header + 6 channel envelope) |
| `MAX_CHUNK_LEN`   | 65536 (64 KB) |
| `COMPRESSION_TRIES` | 4 |

### Buffer Types
- `RNS.Buffer.create_bidirectional_buffer(rx_stream_id, tx_stream_id, channel, callback)` - Full duplex
- `RNS.Buffer.create_reader(stream_id, channel)` - Read-only stream
- `RNS.Buffer.create_writer(stream_id, channel)` - Write-only stream

### Compression
- Uses bz2 compression
- Attempted 4 times with decreasing segment sizes
- Only applied if compressed size < uncompressed size

---

## Request/Response Protocol

Source: `RNS/Destination.py`, `RNS/Link.py`

### Request Format (over link, encrypted)
```
Packet Type: DATA, Context: REQUEST (0x09)
Data: umsgpack.packb([timestamp, path_hash, request_data])
```

### Response Format (over link, encrypted)
```
Packet Type: DATA, Context: RESPONSE (0x0A)
Data: umsgpack.packb([request_id, response_data])
```

### Request Handler Registration
```python
destination.register_request_handler(
    "/path/name",
    response_generator=callback,
    allow=RNS.Destination.ALLOW_ALL  # or ALLOW_NONE, ALLOW_LIST
)

# Callback signature:
def response_generator(path, data, request_id, link_id, remote_identity, requested_at):
    return response_data
```

---

## Transport and Routing

Source: `RNS/Transport.py`

### Transport Types
| Type        | Value | Description |
|------------|-------|-------------|
| `BROADCAST` | 0x00 | Broadcast to all |
| `TRANSPORT` | 0x01 | Routed via transport |
| `RELAY`     | 0x02 | Relayed packet |
| `TUNNEL`    | 0x03 | Tunneled packet |

### Path Discovery
```python
RNS.Transport.has_path(destination_hash)     # Check if path known
RNS.Transport.request_path(destination_hash) # Request path discovery
```

### Announce Propagation Rules
- Max hops: 128 (`PATHFINDER_M`)
- Retransmit retries: 1 (`PATHFINDER_R`)
- Grace period: 5 seconds (`PATHFINDER_G`)
- Random rebroadcast window: 0.5 seconds (`PATHFINDER_RW`)
- Local rebroadcasts max: 2
- Announce bandwidth cap: 2% of interface bandwidth
- PLAIN/GROUP packets limited to 1 hop

### Interface Access Code (IFAC)
- Optional per-interface authentication
- Flag: `0x80` in first byte
- IFAC bytes appended to packet, verified on ingress
- Calculated: `sign(packet)[-ifac_size:]`
- Salt: `"adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8"`

### Packet Deduplication
- Maintains hashlist of seen packet hashes
- Max size: 1,000,000 entries
- Culled at 50% capacity (creates new set)

---

## Interface Layer

Source: `RNS/Interfaces/Interface.py`

### Interface Modes
| Mode              | Value | Description |
|-------------------|-------|-------------|
| `MODE_FULL`        | 0x01 | Full routing |
| `MODE_POINT_TO_POINT` | 0x02 | Direct connection |
| `MODE_ACCESS_POINT`   | 0x03 | Access point |
| `MODE_ROAMING`        | 0x04 | Mobile/roaming |
| `MODE_BOUNDARY`       | 0x05 | Network boundary |
| `MODE_GATEWAY`        | 0x06 | Gateway |

### Key Interface Types for Testing

**TCPInterface** (`RNS/Interfaces/TCPInterface.py`):
- HDLC or KISS framing
- HW_MTU: 262144 bytes
- Bitrate guess: 10 Mbps
- IFAC_SIZE: 16 bytes
- Reconnect wait: 5 seconds
- KISS framing: FEND=0xC0, FESC=0xDB, TFEND=0xDC, TFESC=0xDD

**UDPInterface** (`RNS/Interfaces/UDPInterface.py`):
- HW_MTU: 1064 bytes
- UDP broadcast support
- Bitrate guess: 10 Mbps

**AutoInterface** (`RNS/Interfaces/AutoInterface.py`):
- IPv6 multicast peer discovery
- Default discovery port: 29716
- Default data port: 42671
- Default group: "reticulum"
- Peering timeout: 22 seconds
- HW_MTU: 1196 bytes

**LocalInterface** (`RNS/Interfaces/LocalInterface.py`):
- IPC via Unix socket or TCP
- HW_MTU: 262144 bytes
- HDLC framing: FLAG=0x7E, ESC=0x7D, ESC_MASK=0x20
- Reconnect wait: 8 seconds

---

## Known Test Vectors

Source: `tests/identity.py`, `tests/link.py`

### Fixed Identity Keys
These key pairs can be used for deterministic testing:

```python
fixed_keys = [
    # (private_key_hex, identity_hash_hex)
    ("f8953ffaf607627e615603ff1530c82c434cf87c07179dd7689ea776f30b964cfb7ba6164af00c5111a45e69e57d885e1285f8dbfe3a21e95ae17cf676b0f8b7",
     "650b5d76b6bec0390d1f8cfca5bd33f9"),

    ("d85d036245436a3c33d3228affae06721f8203bc364ee0ee7556368ac62add650ebf8f926abf628da9d92baaa12db89bd6516ee92ec29765f3afafcb8622d697",
     "1469e89450c361b253aefb0c606b6111"),

    ("8893e2bfd30fc08455997caf7abb7a6341716768dbbf9a91cc1455bd7eeaf74cdc10ec72a4d4179696040bac620ee97ebc861e2443e5270537ae766d91b58181",
     "e5fe93ee4acba095b3b9b6541515ed3e"),

    ("b82c7a4f047561d974de7e38538281d7f005d3663615f30d9663bad35a716063c931672cd452175d55bcdd70bb7aa35a9706872a97963dc52029938ea7341b39",
     "1333b911fa8ebb16726996adbe3c6262"),

    ("08bb35f92b06a0832991165a0d9b4fd91af7b7765ce4572aa6222070b11b767092b61b0fd18b3a59cae6deb9db6d4bfb1c7fcfe076cfd66eea7ddd5f877543b9",
     "d13712efc45ef87674fb5ac26c37c912"),
]
```

### Known Destination Hash
Using `fixed_keys[0]` with app name `"rns_unit_tests"` and aspects `"link", "establish"`:
```
Destination hash: fb48da0e82e6e01ba0c014513f74540d
```

### Known Signature
Message: the string stored in `signed_message` variable in `tests/identity.py`
Key: `fixed_keys[0]`
Signature: `3020ef58f861591826a61c3d2d4a25b949cdb3094085ba6b1177a6f2a05f3cdd24d1095d6fdd078f0b2826e80b261c93c1ff97fbfd4857f25706d57dd073590c`

### Known Encryption Token
Key: `fixed_keys[0]`
Plaintext (hex): `71884a271ead43558fcf1e331c5aebcd43498f16da16f8056b0893ce6b15d521eaa4f31639cd34da1b57995944076c4f14f300f2d2612111d21a3429a9966ac1da68545c00c7887d8b26f6c1ab9defa020b9519849ca41b7904199882802b6542771df85144a79890289d3c02daef6c26652c5ce9de231a2`
Ciphertext (hex): `e37705f9b432d3711acf028678b0b9d37fdf7e00a3b47c95251aad61447df2620b5b9978783c3d9f2fb762e68c8b57c554928fb70dd79c1033ce5865f91761aad3e992790f63456092cb69b7b045f539147f7ba10d480e300f193576ae2d75a7884809b76bd17e05a735383305c0aa5621395bbf51e8cc66c1c536f339f2bea600f08f8f9a76564b2522cd904b6c2b6e553ec3d4df718ae70434c734297b313539338d184d2c64a9c4ddbc9b9a4947d0b45f5a274f65ae9f6bb203562fd5cede6abd3c615b699156e08fa33b841647a0`

---

## Test Categories and Strategy

### Category 1: Cryptographic Primitives (Offline Tests)
No network required. Test your crypto implementations against known vectors.

- [ ] **SHA-256 hashing** - Test against standard vectors and empty/large inputs
- [ ] **SHA-512 hashing** - Same
- [ ] **X25519 key generation** - Valid key pairs
- [ ] **X25519 ECDH** - Shared secret derivation
- [ ] **Ed25519 signing** - Deterministic signatures from known keys
- [ ] **Ed25519 verification** - Verify known signatures
- [ ] **AES-256-CBC encrypt/decrypt** - With PKCS7 padding
- [ ] **HMAC-SHA256** - Known input/output pairs
- [ ] **HKDF-SHA256** - Key derivation with known inputs
- [ ] **Token encrypt/decrypt** - Modified Fernet format (no version/timestamp)
- [ ] **Identity hash derivation** - From public key to 16-byte truncated hash
- [ ] **Destination hash derivation** - From name_hash + identity_hash

### Category 2: Identity and Addressing (Offline Tests)
- [ ] **Identity creation from bytes** - Using fixed_keys test vectors
- [ ] **Identity hash matches expected** - Verify all 5 fixed key hashes
- [ ] **Destination hash computation** - Known app_name + aspects + identity
- [ ] **Name hash computation** - SHA256 of app name string, truncated to 10 bytes
- [ ] **Signature generation** - Matches known signature from test vectors
- [ ] **Signature verification** - Valid and invalid signatures
- [ ] **Encryption/decryption round-trip** - Using identity public/private keys
- [ ] **Known token decryption** - Decrypt the fixed_token test vector

### Category 3: Packet Construction (Offline Tests)
- [ ] **Header construction** - Correct flag byte encoding for all type combinations
- [ ] **HEADER_1 format** - Correct offsets and sizes
- [ ] **HEADER_2 format** - With transport ID
- [ ] **Packet size limits** - Enforce MTU of 500 bytes
- [ ] **MDU calculation** - Different for PLAIN, ENCRYPTED, LINK packets
- [ ] **Packet hash computation** - Deterministic hashing

### Category 4: Announce Protocol (Network Tests)
Run against live Reticulum instance.

- [ ] **Valid announce creation and validation** - Announce + verify signature
- [ ] **Invalid announce rejection** - Tampered destination hash
- [ ] **Announce with app data** - Arbitrary payload attached
- [ ] **Announce with ratchet** - Context flag set, ratchet key included
- [ ] **Announce propagation** - Multi-hop announce forwarding
- [ ] **Announce handler callback** - Correct aspect_filter matching
- [ ] **Announce rate limiting** - 2% bandwidth cap enforcement

### Category 5: Link Establishment (Network Tests)
- [ ] **Default mode link** - AES-256-CBC establishment
- [ ] **AES-128-CBC rejection** - Should raise TypeError
- [ ] **Explicit AES-256-CBC mode** - Same as default but explicitly requested
- [ ] **Link state transitions** - PENDING -> ACTIVE -> CLOSED
- [ ] **Link teardown** - Graceful close from either side
- [ ] **Link keepalive** - Automatic heartbeat timing
- [ ] **Link stale detection** - After missed keepalives
- [ ] **Link identification** - Remote identity verification
- [ ] **MTU signalling** - Negotiate link MTU via 3-byte field
- [ ] **RTT measurement** - LRRTT packet exchange

### Category 6: Data Transfer (Network Tests)
- [ ] **Single packet send/receive** - Within MDU
- [ ] **Packet proof delivery** - Automatic with PROVE_ALL
- [ ] **Multiple packet burst** - 50-500 packets in succession
- [ ] **Packet receipt timeout** - Delivery confirmation timing

### Category 7: Resource Transfer (Network Tests)
- [ ] **Micro resource** (128 bytes) - Single-part transfer
- [ ] **Mini resource** (256 KB) - Multi-part transfer
- [ ] **Small resource** (1 MB) - With windowing
- [ ] **Medium resource** (5 MB) - Full windowing and rate adaptation
- [ ] **Large resource** (50 MB) - Sustained transfer
- [ ] **Resource with metadata** - Dictionary metadata attached
- [ ] **Invalid metadata size** - Exceeds METADATA_MAX_SIZE (should raise SystemError)
- [ ] **Resource compression** - Auto-compress behavior
- [ ] **Resource integrity** - Hash verification on completion

### Category 8: Channel Protocol (Network Tests)
- [ ] **Message send and receive** - Custom MessageBase subclass
- [ ] **Message round-trip** - Send, process, respond
- [ ] **Message handler chaining** - Multiple handlers, short-circuit on True
- [ ] **System message type rejection** - Types >= 0xf000
- [ ] **Sequence number handling** - Ordering and deduplication
- [ ] **Channel retry behavior** - Timeout and retry up to 5 times
- [ ] **Channel window adaptation** - Based on RTT

### Category 9: Buffer Protocol (Network Tests)
- [ ] **Small buffer write/read** - Simple string round-trip
- [ ] **Large buffer transfer** (32 KB+) - Multi-packet streaming
- [ ] **Buffer with compression** - bz2 compression of stream data
- [ ] **Buffer EOF signaling** - Stream close detection
- [ ] **Bidirectional buffer** - Simultaneous read/write
- [ ] **Slow link buffer** - Low bitrate (410 bps) transfer

### Category 10: Request/Response (Network Tests)
- [ ] **Register and invoke request handler** - Path-based routing
- [ ] **Request with data payload** - Non-null request data
- [ ] **Response callback** - Async response handling
- [ ] **Request failure callback** - Timeout or error
- [ ] **Request policy enforcement** - ALLOW_NONE, ALLOW_ALL, ALLOW_LIST

### Category 11: Path Discovery (Network Tests)
- [ ] **Path request** - Request path to unknown destination
- [ ] **Path response** - Receive and cache path info
- [ ] **Path expiration** - TTL enforcement
- [ ] **Multi-hop routing** - Through transport nodes

### Category 12: Cross-Implementation Interoperability
The most critical test category for your use case.

- [ ] **Reference -> Alternative announce** - Announce from ref, receive on alt
- [ ] **Alternative -> Reference announce** - Announce from alt, receive on ref
- [ ] **Cross-implementation link** - Link from one impl to the other
- [ ] **Cross-implementation packet exchange** - Data over cross-impl link
- [ ] **Cross-implementation resource transfer** - Large data both directions
- [ ] **Cross-implementation channel/buffer** - Message and stream protocols
- [ ] **Cross-implementation request/response** - RPC pattern across impls
- [ ] **Shared network topology** - Both impls in same routed network

---

## Docker Deployment Guide

The reference implementation does not include Docker files. Here's how to containerize it:

### Minimal Dockerfile for Reference Implementation
```dockerfile
FROM python:3.11-slim

RUN pip install rns

# Create config directory
RUN mkdir -p /etc/reticulum

# Copy configuration
COPY config /etc/reticulum/config

# Expose ports for TCP interface
EXPOSE 4242

# Run daemon
CMD ["rnsd", "--config", "/etc/reticulum", "-vvv"]
```

### Test Configuration for Docker
```ini
[reticulum]
  enable_transport = yes
  share_instance = yes
  shared_instance_port = 37428
  instance_control_port = 37429
  panic_on_interface_error = no

[logging]
  loglevel = 7

[interfaces]
  [[Default Interface]]
    type = TCPServerInterface
    listen_ip = 0.0.0.0
    listen_port = 4242
    interface_enabled = true
```

### Docker Compose for Two Implementations
```yaml
version: '3.8'
services:
  reference:
    build:
      context: ./reference
    ports:
      - "4242:4242"
      - "37428:37428"
    volumes:
      - ref-storage:/root/.reticulum

  alternative:
    build:
      context: ./alternative
    ports:
      - "4243:4242"
      - "37429:37428"
    volumes:
      - alt-storage:/root/.reticulum

  test-runner:
    build:
      context: ./tests
    depends_on:
      - reference
      - alternative
    environment:
      - REF_HOST=reference
      - REF_PORT=4242
      - ALT_HOST=alternative
      - ALT_PORT=4242

volumes:
  ref-storage:
  alt-storage:
```

---

## API Quick Reference

### Initialization
```python
import RNS
reticulum = RNS.Reticulum(configdir=None)
```

### Identity
```python
identity = RNS.Identity()                          # Generate new
identity = RNS.Identity.from_bytes(key_bytes)      # From 64-byte key
identity.hash                                       # 16-byte hash
identity.get_public_key()                           # 64-byte public key
identity.get_private_key()                          # 64-byte private key
identity.sign(data) -> bytes                        # 64-byte signature
identity.validate(signature, data) -> bool          # Verify signature
identity.encrypt(plaintext) -> bytes                # Encrypt to this identity
identity.decrypt(ciphertext) -> bytes               # Decrypt with this identity
RNS.Identity.recall(dest_hash) -> Identity|None     # Lookup known identity
RNS.Identity.validate_announce(packet) -> bool      # Validate announce
```

### Destination
```python
dest = RNS.Destination(identity, direction, type, app_name, *aspects)
dest.hash                                           # 16-byte destination hash
dest.hexhash                                        # Hex string of hash
dest.announce(app_data=None)                        # Send announce
dest.set_proof_strategy(strategy)                   # PROVE_NONE/APP/ALL
dest.set_packet_callback(callback)                  # On packet received
dest.set_link_established_callback(callback)        # On link established
dest.register_request_handler(path, response_generator, allow)
dest.enable_ratchets(storage_path)                  # Enable forward secrecy
```

### Link
```python
link = RNS.Link(destination, mode=None)             # Establish link
link.status                                         # PENDING/ACTIVE/STALE/CLOSED
link.mode                                           # Encryption mode
link.rtt                                            # Round-trip time
link.MDU                                            # Max data unit for this link
link.derived_key                                    # Shared encryption key
link.teardown()                                     # Close link
link.identify(identity)                             # Identify to remote
link.request(path, data, response_callback, failed_callback)
link.get_channel()                                  # Get Channel object
link.set_link_established_callback(callback)
link.set_link_closed_callback(callback)
link.set_packet_callback(callback)
link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
link.set_resource_started_callback(callback)
link.set_resource_concluded_callback(callback)
link.get_remote_identity()                          # After identification
```

### Packet
```python
packet = RNS.Packet(destination_or_link, data, create_receipt=True)
receipt = packet.send()                             # Returns PacketReceipt
receipt.status                                      # SENT/DELIVERED/FAILED
receipt.get_rtt()                                   # RTT in seconds
receipt.set_timeout(seconds)
receipt.set_timeout_callback(callback)
receipt.set_delivery_callback(callback)
```

### Resource
```python
resource = RNS.Resource(data, link, callback=None, progress_callback=None,
                        timeout=120, metadata=None, auto_compress=True)
resource.status                                     # QUEUED through COMPLETE/FAILED
resource.total_size                                 # Total bytes
```

### Channel
```python
channel = link.get_channel()
channel.register_message_type(MessageClass)
channel.add_message_handler(callback)               # Returns True to stop propagation
channel.send(message)
channel.is_ready_to_send()
channel.mdu                                         # Max packed message size
```

### Buffer
```python
buffer = RNS.Buffer.create_bidirectional_buffer(rx_id, tx_id, channel, callback)
buffer.write(data)
buffer.read(num_bytes)
buffer.flush()
buffer.close()
```

### Transport
```python
RNS.Transport.has_path(destination_hash) -> bool
RNS.Transport.request_path(destination_hash)
RNS.Transport.register_destination(destination)
RNS.Transport.register_announce_handler(handler)
```

### Logging
```python
RNS.loglevel = RNS.LOG_DEBUG  # 0=CRITICAL to 7=EXTREME, -1=NONE
RNS.log("message", RNS.LOG_INFO)
```

---

## Key Source Files

Reference these files for protocol details and behavioral specifications:

| File | Purpose | Key Details |
|------|---------|-------------|
| `RNS/Reticulum.py` | Core system, constants | MTU, hash lengths, timing, config |
| `RNS/Identity.py` | Crypto identity | Key generation, sign/verify, encrypt/decrypt |
| `RNS/Destination.py` | Addressing | Hash derivation, announce format, proof strategies |
| `RNS/Packet.py` | Wire format | Header layout, packet types, contexts |
| `RNS/Link.py` | Link protocol | Handshake, keepalive, encryption modes |
| `RNS/Transport.py` | Routing | Path tables, announce propagation, IFAC |
| `RNS/Resource.py` | Large transfers | Windowing, segmentation, hashmap |
| `RNS/Channel.py` | Message protocol | Envelope format, sequencing, flow control |
| `RNS/Buffer.py` | Stream protocol | Stream IDs, compression, EOF |
| `RNS/Cryptography/Token.py` | Encryption | Modified Fernet (no version/timestamp) |
| `RNS/Cryptography/HKDF.py` | Key derivation | HKDF-SHA256 implementation |
| `RNS/Cryptography/Provider.py` | Crypto backend | PyCA vs internal selection |
| `RNS/Interfaces/Interface.py` | Interface base | Modes, IFAC, statistics |
| `RNS/Interfaces/TCPInterface.py` | TCP transport | Framing, reconnection |
| `RNS/Interfaces/LocalInterface.py` | IPC | Shared instance protocol |
| `RNS/vendor/umsgpack.py` | Serialization | MessagePack v2.7.1 |
| `tests/identity.py` | Test vectors | Known keys, signatures, ciphertexts |
| `tests/link.py` | Integration tests | Link, resource, channel, buffer tests |
| `tests/channel.py` | Channel tests | Message types, handlers, buffers |
| `Examples/*.py` | Usage patterns | All major API usage examples |

### Serialization
All structured data uses **MessagePack** (`umsgpack` v2.7.1, MIT license, bundled in `RNS/vendor/umsgpack.py`).
