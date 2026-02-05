# Reticulum Reference Implementation

> **WARNING: DO NOT MODIFY ANY PYTHON CODE IN THIS REPOSITORY.**
> This is the reference implementation of the Reticulum networking stack (v1.1.3).
> It is the source of truth. If a test fails against this implementation, the test is wrong.
> All test infrastructure must be out-of-band (separate project/repository).

## What is Reticulum?
- Cryptography-based networking stack, does NOT rely on IP
- Cryptographic addressing: destination hashes derived from X25519+Ed25519 identity keys
- All communication encrypted by default; fully decentralized, no central authority
- Supports 5 bps to 500 Mbps over heterogeneous mediums (TCP, UDP, serial, LoRa, I2P)

## Running Tests
```bash
make test                # or:
python3 -m tests.all
```

## Key Constants
| Constant | Value |
|----------|-------|
| `MTU` | 500 bytes |
| `TRUNCATED_HASHLENGTH` | 128 bits (16 bytes) |
| `HASHLENGTH` | 256 bits (32 bytes) |
| `KEYSIZE` | 512 bits (64 bytes: 32 X25519 + 32 Ed25519) |
| `SIGLENGTH` | 64 bytes |
| `NAME_HASH_LENGTH` | 10 bytes |
| `TOKEN_OVERHEAD` | 48 bytes (16 IV + 32 HMAC) |
| `HEADER_MINSIZE` | 19 bytes |
| `HEADER_MAXSIZE` | 37 bytes |
| `MDU` | 462 bytes |

## Key Source Files
| File | Purpose |
|------|---------|
| `RNS/Reticulum.py` | Core system, constants, config |
| `RNS/Identity.py` | Key generation, sign/verify, encrypt/decrypt |
| `RNS/Destination.py` | Hash derivation, announce format, proof strategies |
| `RNS/Packet.py` | Wire format, header layout, packet types |
| `RNS/Link.py` | Handshake, keepalive, encryption modes |
| `RNS/Transport.py` | Routing, path tables, announce propagation |
| `RNS/Resource.py` | Large transfers, windowing, segmentation |
| `RNS/Channel.py` | Message envelope, sequencing, flow control |
| `RNS/Buffer.py` | Stream protocol, compression, EOF |
| `RNS/Cryptography/Token.py` | Modified Fernet (no version/timestamp) |
| `RNS/Cryptography/HKDF.py` | HKDF-SHA256 key derivation |
| `RNS/vendor/umsgpack.py` | MessagePack v2.7.1 serialization |
| `tests/identity.py` | Test vectors: known keys, signatures, ciphertexts |
| `tests/link.py` | Integration tests: link, resource, channel, buffer |

## Detailed Specifications
See **[TESTING_PLAN.md](TESTING_PLAN.md)** for complete protocol documentation:
- Wire formats and packet structure
- Cryptographic primitives and algorithms
- Announce, Link, Resource, Channel, Buffer protocols
- Known test vectors (fixed keys, signatures, ciphertexts)
- All 12 test categories with checklists
- Docker deployment guide
- Full API reference
