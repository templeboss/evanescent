# Evanescent — Engineering Standards

**All agents and contributors must read this document before writing any code.**

This document is the single source of truth for every interface boundary in the system. Its purpose is to prevent mismatches between the Go backend and the Android client. When in doubt, this file wins.

---

## Table of Contents

1. [Cryptographic Primitives](#1-cryptographic-primitives)
2. [X3DH Protocol Parameters](#2-x3dh-protocol-parameters)
3. [Double Ratchet Parameters](#3-double-ratchet-parameters)
4. [Sealed Sender](#4-sealed-sender)
5. [Wire Format](#5-wire-format)
6. [Encoding Conventions](#6-encoding-conventions)
7. [WebSocket Protocol (Android ↔ Provider)](#7-websocket-protocol-android--provider)
8. [Identity and Addressing](#8-identity-and-addressing)
9. [Key Sizes and Formats](#9-key-sizes-and-formats)
10. [Nym Integration](#10-nym-integration)
11. [Tor Integration](#11-tor-integration)
12. [Cover Traffic Parameters](#12-cover-traffic-parameters)
13. [Storage Standards](#13-storage-standards)
14. [Error Handling](#14-error-handling)
15. [Naming Conventions](#15-naming-conventions)
16. [Versioning](#16-versioning)
17. [Testing Requirements](#17-testing-requirements)

---

## 1. Cryptographic Primitives

These are fixed. There is no negotiation. There are no alternatives.

| Purpose | Algorithm | Notes |
|---|---|---|
| Identity signing | Ed25519 | RFC 8032 |
| Key agreement (X3DH, DR) | X25519 | RFC 7748 |
| Symmetric encryption | ChaCha20-Poly1305 | RFC 8439, 32-byte key, 12-byte nonce |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| Hashing | SHA-256 | For HKDF, fingerprints |
| Mailbox address derivation | BLAKE3 | 32-byte output, truncated to 32 bytes |
| Random number generation | OS CSPRNG only | `crypto/rand` in Go, `SecureRandom` in Android |

**Never use:**
- RSA (any use)
- AES-CBC or AES-ECB
- SHA-1 or MD5
- ECDSA with P-256 (use Ed25519)
- Any algorithm not in the table above

---

## 2. X3DH Protocol Parameters

Follow the Signal X3DH specification exactly: https://signal.org/docs/specifications/x3dh/

### Key Types

```
IK  — Identity Key:      Ed25519 keypair
IK' — Identity Key (DH): X25519 keypair derived from IK via clamping
SPK — Signed Prekey:     X25519 keypair, signed by IK (Ed25519)
OPK — One-Time Prekey:   X25519 keypair
EK  — Ephemeral Key:     X25519 keypair, generated fresh per session
```

**Ed25519 → X25519 conversion** (for IK' used in DH):
- Take the Ed25519 private scalar, apply SHA-512, clamp bytes [0:32] per RFC 8032 §5.1.5
- Take the Ed25519 public key, convert to Montgomery form per RFC 7748 §4.1
- Use the Golang `filippo.io/edwards25519` library for this conversion; do not implement it manually

### Prekey Bundle (published by each user's provider)

```protobuf
// Defined in proto/prekeys.proto
message PreKeyBundle {
  bytes identity_key       = 1;  // Ed25519 pubkey, 32 bytes
  uint32 signed_prekey_id  = 2;
  bytes signed_prekey      = 3;  // X25519 pubkey, 32 bytes
  bytes signed_prekey_sig  = 4;  // Ed25519 signature over signed_prekey, 64 bytes
  uint32 one_time_prekey_id = 5; // absent if exhausted
  bytes one_time_prekey    = 6;  // X25519 pubkey, 32 bytes; absent if exhausted
}
```

### Key Agreement Computation

Follow Signal spec exactly. DH output concatenation order:
```
If one-time prekey present:
  DH_result = DH(IK'_A, SPK_B) || DH(EK_A, IK'_B) || DH(EK_A, SPK_B) || DH(EK_A, OPK_B)

If one-time prekey absent:
  DH_result = DH(IK'_A, SPK_B) || DH(EK_A, IK'_B) || DH(EK_A, SPK_B)
```

### HKDF for X3DH Master Secret

```
F       = 0xFF repeated 32 times (for X25519 output domain separation)
Input   = F || DH_result
Salt    = 32 zero bytes
Info    = "Evanescent_X3DH_v1"   ← exact UTF-8 string, no null terminator
Output  = 32 bytes (master secret)
```

### Signed Prekey Signature

```
message = "Evanescent_SPK_v1" || SPK_public_bytes   ← exact prefix, no null terminator
signature = Ed25519Sign(IK_private, message)
```

### Prekey Rotation

- Signed prekeys rotate every **7 days**
- Old signed prekeys retained for **14 days** after rotation (to handle in-flight sessions)
- One-time prekeys: upload **100** on registration, replenish when count drops below **20**
- One-time prekey IDs are **uint32**, monotonically increasing, never reused

---

## 3. Double Ratchet Parameters

Follow the Signal Double Ratchet specification exactly: https://signal.org/docs/specifications/doubleratchet/

### KDF Chains

```
Root KDF:
  Input: RK (32 bytes), DH output (32 bytes)
  HKDF-SHA256, salt=RK, info="Evanescent_DR_RK_v1"
  Output: 64 bytes → new_RK (first 32) || new_CK (last 32)

Chain KDF:
  Input: CK (32 bytes), constant 0x02 (1 byte)
  HMAC-SHA256(key=CK, data=0x02)
  Output: 32 bytes (new_CK)

Message Key:
  Input: CK (32 bytes), constant 0x01 (1 byte)
  HMAC-SHA256(key=CK, data=0x01)
  Output: 32 bytes (MK) — used directly as ChaCha20-Poly1305 key
```

### Message Encryption

```
Nonce: 12 bytes, constructed as:
  bytes [0:4]  = message counter (uint32 big-endian)
  bytes [4:12] = zero bytes

AAD (additional authenticated data):
  Serialised MessageHeader proto (see proto/messages.proto)
  Pass the raw serialised bytes as AAD to ChaCha20-Poly1305

Ciphertext layout:
  [ChaCha20-Poly1305 ciphertext || 16-byte tag]
```

### Limits

```
MAX_SKIP = 1000     ← maximum number of message keys stored for out-of-order delivery
MAX_CHAIN = 2000    ← maximum messages per ratchet step before forcing a DH ratchet
```

### State Serialisation

Double Ratchet state is serialised to proto and stored in SQLCipher. See `proto/state.proto`. State is never transmitted to the provider.

---

## 4. Sealed Sender

Sealed sender is an application-layer wrapper applied on top of the Double Ratchet ciphertext. Its purpose: the recipient's provider cannot read the sender's identity, and the recipient does not learn the sender's identity until successful decryption.

### Construction (sender side)

```
1. Generate fresh ephemeral X25519 keypair (EPK_priv, EPK_pub)

2. Compute shared secret:
   ECDH_out = X25519(EPK_priv, recipient_IK_X25519_pub)

3. Derive keys:
   HKDF-SHA256(
     input  = ECDH_out,
     salt   = 32 zero bytes,
     info   = "Evanescent_SealedSender_v1",
     length = 64
   )
   → encryption_key (first 32 bytes)
   → mac_key (last 32 bytes)

4. Construct inner plaintext:
   SealedSenderContent {
     sender_identity_key: Alice's Ed25519 pubkey (32 bytes)
     sender_nym_address:  Alice's Nym address string
     dr_ciphertext:       Double Ratchet encrypted message bytes
   }
   Serialise as proto (proto/sealed_sender.proto)

5. Encrypt inner plaintext:
   nonce = random 12 bytes (CSPRNG)
   ciphertext = ChaCha20Poly1305.Seal(
     key   = encryption_key,
     nonce = nonce,
     plain = serialised SealedSenderContent,
     aad   = EPK_pub  ← the ephemeral public key is authenticated
   )

6. Construct SealedEnvelope proto:
   SealedEnvelope {
     ephemeral_key: EPK_pub (32 bytes)
     nonce:         random nonce (12 bytes)
     ciphertext:    ciphertext || 16-byte Poly1305 tag
   }
```

### Verification (recipient side)

```
1. Read EPK_pub from SealedEnvelope
2. ECDH_out = X25519(recipient_IK_X25519_priv, EPK_pub)
3. Derive same keys via HKDF (same parameters)
4. Decrypt ciphertext → SealedSenderContent
5. Extract sender_identity_key
6. Pass sender_identity_key and dr_ciphertext to Double Ratchet decrypt
7. Double Ratchet verifies sender identity implicitly via session state
```

### Rules

- A fresh EPK is generated for **every single message**. EPK is never reused.
- If decryption fails, the entire message is silently dropped. No error is surfaced to the provider.
- The provider passes the raw `SealedEnvelope` bytes through without inspecting them.

---

## 5. Wire Format

**All inter-component communication uses Protocol Buffers (proto3), binary encoding.**

- No JSON between backend and Android
- No MessagePack, CBOR, or custom binary formats
- Proto files live in `proto/` and are the canonical definitions
- Both Go and Kotlin/Android generate their types from the same `.proto` files

### Proto Generation Commands

```bash
# Go
protoc \
  --go_out=backend/internal/proto \
  --go_opt=paths=source_relative \
  proto/*.proto

# Kotlin (Android)
protoc \
  --kotlin_out=android/app/src/main/java \
  --java_out=android/app/src/main/java \
  proto/*.proto
```

Run these from the repo root. Generated files are committed to the repo.

### Proto File Organisation

```
proto/
  prekeys.proto       ← PreKeyBundle, PreKeyUpload
  messages.proto      ← MessageHeader, Message, MessageEnvelope
  sealed_sender.proto ← SealedEnvelope, SealedSenderContent
  ws.proto            ← WsClientMessage, WsServerMessage (WebSocket frames)
  state.proto         ← RatchetState, SessionState (local storage only, never transmitted)
  identity.proto      ← ContactBundle, IdentityKey
```

### Proto Rules

- Use `proto3` syntax. No `required` fields (proto3 removes them anyway).
- Field numbers are permanent. Never reuse a field number, even after removing a field. Mark removed fields with `reserved`.
- Use `bytes` for all cryptographic material. Never use `string` for keys, ciphertexts, or nonces.
- Use `int64` for timestamps (Unix milliseconds). Never use `google.protobuf.Timestamp` (adds a dependency).
- Use `uint32` for IDs (prekey IDs, message counters). Use `string` for human-readable identifiers.
- Message names: `PascalCase`. Field names: `snake_case`. Enum values: `SCREAMING_SNAKE_CASE`.

---

## 6. Encoding Conventions

| Data Type | Encoding | Notes |
|---|---|---|
| Binary in proto | `bytes` field | Raw bytes, no further encoding |
| Binary in logs/display | hex lowercase | e.g. `a3f4...` — never base64 in logs |
| Timestamps | int64 Unix milliseconds | Milliseconds, not seconds |
| Nym address | string | Format: `<base64url_pubkey>@<gateway_id>` |
| .onion address | string | v3 onion, 56 chars + `.onion` |
| Mailbox address | hex string, 64 chars | BLAKE3(identity_pubkey), full 32 bytes as hex |
| Message ID | string UUID v4 | Generated by sender, formatted as `xxxxxxxx-xxxx-4xxx-...` |
| Prekey ID | uint32 | Monotonically increasing, never reused |

---

## 7. WebSocket Protocol (Android ↔ Provider)

The provider exposes a WebSocket server on its Tor hidden service. Android connects exclusively through Orbot (SOCKS5 proxy).

### Connection

```
URL:    ws://<onion_address>.onion:<port>/ws
Frames: binary only (no text frames)
Each frame: one serialised WsClientMessage or WsServerMessage proto
No frame fragmentation — each proto fits in one WebSocket frame
Max frame size: 512 KB
```

### Authentication

Authentication happens immediately after WebSocket connection, before any other messages are exchanged.

```
1. Android sends: WsClientMessage { auth_challenge_request: AuthChallengeRequest {} }
2. Provider sends: WsServerMessage { auth_challenge: AuthChallenge { nonce: <32 random bytes> } }
3. Android sends: WsClientMessage {
     auth_response: AuthResponse {
       identity_key: <Ed25519 pubkey, 32 bytes>
       signature:    Ed25519Sign(identity_key_private, "Evanescent_Auth_v1" || nonce)
     }
   }
4. Provider verifies signature. If valid:
     sends WsServerMessage { auth_ok: AuthOk { session_token: <opaque 32 bytes> } }
   If invalid:
     sends WsServerMessage { error: Error { code: AUTH_FAILED } }
     closes connection
```

The `session_token` is not used further in the current protocol version (reserved for future session resumption). The connection is considered authenticated for its lifetime.

### Client → Provider Messages

```protobuf
// All defined in proto/ws.proto as WsClientMessage oneof

UploadPreKeys {
  repeated SignedPreKey signed_prekeys  = 1;
  repeated OneTimePreKey one_time_prekeys = 2;
}

FetchMessages {
  repeated string ack_ids = 1;   // IDs of messages acknowledged (delete from server)
}

SendMessage {
  string           correlation_id  = 1;  // UUID v4, for matching SendAck
  string           to_nym_address  = 2;  // recipient's Nym address
  bytes            sealed_envelope = 3;  // serialised SealedEnvelope proto
}

Ping {}
```

### Provider → Client Messages

```protobuf
// All defined in proto/ws.proto as WsServerMessage oneof

Messages {
  repeated StoredMessage items = 1;
}

StoredMessage {
  string id             = 1;  // UUID v4
  bytes  sealed_envelope = 2; // serialised SealedEnvelope proto
  int64  received_at    = 3;  // Unix milliseconds
}

SendAck {
  string correlation_id = 1;
  bool   ok             = 2;
  string error_code     = 3;  // present only if !ok
}

Pong {}

Error {
  string code    = 1;
  string message = 2;  // human-readable, not shown to end users
}
```

### Message Flow Invariants

- Android must send `FetchMessages` with `ack_ids` of all previously received messages before requesting new ones. The provider deletes acknowledged messages.
- If Android disconnects before acknowledging, messages are re-delivered on next connection.
- `SendMessage` is fire-and-confirm: Android sends, awaits `SendAck` with matching `correlation_id` before considering delivery complete.
- The provider does not buffer outbound `SendMessage` requests beyond a queue of **100**. If the queue is full, `SendAck { ok: false, error_code: "QUEUE_FULL" }` is returned.

---

## 8. Identity and Addressing

### User Identity

```
identity_key     — Ed25519 keypair. Generated on device. Private key never leaves device.
                   This is the root of all trust for a user.

mailbox_address  — BLAKE3(identity_key_public)[0:32] as 64-char hex string.
                   This is how the provider indexes the user's mailbox slot.

nym_address      — The provider's Nym address (not the user's directly).
                   Format: <nym_client_pubkey_base64url>@<gateway_id>
                   This is what senders use to route messages through the mix-net.
```

### Contact Bundle

A contact bundle is the complete information needed to send someone a message. Shared out-of-band (QR code, secure link).

```protobuf
// proto/identity.proto
message ContactBundle {
  bytes  identity_key     = 1;  // Ed25519 pubkey, 32 bytes
  string nym_address      = 2;  // provider's Nym address
  string provider_onion   = 3;  // provider's .onion address (for prekey fetch fallback)
  uint32 version          = 4;  // bundle format version, currently 1
}
```

Contact bundles are serialised to proto, then encoded as **base64url (no padding)** for display/QR codes.

### Safety Numbers

Safety numbers allow out-of-band identity verification (call the contact, read numbers aloud).

```
safety_number = SHA256(sort(identity_key_A, identity_key_B) concatenated)[0:30]
Display as: 5 groups of 6 decimal digits
```

Sorting is lexicographic on the raw 32-byte key. Always sort so both parties compute identical numbers.

---

## 9. Key Sizes and Formats

All sizes in bytes.

| Key | Size | Format in proto |
|---|---|---|
| Ed25519 private key | 64 | Not transmitted — stored locally in encrypted storage |
| Ed25519 public key | 32 | `bytes` |
| Ed25519 signature | 64 | `bytes` |
| X25519 private key | 32 | Not transmitted — stored locally |
| X25519 public key | 32 | `bytes` |
| X25519 DH output | 32 | Not stored — ephemeral |
| ChaCha20-Poly1305 key | 32 | Not transmitted — derived via HKDF |
| ChaCha20-Poly1305 nonce | 12 | `bytes` (in SealedEnvelope only) |
| Poly1305 tag | 16 | Appended to ciphertext — not a separate field |
| BLAKE3 mailbox address | 32 | Transmitted as 64-char hex string |
| Session auth nonce | 32 | `bytes` |

---

## 10. Nym Integration

### nym-client Sidecar

The provider runs `nym-client` as a separate process. Communication is via WebSocket on `ws://127.0.0.1:1977`.

```
Provider binary responsibilities:
  - Start nym-client subprocess on boot
  - Monitor subprocess health (restart on crash, max 5 restarts/minute)
  - Connect to nym-client WebSocket
  - Send/receive Nym messages via nym-client WebSocket API
  - Log nym-client stderr but never log message contents
```

### Nym WebSocket API (provider ↔ nym-client)

The nym-client uses its own JSON protocol on port 1977. The provider wraps this:

```json
// Send a message via Nym:
{ "type": "send",
  "message": "<base64-encoded SealedEnvelope proto bytes>",
  "recipient": "<nym_address_string>" }

// Incoming message from Nym:
{ "type": "received",
  "message": "<base64-encoded bytes>",
  "sender": "<nym_address_or_null>" }
```

The provider passes `SealedEnvelope` bytes as the Nym message payload. The nym-client handles Sphinx wrapping; the provider does not implement Sphinx.

### Nym Address in Contact Bundle

The `nym_address` in a `ContactBundle` is the **provider's** Nym address, not the user's device address. This is correct: the provider is the permanent endpoint; the device is ephemeral.

### Message Size Limit

Nym imposes a maximum plaintext payload per Sphinx packet. Current limit: **32 KB**.

Messages exceeding this limit must be split by the sender and reassembled by the recipient. Splitting protocol is defined in `proto/messages.proto` (`MessageFragment` message). This is a future concern; initial implementation may reject messages > 32 KB with `error_code: "MESSAGE_TOO_LARGE"`.

---

## 11. Tor Integration

### Provider (Tor Hidden Service)

```
The provider creates a v3 Tor hidden service.
Port mapping: <onion>:443 → 127.0.0.1:<ws_port>
The ws_port is configured in provider config; not exposed on clearnet.
The .onion address is the provider's stable address and is included in ContactBundle.

Tor control: provider manages Tor via the Tor control port (127.0.0.1:9051)
Authentication: cookie authentication
Library (Go): github.com/cretz/bine (tor control library for Go)
```

### Android (Orbot SOCKS5)

```
All network traffic from the Android app goes through Orbot.
SOCKS5 proxy address: 127.0.0.1:9050  (Orbot default)

The app must:
  1. Check if Orbot is installed. If not, prompt user to install from F-Droid.
  2. Check if Orbot is running. If not, request Orbot to start via Intent.
  3. Route all WebSocket connections through the SOCKS5 proxy.
  4. Never establish a direct TCP connection to anything.

OkHttp SOCKS5 proxy setup (Kotlin):
  val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 9050))
  OkHttpClient.Builder().proxy(proxy)...
```

### .onion Address Validation

Before connecting, validate the `.onion` address:
- Must be exactly 56 characters + `.onion` (62 chars total)
- Characters must be valid base32 (a-z2-7)
- Any other format must be rejected with a logged error — never connect

---

## 12. Cover Traffic Parameters

Cover traffic runs on the **provider** at all times, regardless of whether the Android client is connected.

```
Loop messages  (provider sends to own Nym address, then discards on receipt):
  Rate:    Poisson process, λ = 1 message per 60 seconds
  Size:    Fixed 512 bytes (pad with CSPRNG bytes if needed)
  Purpose: Prove path liveness; contribute to anonymity set

Drop messages  (provider sends to random Nym addresses; recipients discard):
  Rate:    Poisson process, λ = 1 message per 120 seconds
  Target:  Random Nym address selected from published network directory
  Size:    Fixed 512 bytes
  Purpose: Make traffic indistinguishable from real messages

Real messages:
  Padded to the next multiple of 512 bytes before sending via Nym
  (Nym handles per-hop Sphinx padding; this is application-level padding
   so message sizes don't leak plaintext length to the provider's Nym address)
```

Cover traffic rates are **not configurable by end users**. They may be adjusted by updating the constants in `backend/internal/cover/params.go` with a protocol version bump.

---

## 13. Storage Standards

### Provider (Go)

```
Database:   SQLite via modernc.org/sqlite (pure Go, no CGO required)
Schema:     Defined in backend/internal/store/schema.sql
Migrations: Sequential numbered files in backend/internal/store/migrations/

Tables:
  mailboxes     (mailbox_address TEXT PK, created_at INTEGER)
  messages      (id TEXT PK, mailbox_address TEXT, envelope BLOB, received_at INTEGER)
  prekeys       (mailbox_address TEXT, prekey_id INTEGER, type TEXT, key_data BLOB, used INTEGER)
  signed_prekeys (mailbox_address TEXT, prekey_id INTEGER, key_data BLOB, sig BLOB, expires_at INTEGER)

Message TTL: 30 days from received_at. Enforced by a daily cleanup job.
No logging of: message contents, sender identities, receipt/delivery timestamps beyond what's in the messages table.
```

### Android (Kotlin)

```
Database:   SQLCipher (encrypted SQLite)
ORM:        Room with SQLCipher support
Key:        Master encryption key stored in Android Keystore (TEE-backed)

Tables:
  contacts      (identity_key BLOB PK, nym_address TEXT, alias TEXT, verified INTEGER)
  sessions      (contact_id BLOB, ratchet_state BLOB)  ← ratchet_state is serialised proto
  messages      (id TEXT PK, contact_id BLOB, direction TEXT, plaintext TEXT, timestamp INTEGER, status TEXT)
  prekeys       (type TEXT, prekey_id INTEGER, key_data BLOB, used INTEGER)

The ratchet_state column stores serialised RatchetState proto.
Plaintext is stored after decryption. Messages are not stored in encrypted form locally
(the SQLCipher encryption of the database itself provides at-rest protection).
```

---

## 14. Error Handling

### Error Codes (WebSocket)

These are the only valid `error_code` values in `SendAck` and `Error` messages:

```
AUTH_FAILED          — authentication signature invalid or identity key not registered
AUTH_REQUIRED        — attempted operation before authentication
PREKEY_EXHAUSTED     — no one-time prekeys available (bundle returned without OPK)
QUEUE_FULL           — outbound send queue is full (100 pending)
MESSAGE_TOO_LARGE    — message exceeds 32 KB Nym limit
UNKNOWN_MAILBOX      — FetchMessages for unknown mailbox address
INVALID_MESSAGE      — proto deserialisation failed
RATE_LIMITED         — client exceeded rate limit
INTERNAL             — unexpected server error
```

### Rules

- **Never surface stack traces** in error messages sent to clients.
- **Never log message contents** — not plaintext, not ciphertext, not sealed envelope bytes.
- **Fail closed**: on any cryptographic error, drop the message silently. Do not send an error response that could be used as an oracle.
- **Provider errors** are logged to stderr with structured JSON logs (no message data, only metadata: timestamp, error code, mailbox_address if available).
- **Android errors** are logged via Android Logcat with tag `Evanescent` at DEBUG level only. Production builds must set minimum log level to WARN.

---

## 15. Naming Conventions

### Go (backend)

- Packages: short, lowercase, single word: `crypto`, `mailbox`, `cover`, `prekeys`, `nym`, `onion`, `ws`
- Exported types: `PascalCase`
- Unexported types and functions: `camelCase`
- Constants: `ALL_CAPS` for protocol constants in `params.go` files; `PascalCase` for others
- Test files: `_test.go` suffix, same package (white-box) or `_test` package suffix (black-box)

### Kotlin (Android)

- Packages: `net.evanescent.<module>` (e.g., `net.evanescent.crypto`)
- Classes: `PascalCase`
- Functions and properties: `camelCase`
- Constants: `SCREAMING_SNAKE_CASE` in companion objects
- Coroutine scopes: suffix `Scope` (e.g., `cryptoScope`)

### Proto

- Message names: `PascalCase`
- Field names: `snake_case`
- Enum type names: `PascalCase`
- Enum value names: `SCREAMING_SNAKE_CASE` prefixed with enum type name (e.g., `ERROR_AUTH_FAILED`)
- Package: `evanescent.v1`
- Go package option: `option go_package = "github.com/evanescent/evanescent/backend/internal/proto";`

---

## 16. Versioning

### Protocol Version

The current protocol version is **`v1`**.

All proto packages use `evanescent.v1`. All HKDF info strings contain `_v1`. When a breaking change is made:
- Bump the version in all info strings simultaneously
- Create new proto package `evanescent.v2`
- Old and new versions are incompatible; there is no negotiation

### API Versioning

The WebSocket URL is unversioned (`/ws`). Breaking changes require a full protocol version bump, not a URL path change.

### Application Version

Android app uses semantic versioning: `MAJOR.MINOR.PATCH` where:
- MAJOR: protocol version change
- MINOR: new features, backward compatible
- PATCH: bug fixes

---

## 17. Testing Requirements

### Backend (Go)

```
Unit tests:    go test ./...
               Minimum coverage: 80% for packages under internal/crypto/
               Coverage tool: go test -coverprofile=coverage.out ./...

Integration:   Separate test binary in backend/cmd/integration_test/
               Requires: running nym-client (mock acceptable in CI)
                         running Tor (mock acceptable in CI)

Crypto tests:  Must include test vectors from Signal's published X3DH and
               Double Ratchet test vectors where available.
               Any divergence from test vectors is a bug, not a test failure.
```

### Android (Kotlin)

```
Unit tests:    JUnit5 + Kotlin coroutines test
               Minimum coverage: 80% for net.evanescent.crypto package

Instrumented:  Espresso for UI flows; run on emulator (API 26+) in CI

Crypto tests:  Same requirement as Go — must validate against published
               Signal test vectors.
```

### Cross-Component Tests

The `backend/cmd/integration_test/` binary includes a test that:
1. Runs a provider instance in test mode (no Nym, no Tor — loopback only)
2. Runs a simulated Android client (Go-based, using same proto definitions)
3. Exercises the full send/receive flow through the WebSocket protocol
4. Verifies that X3DH session establishment + Double Ratchet + sealed sender round-trips correctly

This test is the primary guard against backend/Android mismatches.
