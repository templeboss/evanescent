# Evanescent — Engineering Standards

This document is the single source of truth for every interface boundary in the system. Its purpose is to prevent mismatches between the backend and the Android client. When in doubt, this file wins.

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
10. [Inter-Provider HTTP API](#10-inter-provider-http-api)
11. [Tor Integration](#11-tor-integration)
12. [Storage Standards](#12-storage-standards)
13. [Error Handling](#13-error-handling)
14. [Naming Conventions](#14-naming-conventions)
15. [Versioning](#15-versioning)
16. [Testing Requirements](#16-testing-requirements)

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
| Random number generation | OS CSPRNG only | `OsRng` in Rust, `SecureRandom` in Android |

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
- Use the `curve25519-dalek` / `ed25519-dalek` crates for this conversion in Rust; do not implement it manually

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
- Both Rust and Android generate their types from the same `.proto` files

### Proto Generation Commands

```bash
# Rust (backend) — uses protoc-bin-vendored in build.rs; no system protoc required
cargo build   # build.rs invokes prost-build automatically

# Kotlin (Android)
protoc \
  --kotlin_out=android/app/src/main/java \
  --java_out=android/app/src/main/java \
  proto/*.proto
```

Run Kotlin generation from the repo root. Generated files are committed to the repo.

### Proto File Organisation

```
proto/
  prekeys.proto       ← PreKeyBundle, PreKeyUpload, GetPreKeys, PreKeys
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
| .onion address | string | v3 onion, 56 chars + `.onion` |
| Mailbox address | hex string, 64 chars | BLAKE3(identity_pubkey), full 32 bytes as hex |
| Message ID | string UUID v4 | Generated by sender, formatted as `xxxxxxxx-xxxx-4xxx-...` |
| Prekey ID | uint32 | Monotonically increasing, never reused |

---

## 7. WebSocket Protocol (Android ↔ Provider)

The provider exposes a WebSocket server on its Tor hidden service. Android connects via embedded Tor (no external Orbot required).

### Connection

```
URL:    ws://<onion_address>/ws
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
  repeated SignedPreKey signed_prekeys    = 1;
  repeated OneTimePreKey one_time_prekeys = 2;
}

FetchMessages {
  repeated string ack_ids = 1;   // IDs of messages acknowledged (delete from server)
}

SendMessage {
  string correlation_id    = 1;  // UUID v4, for matching SendAck
  reserved 2;                    // was to_nym_address
  reserved "to_nym_address";
  bytes  sealed_envelope   = 3;  // serialised SealedEnvelope proto
  bytes  to_mailbox_addr   = 4;  // 32 bytes — recipient's mailbox address
  reserved 5;                    // was nym_prefix
  reserved "nym_prefix";
  string to_provider_onion = 6;  // recipient provider's .onion address
}

// Request a prekey bundle from another provider on the client's behalf
GetPreKeys {
  string provider_onion = 1;  // target provider's .onion address
  bytes  mailbox_addr   = 2;  // 32 bytes — target user's mailbox address
  string correlation_id = 3;  // UUID v4, for matching PreKeys response
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
  string id              = 1;  // UUID v4
  bytes  sealed_envelope = 2;  // serialised SealedEnvelope proto
  int64  received_at     = 3;  // Unix milliseconds
}

SendAck {
  string correlation_id = 1;
  bool   ok             = 2;
  string error_code     = 3;  // present only if !ok
}

// Response to GetPreKeys
PreKeys {
  string       correlation_id = 1;
  PreKeyBundle bundle         = 2;  // absent on error
  string       error_code     = 3;  // present only on error
}

ProviderInfo {
  reserved 1;              // was nym_address
  reserved "nym_address";
  string onion_address = 2;
  bytes  mailbox_addr  = 3;  // 32 raw bytes — this user's own mailbox address
}

Pong {}

Error {
  string code    = 1;
  string message = 2;  // human-readable, not shown to end users
}
```

### WsClientMessage oneof variants

```
auth_challenge_request = 1
auth_response          = 2
upload_pre_keys        = 3
fetch_messages         = 4
send_message           = 5
ping                   = 6
get_pre_keys           = 7
```

### WsServerMessage oneof variants

```
auth_challenge = 1
auth_ok        = 2
messages       = 3
send_ack       = 4
provider_info  = 5
pong           = 6
error          = 7
pre_keys       = 8
```

### Message Flow Invariants

- Android must send `FetchMessages` with `ack_ids` of all previously received messages before requesting new ones. The provider deletes acknowledged messages.
- If Android disconnects before acknowledging, messages are re-delivered on next connection.
- `SendMessage` is fire-and-confirm: Android sends, awaits `SendAck` with matching `correlation_id` before considering delivery complete.
- The provider does not buffer outbound `SendMessage` requests beyond a queue of **100**. If the queue is full, `SendAck { ok: false, error_code: "QUEUE_FULL" }` is returned.
- `GetPreKeys` is proxied by the provider to the target provider's HTTP API. The provider responds with `PreKeys` containing the bundle or an error code.

---

## 8. Identity and Addressing

### User Identity

```
identity_key     — Ed25519 keypair. Generated on device. Private key never leaves device.
                   This is the root of all trust for a user.

mailbox_address  — BLAKE3(identity_key_public)[0:32] as 64-char hex string.
                   This is how the provider indexes the user's mailbox slot.
```

### Contact Bundle

A contact bundle is the complete information needed to send someone a message. Shared out-of-band (QR code, secure link).

```protobuf
// proto/identity.proto
message ContactBundle {
  bytes  identity_key   = 1;  // Ed25519 pubkey, 32 bytes
  reserved 2;                 // was nym_address
  reserved "nym_address";
  string provider_onion = 3;  // provider's .onion address
  uint32 version        = 4;  // bundle format version, currently 2
  bytes  mailbox_addr   = 5;  // 32 bytes — user's mailbox address
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
| BLAKE3 mailbox address | 32 | Transmitted as 64-char hex string or raw `bytes` depending on context |
| Session auth nonce | 32 | `bytes` |

---

## 10. Inter-Provider HTTP API

Providers communicate with each other via HTTP over Tor. Requests are made via the provider's Tor SOCKS5 proxy (`127.0.0.1:<tor_socks_port>`, default 9050) to the target provider's `.onion` address.

All request/response bodies are proto3 binary (`Content-Type: application/x-protobuf`).

### Endpoints

**POST /api/v1/deliver**

```
Body:     DeliverRequest { bytes mailbox_addr = 1; bytes sealed_envelope = 2; }
Response: 200 OK (empty body) on success
Errors:   400 Bad Request (invalid proto)
          404 Not Found (unknown mailbox)
          500 Internal Server Error
```

The receiving provider stores the `sealed_envelope` in the specified mailbox.

**GET /api/v1/prekeys/{mailbox_addr_hex}**

```
Path param: mailbox_addr_hex — 64-char hex string of the 32-byte mailbox address
Response:   200 OK, body = PreKeyBundle proto bytes
Errors:     404 Not Found (unknown mailbox or no prekeys)
            500 Internal Server Error
```

The receiving provider returns the active prekey bundle for the specified mailbox. A one-time prekey is consumed if available; the bundle is returned without one if exhausted.

### Security

No authentication between providers. The `.onion` address itself authenticates the provider: a server reachable at a given `.onion` address holds the corresponding private key by construction.

Rate limiting: max 10 deliver requests per second per source `.onion` address.

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
```

The provider also uses the Tor SOCKS5 proxy for outbound inter-provider HTTP requests (see §10).

### Android (Embedded Tor)

```
The Android app embeds Tor via the tor-android library (Guardian Project).
Tor bootstraps silently on app startup. No external Orbot installation required.
The app obtains a dynamic SOCKS5 port from TorManager after bootstrap.
All WebSocket connections are proxied through this SOCKS5 port.
Never fall back to direct connections if Tor fails to bootstrap.

OkHttp SOCKS5 proxy setup (Kotlin):
  val port = TorManager.getSocksPort()   // dynamic, assigned after bootstrap
  val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
  OkHttpClient.Builder().proxy(proxy)...
```

### .onion Address Validation

Before connecting, validate the `.onion` address:
- Must be exactly 56 characters + `.onion` (62 chars total)
- Characters must be valid base32 (a-z2-7)
- Any other format must be rejected with a logged error — never connect

---

## 12. Storage Standards

### Provider (Rust)

```
Database:   SQLite via sqlx with the sqlite feature (WAL mode, foreign keys enabled)
Schema:     Defined inline in backend/src/store.rs (CREATE TABLE IF NOT EXISTS — idempotent)

Tables:
  mailboxes       (mailbox_addr TEXT PK, identity_key BLOB, created_at INTEGER)
  messages        (id TEXT PK, mailbox_addr TEXT, envelope BLOB, received_at INTEGER, delivered INTEGER)
  signed_prekeys  (mailbox_addr TEXT, prekey_id INTEGER, key_data BLOB, expires_at INTEGER)
                  PK: (mailbox_addr, prekey_id)
  one_time_prekeys (mailbox_addr TEXT, prekey_id INTEGER, key_data BLOB, used INTEGER)
                   PK: (mailbox_addr, prekey_id)

Indexes:
  idx_messages_mailbox  ON messages(mailbox_addr, received_at)
  idx_otpk_mailbox      ON one_time_prekeys(mailbox_addr, used)

Message TTL: 30 days from received_at. Enforced by a periodic cleanup task.
No logging of: message contents, sender identities, or receipt/delivery timestamps
               beyond what is present in the messages table.
```

### Android (Kotlin)

```
Database:   SQLCipher (encrypted SQLite)
ORM:        Room with SQLCipher support
Key:        Master encryption key stored in Android Keystore (TEE-backed)

Tables:
  contacts      (identity_key BLOB PK, mailbox_addr BLOB, provider_onion TEXT, alias TEXT, verified INTEGER)
  sessions      (contact_id BLOB, ratchet_state BLOB)  ← ratchet_state is serialised proto
  messages      (id TEXT PK, contact_id BLOB, direction TEXT, plaintext TEXT, timestamp INTEGER, status TEXT)
  prekeys       (type TEXT, prekey_id INTEGER, key_data BLOB, used INTEGER)

The ratchet_state column stores serialised RatchetState proto.
Plaintext is stored after decryption. Messages are not stored in encrypted form locally
(the SQLCipher encryption of the database itself provides at-rest protection).
```

---

## 13. Error Handling

### Error Codes (WebSocket)

These are the only valid `error_code` values in `SendAck`, `PreKeys`, and `Error` messages:

```
AUTH_FAILED          — authentication signature invalid or identity key not registered
AUTH_REQUIRED        — attempted operation before authentication
PREKEY_EXHAUSTED     — no one-time prekeys available (bundle returned without OPK)
QUEUE_FULL           — outbound send queue is full (100 pending)
MESSAGE_TOO_LARGE    — message exceeds 512 KB WebSocket frame limit
UNKNOWN_MAILBOX      — FetchMessages for unknown mailbox address
INVALID_MESSAGE      — proto deserialisation failed
RATE_LIMITED         — client exceeded rate limit
INTERNAL             — unexpected server error
```

### Rules

- **Never surface stack traces** in error messages sent to clients.
- **Never log message contents** — not plaintext, not ciphertext, not sealed envelope bytes.
- **Fail closed**: on any cryptographic error, drop the message silently. Do not send an error response that could be used as an oracle.
- **Provider errors** are logged to stderr with structured JSON logs (no message data, only metadata: timestamp, error code, mailbox_addr if available).
- **Android errors** are logged via Android Logcat with tag `Evanescent` at DEBUG level only. Production builds must set minimum log level to WARN.

---

## 14. Naming Conventions

### Rust (backend)

- Modules: short, lowercase, single word: `crypto`, `mailbox`, `prekeys`, `onion`, `ws`, `store`
- Public types: `PascalCase`
- Private types and functions: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Test modules: `#[cfg(test)] mod tests` at the bottom of each file

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

---

## 15. Versioning

### Protocol Version

The current protocol version is **`v1`**.

All proto packages use `evanescent.v1`. All HKDF info strings contain `_v1`. When a breaking change is made:
- Bump the version in all info strings simultaneously
- Create new proto package `evanescent.v2`
- Old and new versions are incompatible; there is no negotiation

### API Versioning

The WebSocket URL is unversioned (`/ws`). The inter-provider HTTP API is versioned by path prefix (`/api/v1/`). Breaking changes to either require a full protocol version bump.

### Application Version

Android app uses semantic versioning: `MAJOR.MINOR.PATCH` where:
- MAJOR: protocol version change
- MINOR: new features, backward compatible
- PATCH: bug fixes

---

## 16. Testing Requirements

### Backend (Rust)

```
Unit tests:    cargo test
               Minimum coverage: 80% for modules under src/crypto/
               Coverage tool: cargo llvm-cov (or cargo tarpaulin)

Integration:   Separate binary or test module in backend/tests/
               Requires: running Tor (mock acceptable in CI)

Crypto tests:  Must include test vectors from Signal's published X3DH and
               Double Ratchet test vectors where available.
               Any divergence from test vectors is a bug, not a test failure.
```

### Android (Kotlin)

```
Unit tests:    JUnit5 + Kotlin coroutines test
               Minimum coverage: 80% for net.evanescent.crypto package

Instrumented:  Espresso for UI flows; run on emulator (API 26+) in CI

Crypto tests:  Same requirement as Rust — must validate against published
               Signal test vectors.
```

### Cross-Component Tests

The integration test suite includes a test that:
1. Runs a provider instance in test mode (no Tor — loopback only)
2. Runs a simulated Android client (Rust-based, using same proto definitions)
3. Exercises the full send/receive flow through the WebSocket protocol
4. Verifies that X3DH session establishment + Double Ratchet + sealed sender round-trips correctly

This test is the primary guard against backend/Android mismatches.
