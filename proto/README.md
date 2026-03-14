# Evanescent — Protocol Buffers

## Role

The `proto/` directory is the source of truth for every message that crosses a component boundary:

- Messages exchanged between Android and the Provider over WebSocket
- Prekey bundles served from provider to provider (HTTP)
- Provider-to-provider message delivery (HTTP)
- Local state serialised to SQLCipher (Double Ratchet state — never transmitted)

The `.proto` files are the contract. If the Rust and Android implementations disagree, the `.proto` file is correct.

---

## Files

```
proto/
  ws.proto            WebSocket protocol: Android ↔ Provider
  prekeys.proto       X3DH prekey bundles, upload messages, and provider-to-provider delivery
  messages.proto      Double Ratchet message header and envelope
  sealed_sender.proto Sealed sender outer envelope and inner content
  identity.proto      Contact bundles and identity keys
  state.proto         Double Ratchet local state (never transmitted)
```

---

## Generation

### Rust (backend)

Handled automatically by `prost-build` in `backend/build.rs`. No manual step required. The build script compiles all `.proto` files and emits Rust source into `OUT_DIR`.

### Android (Kotlin)

Handled by the Gradle protobuf plugin configured in `android/app/build.gradle`. Run a normal Gradle build to regenerate:

```bash
./gradlew :app:generateDebugProto
```

Output: `android/app/build/generated/source/proto/debug/java/evanescent/v1/`

---

## Versioning and Stability Rules

Field numbers are permanent. Follow these rules without exception:

1. **Never reuse a field number** — even after removing a field. Mark removed fields:
   ```protobuf
   reserved 3;
   reserved "old_field_name";
   ```

2. **Never change a field's type** — this is a breaking change. Add a new field instead.

3. **Never rename a field without adding a `reserved` entry** for the old name.

4. **New fields default to zero/empty** — design with this in mind. A missing field must be a valid state.

5. **Breaking changes require a version bump** — update the package from `evanescent.v1` to `evanescent.v2` and update all HKDF info strings simultaneously.

---

## Naming Rules

- Message names: `PascalCase` — e.g., `PreKeyBundle`, `SealedEnvelope`
- Field names: `snake_case` — e.g., `identity_key`, `signed_prekey_id`
- Enum type names: `PascalCase` — e.g., `ErrorCode`
- Enum value names: `SCREAMING_SNAKE_CASE` prefixed with enum type — e.g., `ERROR_CODE_AUTH_FAILED`
- File names: `snake_case.proto`

---

## Type Rules

| Data | Proto type | Notes |
|---|---|---|
| Cryptographic keys | `bytes` | Raw bytes, no encoding |
| Ciphertexts and nonces | `bytes` | Raw bytes |
| Timestamps | `int64` | Unix milliseconds. Never `google.protobuf.Timestamp`. |
| IDs (prekey, message counter) | `uint32` | Monotonically increasing |
| UUIDs | `string` | Formatted as standard UUID v4 string |
| Onion addresses | `string` | Full `.onion` address including suffix |
| Mailbox addresses | `bytes` | 32 raw bytes — BLAKE3(identity_key)[0:32] |
| Boolean flags | `bool` | |
| Repeated fields | `repeated` | Never use `map` for protocol messages |

---

## File Definitions (Current)

### ws.proto — WebSocket Protocol

All messages exchanged between Android and the Provider over WebSocket.

Each WebSocket binary frame contains exactly one `WsClientMessage` (Android → Provider) or `WsServerMessage` (Provider → Android).

```protobuf
syntax = "proto3";
package evanescent.v1;

import "prekeys.proto";

// Android → Provider
message WsClientMessage {
  oneof body {
    AuthChallengeRequest auth_challenge_request = 1;
    AuthResponse         auth_response          = 2;
    UploadPreKeys        upload_pre_keys        = 3;
    FetchMessages        fetch_messages         = 4;
    SendMessage          send_message           = 5;
    Ping                 ping                   = 6;
    GetPreKeys           get_pre_keys           = 7;
  }
}

// Provider → Android
message WsServerMessage {
  oneof body {
    AuthChallenge auth_challenge = 1;
    AuthOk        auth_ok        = 2;
    Messages      messages       = 3;
    SendAck       send_ack       = 4;
    Pong          pong           = 5;
    Error         error          = 6;
    ProviderInfo  provider_info  = 7;
    PreKeys       pre_keys       = 8;
  }
}

message AuthChallengeRequest {}

message AuthChallenge {
  bytes nonce = 1;  // 32 random bytes
}

message AuthResponse {
  bytes identity_key = 1;  // Ed25519 pubkey, 32 bytes
  bytes signature    = 2;  // Ed25519 signature over ("Evanescent_Auth_v1" || nonce), 64 bytes
}

message AuthOk {
  bytes session_token = 1;  // opaque 32 bytes, reserved for future use
}

message UploadPreKeys {
  repeated SignedPreKey  signed_prekeys   = 1;
  repeated OneTimePreKey one_time_prekeys = 2;
}

message FetchMessages {
  repeated string ack_ids = 1;  // UUIDs of messages to acknowledge and delete
}

message SendMessage {
  string correlation_id    = 1;  // UUID v4, for matching SendAck
  reserved 2;                    // was to_nym_address
  reserved "to_nym_address";
  bytes  sealed_envelope   = 3;  // serialised SealedEnvelope proto bytes
  bytes  to_mailbox_addr   = 4;  // target mailbox address, 32 raw bytes (BLAKE3 of their IK)
  reserved 5;                    // was nym_prefix
  reserved "nym_prefix";
  string to_provider_onion = 6;  // recipient provider's .onion address
}

// Request a prekey bundle from another provider on the client's behalf.
message GetPreKeys {
  string provider_onion = 1;  // .onion address of the target provider
  bytes  mailbox_addr   = 2;  // 32-byte mailbox address of the target user
  string correlation_id = 3;  // UUID v4, for matching PreKeys response
}

message Messages {
  repeated StoredMessage items = 1;
}

message StoredMessage {
  string id              = 1;  // UUID v4
  bytes  sealed_envelope = 2;  // serialised SealedEnvelope proto bytes
  int64  received_at     = 3;  // Unix milliseconds
}

message SendAck {
  string correlation_id = 1;
  bool   ok             = 2;
  string error_code     = 3;  // present only if !ok
}

// Response to GetPreKeys.
message PreKeys {
  string       correlation_id = 1;
  PreKeyBundle bundle         = 2;  // absent on error
  string       error_code     = 3;  // present only on error
}

message Ping {}
message Pong {}

message Error {
  string code    = 1;
  string message = 2;
}

// Sent once immediately after AuthOk so the Android client knows its mailbox address and provider info.
message ProviderInfo {
  reserved 1;                  // was nym_address
  reserved "nym_address";
  string onion_address = 2;  // provider's .onion address (v3)
  bytes  mailbox_addr  = 3;  // this client's mailbox address, 32 raw bytes (BLAKE3 of IK)
}
```

### prekeys.proto — X3DH Prekeys and Provider Delivery

```protobuf
syntax = "proto3";
package evanescent.v1;

message PreKeyBundle {
  bytes  identity_key       = 1;  // Ed25519 pubkey, 32 bytes
  uint32 signed_prekey_id   = 2;
  bytes  signed_prekey      = 3;  // X25519 pubkey, 32 bytes
  bytes  signed_prekey_sig  = 4;  // Ed25519 signature, 64 bytes
  uint32 one_time_prekey_id = 5;  // absent (0) if exhausted
  bytes  one_time_prekey    = 6;  // X25519 pubkey, 32 bytes; absent if exhausted
}

message SignedPreKey {
  uint32 prekey_id  = 1;
  bytes  public_key = 2;  // X25519 pubkey, 32 bytes
  bytes  signature  = 3;  // Ed25519 signature over ("Evanescent_SPK_v1" || public_key), 64 bytes
}

message OneTimePreKey {
  uint32 prekey_id  = 1;
  bytes  public_key = 2;  // X25519 pubkey, 32 bytes
}

// Used as the HTTP request body for POST /api/v1/deliver between providers.
message DeliverRequest {
  bytes mailbox_addr    = 1;  // 32-byte target mailbox address
  bytes sealed_envelope = 2;  // serialised SealedEnvelope proto bytes
}
```

### messages.proto — Double Ratchet Messages

```protobuf
syntax = "proto3";
package evanescent.v1;

message MessageHeader {
  bytes  dh_ratchet_key   = 1;  // X25519 pubkey, 32 bytes (sender's current ratchet key)
  uint32 previous_counter = 2;  // PN: messages in previous chain
  uint32 message_counter  = 3;  // N: message number in current chain
}

// A complete Double Ratchet encrypted message
message DrMessage {
  bytes message_header = 1;  // serialised MessageHeader (used as AAD for AEAD)
  bytes ciphertext     = 2;  // ChaCha20-Poly1305 ciphertext || 16-byte tag
}

// Application-level message content (plaintext before Double Ratchet encryption)
message MessageContent {
  string text       = 1;
  int64  sent_at    = 2;  // Unix milliseconds, set by sender
  string message_id = 3;  // UUID v4
}
```

### sealed_sender.proto — Sealed Sender

```protobuf
syntax = "proto3";
package evanescent.v1;

// Outer envelope: stored by provider, routed to recipient.
// Provider cannot decrypt this.
message SealedEnvelope {
  bytes ephemeral_key = 1;  // X25519 pubkey, 32 bytes (EPK_pub)
  bytes nonce         = 2;  // ChaCha20-Poly1305 nonce, 12 bytes
  bytes ciphertext    = 3;  // encrypted SealedSenderContent || 16-byte Poly1305 tag
}

// Inner content: decrypted by recipient's device only.
message SealedSenderContent {
  bytes  sender_identity_key = 1;  // Ed25519 pubkey, 32 bytes
  reserved 2;                       // was sender_nym_address
  reserved "sender_nym_address";
  bytes  dr_message          = 3;  // serialised DrMessage proto bytes
}
```

### identity.proto — Identity and Contact Exchange

```protobuf
syntax = "proto3";
package evanescent.v1;

// Shared out-of-band (QR code, secure link) to add a contact.
message ContactBundle {
  bytes  identity_key   = 1;  // Ed25519 pubkey, 32 bytes
  reserved 2;                  // was nym_address
  reserved "nym_address";
  string provider_onion = 3;  // provider's .onion address (with .onion suffix)
  uint32 version        = 4;  // bundle format version; currently 2
  bytes  mailbox_addr   = 5;  // BLAKE3(identity_key)[0:32], 32 bytes
}
```

### state.proto — Double Ratchet Local State

**Never transmitted.** Stored in SQLCipher on Android only.

```protobuf
syntax = "proto3";
package evanescent.v1;

message RatchetState {
  bytes  dh_self_public   = 1;  // Current DH ratchet keypair (public), X25519, 32 bytes
  bytes  dh_self_private  = 2;  // Current DH ratchet keypair (private), X25519, 32 bytes
  bytes  dh_remote_public = 3;  // Remote's current ratchet public key, 32 bytes
  bytes  root_key         = 4;  // Current root key, 32 bytes
  bytes  chain_key_send   = 5;  // Sending chain key, 32 bytes
  bytes  chain_key_recv   = 6;  // Receiving chain key, 32 bytes
  uint32 send_count       = 7;  // N_s: messages sent in current chain
  uint32 recv_count       = 8;  // N_r: messages received in current chain
  uint32 prev_send_count  = 9;  // PN: messages in previous sending chain
  repeated SkippedKey skipped_keys = 10;
}

message SkippedKey {
  bytes  dh_public       = 1;  // Ratchet public key this skip key belongs to
  uint32 message_counter = 2;  // Message counter for this skip key
  bytes  message_key     = 3;  // The skip key itself, 32 bytes
}
```

---

## Adding New Messages

1. Add the message definition to the appropriate `.proto` file.
2. Regenerate Rust and Android code (prost-build runs automatically on `cargo build`; Gradle handles Android).
3. Commit generated files alongside the `.proto` change in the same commit.
4. Update this README if adding a new `.proto` file or a message that crosses a component boundary.
5. Update `docs/standards.md` if the new message affects a protocol boundary.

Never add a message that crosses a component boundary (Android ↔ Provider, or Provider ↔ Provider via HTTP) without a corresponding entry in this README and in `docs/standards.md`.
