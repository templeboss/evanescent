# Evanescent — Protocol Buffers

**Agent briefing**: This directory is the source of truth for all wire formats. If you are adding a field, changing a type, or adding a message, you do so here — nowhere else. Both Go and Android generate their types from these files. Read [docs/standards.md](../docs/standards.md) before making any changes.

---

## Role

The `proto/` directory defines every message that crosses a component boundary:
- Messages sent between Android and the Personal Provider (WebSocket)
- Messages sent via the Nym mix-net (provider ↔ provider)
- Prekey bundles served from provider to requester
- Local state serialised to SQLCipher (Double Ratchet state)

The `.proto` files are the contract. If the Go and Android implementations disagree, the `.proto` file is correct.

---

## Files

```
proto/
  ws.proto            WebSocket protocol: Android ↔ Provider
  prekeys.proto       X3DH prekey bundles and upload messages
  messages.proto      Double Ratchet message header and envelope
  sealed_sender.proto Sealed sender outer envelope and inner content
  identity.proto      Contact bundles and identity keys
  state.proto         Double Ratchet local state (never transmitted)
```

---

## Generation

Run from the repository root. Generated files are committed to the repo.

### Go

```bash
protoc \
  --go_out=backend/internal/proto \
  --go_opt=paths=source_relative \
  proto/*.proto
```

Output: `backend/internal/proto/<filename>.pb.go`

### Kotlin / Android

```bash
protoc \
  --kotlin_out=android/app/src/main/java \
  --java_out=android/app/src/main/java \
  proto/*.proto
```

Output: `android/app/src/main/java/evanescent/v1/`

### Required Tools

```bash
# Install protoc
# macOS:  brew install protobuf
# Linux:  apt install protobuf-compiler  OR  download from github.com/protocolbuffers/protobuf/releases

# Install Go plugin
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

# Install Kotlin plugin
# Download protoc-gen-kotlin from: https://github.com/grpc/grpc-kotlin/releases
# Or use the Gradle protobuf plugin in the Android project (preferred)
```

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
| Nym addresses | `string` | `<pubkey_base64url>@<gateway_id>` |
| Onion addresses | `string` | Full `.onion` address including suffix |
| Boolean flags | `bool` | |
| Repeated fields | `repeated` | Never use `map` for protocol messages |

---

## File Definitions (Current)

### ws.proto — WebSocket Protocol

All messages exchanged between Android and the Personal Provider over WebSocket.

Each WebSocket binary frame contains exactly one `WsClientMessage` (Android → Provider) or `WsServerMessage` (Provider → Android).

```protobuf
syntax = "proto3";
package evanescent.v1;

// Android → Provider
message WsClientMessage {
  oneof body {
    AuthChallengeRequest auth_challenge_request = 1;
    AuthResponse         auth_response          = 2;
    UploadPreKeys        upload_pre_keys        = 3;
    FetchMessages        fetch_messages         = 4;
    SendMessage          send_message           = 5;
    Ping                 ping                   = 6;
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
  repeated SignedPreKey   signed_prekeys    = 1;
  repeated OneTimePreKey  one_time_prekeys  = 2;
}

message FetchMessages {
  repeated string ack_ids = 1;  // UUIDs of messages to acknowledge and delete
}

message SendMessage {
  string correlation_id   = 1;  // UUID v4, for matching SendAck
  string to_nym_address   = 2;  // recipient provider's Nym address
  bytes  sealed_envelope  = 3;  // serialised SealedEnvelope proto bytes
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
  string error_code     = 3;  // present only if !ok; see standards.md §14 for valid values
}

message Ping {}
message Pong {}

message Error {
  string code    = 1;
  string message = 2;
}
```

### prekeys.proto — X3DH Prekeys

```protobuf
syntax = "proto3";
package evanescent.v1;

message PreKeyBundle {
  bytes  identity_key        = 1;  // Ed25519 pubkey, 32 bytes
  uint32 signed_prekey_id    = 2;
  bytes  signed_prekey       = 3;  // X25519 pubkey, 32 bytes
  bytes  signed_prekey_sig   = 4;  // Ed25519 signature, 64 bytes
  uint32 one_time_prekey_id  = 5;  // absent (0) if exhausted
  bytes  one_time_prekey     = 6;  // X25519 pubkey, 32 bytes; absent if exhausted
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

// Sent via Nym from requester to provider to request a prekey bundle
message PreKeyRequest {
  bytes reply_nym_address = 1;  // Nym address to send the PreKeyBundle response to
}
```

### messages.proto — Double Ratchet Messages

```protobuf
syntax = "proto3";
package evanescent.v1;

message MessageHeader {
  bytes  dh_ratchet_key    = 1;  // X25519 pubkey, 32 bytes (sender's current ratchet key)
  uint32 previous_counter  = 2;  // PN: messages in previous chain
  uint32 message_counter   = 3;  // N: message number in current chain
}

// A complete Double Ratchet encrypted message
message DrMessage {
  bytes message_header     = 1;  // serialised MessageHeader (used as AAD for AEAD)
  bytes ciphertext         = 2;  // ChaCha20-Poly1305 ciphertext || 16-byte tag
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

// Outer envelope: stored by provider, routed via Nym
// Provider cannot decrypt this.
message SealedEnvelope {
  bytes ephemeral_key = 1;  // X25519 pubkey, 32 bytes (EPK_pub)
  bytes nonce         = 2;  // ChaCha20-Poly1305 nonce, 12 bytes
  bytes ciphertext    = 3;  // encrypted SealedSenderContent || 16-byte Poly1305 tag
}

// Inner content: decrypted by recipient's device only
message SealedSenderContent {
  bytes  sender_identity_key = 1;  // Ed25519 pubkey, 32 bytes
  string sender_nym_address  = 2;  // sender provider's Nym address (for reply routing)
  bytes  dr_message          = 3;  // serialised DrMessage proto bytes
}
```

### identity.proto — Identity and Contact Exchange

```protobuf
syntax = "proto3";
package evanescent.v1;

// Shared out-of-band (QR code, secure link) to add a contact
message ContactBundle {
  bytes  identity_key    = 1;  // Ed25519 pubkey, 32 bytes
  string nym_address     = 2;  // provider's Nym address
  string provider_onion  = 3;  // provider's .onion address (with .onion suffix)
  uint32 version         = 4;  // bundle format version; currently 1
}
```

### state.proto — Double Ratchet Local State

**Never transmitted.** Stored in SQLCipher only.

```protobuf
syntax = "proto3";
package evanescent.v1;

message RatchetState {
  bytes  dh_self_public    = 1;   // Current DH ratchet keypair (public), X25519, 32 bytes
  bytes  dh_self_private   = 2;   // Current DH ratchet keypair (private), X25519, 32 bytes
  bytes  dh_remote_public  = 3;   // Remote's current ratchet public key, 32 bytes
  bytes  root_key          = 4;   // Current root key, 32 bytes
  bytes  chain_key_send    = 5;   // Sending chain key, 32 bytes
  bytes  chain_key_recv    = 6;   // Receiving chain key, 32 bytes
  uint32 send_count        = 7;   // N_s: messages sent in current chain
  uint32 recv_count        = 8;   // N_r: messages received in current chain
  uint32 prev_send_count   = 9;   // PN: messages in previous sending chain
  repeated SkippedKey skipped_keys = 10;
}

message SkippedKey {
  bytes  dh_public         = 1;   // Ratchet public key this skip key belongs to
  uint32 message_counter   = 2;   // Message counter for this skip key
  bytes  message_key       = 3;   // The skip key itself, 32 bytes
}
```

---

## Adding New Messages

1. Add the message definition to the appropriate `.proto` file
2. Run generation commands (Go and Kotlin)
3. Commit generated files alongside the `.proto` change in the same commit
4. Update this README if adding a new `.proto` file
5. Update `docs/standards.md` if the new message affects a protocol boundary

Never add a message that crosses a component boundary (Android ↔ Provider, or Provider ↔ Provider via Nym) without a corresponding entry in this README and in `docs/standards.md`.
