# Evanescent — Provider (Backend)

## Role

The provider is a long-running Rust server that acts as a persistent presence for one or more users. The Android app is ephemeral; the provider is not.

**What this server does:**
1. Maintains a Tor hidden service (`.onion`) for Android clients to connect to
2. Authenticates Android clients via challenge-response over WebSocket
3. Receives messages from other providers via HTTP over Tor and stores them encrypted for offline delivery
4. Serves the user's X3DH prekey bundles to other providers on request
5. Relays outbound messages to recipient providers via Tor SOCKS5

**What this server does NOT do:**
- It never decrypts any message content
- It never stores the user's identity private key
- It never logs sender identities (sealed sender ensures it cannot)
- It never connects to clearnet on behalf of the user
- It never exposes any clearnet HTTP endpoint

---

## Technology Stack

| Component | Choice | Version |
|---|---|---|
| Language | Rust | stable (2021 edition) |
| Async runtime | tokio | 1.x |
| WebSocket server | axum | 0.7 |
| HTTP client (inter-provider) | reqwest | 0.12 |
| SQLite | sqlx | 0.8 |
| Proto serialization | prost | 0.12 |
| Tor integration | raw TCP control protocol | — |
| Config | serde_yaml | 0.9 |
| Logging | tracing + tracing-subscriber | — |
| Crypto | ed25519-dalek 2.x, blake3 | — |

---

## Project Structure

```
backend/
  Cargo.toml
  build.rs          prost-build: compiles proto/*.proto

  src/
    main.rs         Entry point — startup, routes, graceful shutdown
    config.rs       YAML config
    store.rs        SQLite schema + migrations
    mailbox.rs      Mailbox CRUD + 30-day TTL
    prekeys.rs      Signed prekey + OTP store + rotation
    crypto.rs       Ed25519 auth verification, mailbox_addr derivation
    onion.rs        Tor hidden service (raw control protocol)
    relay.rs        Outbound HTTP client via Tor SOCKS5 (inter-provider delivery + prekey fetch)

    proto/
      mod.rs        prost-generated types

    ws/
      mod.rs        axum WebSocket server + inter-provider HTTP routes, AppState
      auth.rs       Challenge-response auth
      handler.rs    FetchMessages, SendMessage, GetPreKeys, UploadPreKeys, Ping
      session.rs    Per-connection state
      errors.rs     Error code constants
```

---

## Configuration

Config file path passed as `--config <path>` (all fields optional; defaults shown).

```yaml
# provider.yaml

tor:
  control_port: 9051
  socks_port: 9050      # Tor SOCKS5 proxy port (used for inter-provider relay)
  ws_port: 8765         # internal WebSocket port (loopback only)
  hidden_service_port: 443

storage:
  db_path: /var/lib/evanescent/provider.db

logging:
  level: info           # debug | info | warn | error
  format: json          # json | text
```

---

## Building

```bash
cd backend

# Debug build (required on first run to generate proto types via build.rs)
cargo build

# Release binary
cargo build --release

# Lint (no warnings policy)
cargo clippy -- -D warnings
```

The `build.rs` script runs `prost-build` on first compilation, generating
`$OUT_DIR/evanescent.v1.rs` from the `.proto` files in `../proto/`.

---

## Running

Prerequisites:
1. Tor daemon running with `ControlPort 9051` and `SocksPort 9050` in torrc (unauthenticated or cookie auth)
2. Config file written

```bash
./target/release/evanescent-provider --config /etc/evanescent/provider.yaml
```

On first run, the provider will:
1. Initialise the SQLite database (WAL mode)
2. Create the Tor hidden service (generates `.onion` key via Tor daemon)
3. Print the `.onion` address to stdout — **save this for the ContactBundle**
4. Begin accepting WebSocket connections on the `.onion` address

---

## WebSocket Protocol

All frames are proto3 binary (`WsClientMessage` / `WsServerMessage` from `proto/ws.proto`).

**Full protocol specification**: see [docs/standards.md — §7](../docs/standards.md#7-websocket-protocol-android--provider)

Key invariants enforced by this server:
- Reject all messages before authentication completes (`AUTH_REQUIRED`)
- Never log `sealed_envelope` bytes or their length
- Max frame size: 512 KB — connection closed on violation
- Outbound queue: 100 frames — return `QUEUE_FULL` error, never block
- Deliver messages in `received_at` order (oldest first)

---

## Inter-Provider API

Both endpoints are served on the same port as the WebSocket server, via the Tor hidden service.

```
POST /api/v1/deliver
  Receives a message from another provider and stores it in the recipient's mailbox.

GET /api/v1/prekeys/:mailbox_addr
  Returns a PreKeyBundle proto for the given mailbox address.
```

Request and response bodies are proto3 binary (`Content-Type: application/x-protobuf`).

Authentication is not required at the HTTP level. The `.onion` address provides transport-level authentication — a provider can only be reached by another party that already knows its address.

---

## Prekey Management

**Storage:** signed prekeys and one-time prekeys are uploaded from Android via the `UploadPreKeys` WS message and stored in SQLite.

**Serving prekey bundles (via `GET /api/v1/prekeys/:mailbox_addr`):**
1. Read current signed prekey (fallback to most recent if all expired)
2. Pop one OTP key from pool (FIFO); serve bundle without OTP key if pool is empty
3. Return `PreKeyBundle` proto in response body

**OTP replenishment threshold:** 20 keys (`OTPK_REPLENISH_THRESHOLD` in `prekeys.rs`).

---

## Storage Schema

See `src/store.rs` (embedded `SCHEMA` constant) for authoritative DDL.

Tables: `mailboxes`, `messages`, `signed_prekeys`, `one_time_prekeys`.

TTL: messages older than 30 days are deleted daily by `MailboxStore::spawn_ttl_cleaner`.
SPK rotation: expired signed prekeys are pruned daily by `PrekeyStore::spawn_rotation`.

---

## What NOT to Do

- Do not add clearnet HTTP endpoints
- Do not log message content, envelope bytes, or envelope sizes
- Do not store any key that belongs on the Android device (identity private key, Double Ratchet state)
- Do not add JSON wire format between Android and provider (use proto binary)
- Do not add JSON wire format for inter-provider HTTP (use proto binary)
