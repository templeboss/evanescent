# Evanescent — Personal Provider (Backend)

## Role

The Personal Provider is a long-running Rust server operated on behalf of a user. It is the user's permanent presence on the Nym network. The Android app is ephemeral; this server is not.

**What this server does:**
1. Runs the Nym SDK natively (no subprocess) and maintains a persistent Nym network connection with automatic cover traffic (Loopix loop/drop)
2. Receives messages from the Nym network and stores them encrypted for offline delivery
3. Serves the user's X3DH prekey bundles to other users (via Nym)
4. Exposes a Tor hidden service (`.onion`) for the Android app to connect to
5. Authenticates the Android app via challenge-response and delivers stored messages over WebSocket

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
| Nym transport | `nym-sdk` (native SDK) | git master |
| SQLite driver | `rusqlite` (bundled C) | 0.31 |
| Tor control | raw TCP control protocol | — |
| WebSocket server | `axum` 0.7 | — |
| Proto codegen | `prost-build` | 0.12 |
| Config | `serde_yaml` | 0.9 |
| Logging | `tracing` + `tracing-subscriber` | — |
| Crypto | `ed25519-dalek` 2.x | — |

---

## Project Structure

```
backend/
  Cargo.toml          Package manifest
  build.rs            prost-build: compiles proto/*.proto → src/proto/

  src/
    main.rs           Entry point — wires all subsystems, handles graceful shutdown
    config.rs         serde_yaml config structs + defaults
    store.rs          SQLite open + WAL + schema migration
    mailbox.rs        Message CRUD + 30-day TTL cleaner task
    prekeys.rs        SPK store + OTP pool + rotation task
    crypto.rs         Ed25519 verify_auth, verify_spk, mailbox_addr_from_key
    onion.rs          Tor hidden service via raw TCP control protocol (ADD_ONION)
    nym_client.rs     Nym SDK: connect, send, receive loop, inbound router

    proto/
      mod.rs          include!(OUT_DIR/evanescent.v1.rs) — prost-generated types

    ws/
      mod.rs          axum WebSocket server, AppState, connection lifecycle
      auth.rs         Challenge-response authentication (start_challenge, verify_response)
      handler.rs      Post-auth dispatch: FetchMessages, SendMessage, UploadPreKeys, Ping
      session.rs      Per-connection state (owned by read-loop task, no locks needed)
      errors.rs       Error code string constants per standards.md §14
```

---

## Configuration

Config file path passed as `--config <path>` (all fields optional; defaults shown).

```yaml
# provider.yaml

nym:
  data_dir: /var/lib/evanescent/nym    # Nym SDK stores identity here; persisted across restarts
  gateway: null                         # null = auto-select from network

tor:
  control_port: 9051
  ws_port: 8765                         # internal WebSocket port (loopback only)
  hidden_service_port: 443              # external port on .onion address

storage:
  db_path: /var/lib/evanescent/provider.db

logging:
  level: info                           # debug | info | warn | error
  format: json                          # json | text
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
1. Tor daemon running with `ControlPort 9051` in torrc (unauthenticated or cookie auth)
2. Config file written

```bash
./target/release/evanescent-provider --config /etc/evanescent/provider.yaml
```

On first run, the provider will:
1. Initialise the SQLite database (WAL mode)
2. Initialise the Nym SDK client (generates Nym identity in `nym.data_dir` if not present)
3. Create the Tor hidden service (generates `.onion` key via Tor daemon)
4. Print the `.onion` address and Nym address to stdout — **save these for the ContactBundle**
5. Begin accepting WebSocket connections on the `.onion` address

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

## Nym Integration

The Nym SDK client runs natively in-process via `nym_client.rs`. Cover traffic
(Loopix loop and drop messages) is **automatic** — the SDK handles this; no manual
scheduling is needed.

**Inbound routing prefix bytes:**
- `0x01` → prekey bundle request (TODO: parse + respond)
- `0x02` → loop cover — discard silently
- `0x03` → drop cover — discard silently
- other → sealed envelope for mailbox store

**Send:** `NymHandle::send(to_nym_addr, payload)` — async, buffered via mpsc channel.

---

## Prekey Management

**Storage:** signed prekeys and one-time prekeys are uploaded from Android via
`UploadPreKeys` WS message and stored in SQLite.

**Serving prekey bundles (via Nym, inbound `0x01` prefix):**
1. Read current signed prekey (fallback to most recent if all expired)
2. Pop one OTP key from pool (FIFO); serve bundle without OTP key if pool is empty
3. Respond via `nym.send(reply_addr, PreKeyBundle.encode_to_vec())`

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
- Do not implement Sphinx packet construction (Nym SDK's responsibility)
- Do not add JSON wire format between Android and provider (use proto binary)
- Do not write manual cover traffic — Nym SDK handles this automatically
