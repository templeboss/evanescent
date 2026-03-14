# Evanescent

A privacy-first end-to-end encrypted messaging system with Signal-grade cryptography and Tor transport.

Evanescent is designed for users who need strong protection against network-level surveillance. It routes all traffic through Tor and applies three independent layers of cryptographic protection, so that even a party who can observe the network or operate the server infrastructure cannot identify message content or sender identity.

> **Status**: Pre-alpha. Implementation in progress (Rust backend + Android client). Not for production use.

---

## Protection Layers

Evanescent combines three independent layers of protection. Each layer can be compromised without exposing the others:

| Layer | Mechanism | What it protects |
|---|---|---|
| Content | Double Ratchet (Signal protocol) | Message plaintext — only the recipient's device can decrypt |
| Sender identity | Sealed sender (ephemeral X25519 per message) | The recipient's server cannot identify who sent a message |
| Transport | Tor (embedded in Android APK; Tor hidden services on providers) | IP addresses and routing — neither party's IP is visible to the other |

---

## Repository Structure

```
evanescent/
  README.md              this file
  proto/                 canonical .proto definitions (wire format source of truth)
    README.md
  backend/               Provider server (Rust)
    README.md
    src/
      crypto/            Ed25519 auth, SPK verification, mailbox_addr derivation
      mailbox/           encrypted offline message store
      prekeys/           prekey store and rotation
      onion/             Tor hidden service management
      relay.rs           inter-provider HTTP relay via Tor
      ws/                WebSocket server (Android ↔ Provider)
    build.rs             compiles proto/ via prost-build
    Cargo.toml
  android/               Android client (Kotlin)
    README.md
    app/src/main/kotlin/net/evanescent/
      crypto/            X3DH, Double Ratchet, sealed sender
      provider/          WebSocket client + embedded Tor (TorManager)
      db/                SQLCipher storage
      ui/                Jetpack Compose
      model/             domain models
  docs/
    architecture.md      full system architecture
    threat-model.md      threat model and adversary analysis
    standards.md         canonical engineering standards
```

---

## Component Roles

| Component | Language | Role |
|---|---|---|
| `proto/` | Proto3 | Single source of truth for all wire formats. Both Rust and Android code is generated from these definitions. |
| `backend/` | Rust (2021 edition) | Provider: mailbox storage, Tor hidden service, prekey server, inter-provider relay |
| `android/` | Kotlin (API 26+) | User-facing app: all encryption locally, embedded Tor, WebSocket to provider, Jetpack Compose UI |

---

## How It Works

Each user connects to a **provider** — a Rust server that:
- Stores encrypted messages when the Android app is offline (it never sees plaintext)
- Serves the user's X3DH prekey bundles to other providers on request
- Relays outbound messages to other providers via HTTP over its own Tor proxy
- Exposes itself as a Tor hidden service (`.onion`) so Android clients connect without revealing their IP address

The Android app:
- Holds the user's identity keypair (never leaves the device)
- Performs all encryption locally (X3DH + Double Ratchet + sealed sender)
- Uses an embedded Tor library — no external Tor client is required; the user installs one APK and Tor bootstraps silently on first launch
- Connects to its provider exclusively through Tor; sends nothing over clearnet

Message path: `Android → [embedded Tor] → Provider (.onion) → [Tor SOCKS5] → Recipient's Provider (.onion) → [Tor] → Recipient's Android`

Contact exchange is out-of-band (QR code). No phone numbers, no email addresses, no account registration.

---

## Documentation

- [Architecture](docs/architecture.md) — detailed system design, message flow, component reference
- [Threat Model](docs/threat-model.md) — adversary model, mitigations, and explicit residual risks
- [Standards](docs/standards.md) — canonical crypto constants, wire format rules, version policy

---

## Development Setup

**Rust (backend)**
- Rust 1.85 or later (stable toolchain)
- SQLite development libraries
- Tor (for the provider's hidden service; can run locally for development)
- Proto compilation is handled automatically by `build.rs` via `prost-build` and `protoc-bin-vendored` — no system `protoc` required

**Android**
- Android SDK, API 26 minimum / API 35 target
- Kotlin 2.0+
- NDK (required by tor-android)

See [backend/README.md](backend/README.md) and [android/README.md](android/README.md) for component-specific setup instructions.

---

## Design Principles

1. **The server learns nothing actionable.** A fully compromised provider yields only ciphertext, anonymous mailbox activity counts, and approximate timing. No sender identities, no plaintext, no communication graph.
2. **No trusted parties.** Providers are designed to be self-hosted or operated by independent parties. The system assumes providers are potentially adversarial.
3. **Crypto agility is a trap.** Algorithms are fixed per protocol version. There are no negotiable cipher suites. See [standards.md](docs/standards.md).
4. **The proto is law.** All wire formats are defined in `proto/`. No ad-hoc serialisation between components.
5. **No external dependencies on the client.** The Android APK includes everything required: embedded Tor, all cryptographic primitives. The user installs one file and the system works.
