# Evanescent

A privacy-first end-to-end encrypted messaging system targeting resilience against global passive adversaries (GPA) — nation-state-level surveillance infrastructure with access to major internet exchange points.

Evanescent combines three independent layers of protection:

1. **Content encryption** — Double Ratchet (Signal protocol), meaning no server or relay ever sees plaintext
2. **Sender anonymity** — Sealed sender, meaning no relay knows who sent a given message
3. **Transport anonymity** — Nym mix-net (Loopix model), meaning no observer can correlate sender and recipient via traffic analysis

> **Status**: Pre-alpha. Implementation phase (Rust backend + Android client). No production use.

---

## Repository Structure

```
evanescent/
  README.md              ← this file
  proto/                 ← canonical .proto definitions (source of truth for all wire formats)
    README.md
  backend/               ← Personal Provider server (Rust)
    README.md
    src/
      crypto/            ← X3DH, prekey bundle validation
      mailbox/           ← encrypted offline message store
      prekeys/           ← prekey store and rotation
      onion/             ← Tor hidden service management
      ws/                ← WebSocket server (Android ↔ Provider)
    build.rs             ← compiles proto/ via prost-build
    Cargo.toml
  android/               ← Android client (Kotlin)
    README.md
    app/src/main/kotlin/net/evanescent/
      crypto/            ← X3DH, Double Ratchet, sealed sender
      provider/          ← WebSocket client (via Tor/Orbot)
      db/                ← SQLCipher storage
      ui/                ← Jetpack Compose
      model/             ← domain models
  docs/
    architecture.md      ← full system architecture
    threat-model.md      ← threat model and adversary analysis
    standards.md         ← CANONICAL standards — read before writing any code
```

---

## Component Roles

| Component | Language | Role |
|---|---|---|
| `proto/` | Proto3 | Single source of truth for all wire formats. Both Rust and Android generated from this. |
| `backend/` | Rust (2021) | Personal Provider: runs Nym client, cover traffic, mailbox storage, Tor hidden service, prekey server |
| `android/` | Kotlin (API 26+) | User-facing app: crypto layer, Tor connection to provider, UI |

---

## How It Works (Brief)

Each user runs or is assigned a **Personal Provider** — a Rust server that:
- Maintains a permanent Nym network connection (mix-net routing)
- Generates continuous cover traffic so the user's activity pattern is never visible
- Stores encrypted messages when the Android app is offline
- Exposes itself as a Tor hidden service (`.onion`) so Android connects without revealing the user's IP

The Android app:
- Holds the user's identity keypair (never leaves the device)
- Performs all encryption locally (X3DH + Double Ratchet + sealed sender)
- Connects to its Personal Provider exclusively through Tor (Orbot)
- Sends clearnet nothing — ever

Message routing: `Android → [Tor] → Personal Provider → [Nym mix-net] → Recipient's Provider → [Tor] → Recipient's Android`

---

## Documentation

- [Architecture](docs/architecture.md) — detailed system design
- [Threat Model](docs/threat-model.md) — adversary model and mitigations
- **[Standards](docs/standards.md) — all agents must read this first**

---

## Development Setup

Requirements:
- Rust (2021 edition, stable toolchain)
- Kotlin / Android SDK (API 26+, target API 35)
- protoc (proto compilation handled automatically by `build.rs` via prost-build)
- Tor (for provider hidden service)

See [backend/README.md](backend/README.md) and [android/README.md](android/README.md) for component-specific setup.

---

## Design Principles

1. **No metadata survives.** The system is designed so that even a fully compromised server gives an adversary nothing actionable — no sender identities, no communication graphs, no timing information.
2. **No trusted parties.** The Personal Provider is designed to be self-hosted. No party in the system is trusted with meaningful data.
3. **Crypto agility is a trap.** Algorithms are fixed per protocol version. There are no negotiable cipher suites. See [standards.md](docs/standards.md).
4. **The proto is law.** All wire formats are defined in `proto/`. No ad-hoc JSON structures between components.
5. **Cover traffic is not optional.** The provider runs cover traffic at all times regardless of user activity. It cannot be disabled without breaking the anonymity guarantees.
