# Evanescent — Architecture

## Overview

Evanescent is a privacy-first messaging system designed to resist a global passive adversary (GPA): a nation-state with access to major internet exchange points capable of observing all network traffic simultaneously.

The system achieves this by combining:
- **Double Ratchet** (per-message forward secrecy, Signal protocol)
- **Sealed sender** (recipient's server cannot identify the sender)
- **Nym mix-net** (Loopix model: Sphinx packets, Poisson delays, cover traffic — defeats timing correlation)
- **Tor hidden services** (server and client IP addresses mutually hidden)

---

## System Components

### 1. Android App

The only user interface. Holds the user's identity keypair. Performs all encryption and decryption locally.

- **Identity**: Ed25519 keypair generated on device. Private key stored in Android Keystore (TEE). Never transmitted.
- **Crypto**: X3DH session establishment, Double Ratchet per-message encryption, sealed sender construction.
- **Storage**: SQLCipher (encrypted SQLite). Room ORM. All data encrypted at rest.
- **Transport**: All connections routed through Orbot (Tor SOCKS5 proxy on 127.0.0.1:9050). No direct internet connections.
- **Provider connection**: WebSocket to the Personal Provider's `.onion` address.

### 2. Provider (Shared / Federated)

A Rust server that may host any number of users. It is each user's permanent presence on the Nym network. Users install only the Android APK and connect to a provider of their choice; no server of their own is required.

**Default provider**: Evanescent ships with a default provider address. Users can switch to any compatible provider at setup time.

**Self-hosting**: Operators can run a provider on any Linux VPS or Raspberry Pi. A Docker Compose configuration is provided. The default provider is operated by the Evanescent project.

**Responsibilities:**
- Connects to the Nym mix-net via the native Rust SDK, maintaining a permanent Nym network connection with a single shared Nym address for all hosted users
- Cover traffic (loop + drop messages at Loopix rate) runs continuously on the server, independent of whether any Android client is connected
- Routes inbound Nym messages to the correct user mailbox using the 32-byte routing tag embedded in every message
- Stores encrypted blobs for offline delivery to Android
- Serves X3DH prekey bundles to requesters (via Nym)
- Exposes a Tor hidden service (`.onion`) for Android connections
- Knows only: which mailboxes received messages (count, timing) — never plaintext, never sender identity

### 3. Nym Mix-Net

External infrastructure, not operated by Evanescent. The Nym network provides:

- **Sphinx packet format**: Fixed 512-byte packets at every hop — no size-based correlation between hops
- **Stratified topology**: Messages traverse exactly L layers of mix nodes; each layer has N nodes
- **Poisson delays**: Each node independently delays by Poisson(λ) — batch reordering defeats timing analysis
- **Decentralized operators**: Mix nodes run by independent parties incentivized via NYM token

The provider integrates with Nym via the `nym-client` binary's WebSocket API (port 1977). Evanescent does not implement Sphinx.

---

## Network Topology

```
Alice's Android
  │
  │ WebSocket over Tor (SOCKS5 via Orbot)
  ▼
Alice's Provider (.onion)          ← shared, may host many users
  │ nym-sdk native client
  │ continuously generates cover traffic for all users
  │
  │ [0x05][bob_mailbox_tag][SealedEnvelope]  (Sphinx via Nym SDK)
  ▼
Nym Mix-Net
  [Layer 1: Mix nodes]
  [Layer 2: Mix nodes]
  [Layer 3: Mix nodes]
  │
  ▼
Bob's Provider (reached via provider's Nym address)
  │ routes to Bob's mailbox using the 32-byte routing tag
  │ stores encrypted blob
  │
  │ WebSocket over Tor
  ▼
Bob's Android (fetches when online)
```

---

## Encryption Layers

Three independent layers. Each can be compromised independently without exposing the others.

### Layer 1 — Content (Double Ratchet)

- Applied by the Android app before sending to the provider.
- Only Bob's device can decrypt. The provider and Nym never see plaintext.
- Forward secrecy: a compromised key does not expose past messages.
- Break-in recovery: a compromised key does not expose future messages indefinitely; the ratchet heals.

### Layer 2 — Sender Identity (Sealed Sender)

- Applied by the Android app, wrapping the Double Ratchet ciphertext.
- Bob's provider stores a `SealedEnvelope` but cannot read the sender's identity.
- Bob's device decrypts the envelope and learns the sender identity only after successful decryption.
- Uses an ephemeral X25519 keypair per message; ephemeral key is discarded after send.

### Layer 3 — Transport (Nym Mix-Net + Sphinx)

- Applied by the `nym-client` sidecar on the provider.
- The GPA sees only Sphinx packets of uniform size with Poisson-distributed timing.
- No node in the mix-net knows both the origin and the destination of a message.

---

## Message Flow

### Sending (Alice → Bob)

```
1. Alice opens app. Connects to her provider via Tor (.onion).

2. Alice needs Bob's prekeys (first message or prekey exhaustion):
   Alice's provider → Nym mix-net → Bob's provider → returns PreKeyBundle
   (Bob's provider cannot link this request to Alice — no identity presented)

3. X3DH key agreement:
   Alice runs X3DH locally using Bob's PreKeyBundle.
   Shared master secret → initialises Double Ratchet session.

4. Alice composes message. App encrypts:
   a. Double Ratchet → dr_ciphertext
   b. Sealed sender wraps dr_ciphertext → SealedEnvelope
   c. App sends SealedEnvelope to provider via WebSocket

5. Provider receives SealedEnvelope:
   - Wraps in Nym message: [0x05][bob_mailbox_addr_32B][SealedEnvelope]
   - Sends to Bob's provider's Nym address via the SDK
   - Returns SendAck to Android

6. Nym mix-net routes the message through L layers.
   Cover traffic from Alice's provider continues uninterrupted.

7. Bob's provider receives Sphinx packet (via its nym-client):
   - Stores SealedEnvelope bytes under Bob's mailbox slot
   - Records received_at timestamp
   - Does not log sender (sealed sender — sender unknown)
```

### Receiving (Bob fetches)

```
8. Bob's Android connects to his provider via Tor.

9. Android sends FetchMessages (ack_ids of previously received messages).

10. Provider delivers stored SealedEnvelope items.

11. Android decrypts:
    a. Sealed sender decryption → SealedSenderContent (reveals sender identity)
    b. Double Ratchet decryption → plaintext
    c. Double Ratchet state advances

12. Android sends FetchMessages again with ack_ids to confirm delivery.
    Provider deletes confirmed messages.
```

---

## Identity Model

**No phone numbers. No email addresses. No account registration.**

### User Identity

```
identity_key      Ed25519 keypair. Root of trust. Generated once, stored in TEE.
mailbox_address   BLAKE3(identity_key_public)[0:32], hex. Used as mailbox index.
nym_address       The provider's Nym address. Used for mix-net routing.
```

### Contact Exchange

Users share a `ContactBundle` out-of-band (QR code, secure link):

```
ContactBundle {
  identity_key:    <Ed25519 pubkey, 32 bytes>
  mailbox_addr:    <BLAKE3(identity_key)[0:32], 32 bytes>  ← routing tag on the wire
  nym_address:     <recipient provider's Nym address>       ← where to send Nym messages
  provider_onion:  <recipient provider's .onion address>    ← shared by all users on that provider
  version:         1
}
```

Encoded as base64url (no padding) for QR codes.

**Note**: `nym_address` and `provider_onion` identify the provider, not the individual user. `mailbox_addr` identifies the user within the provider and is used as the routing tag on all Nym messages.

### Safety Numbers

For out-of-band identity verification (prevent MITM during contact exchange):

```
safety_number = SHA256( sort(IK_alice, IK_bob) concatenated )[0:30]
Displayed as: 5 groups of 6 decimal digits
```

---

## Provider Architecture (Rust)

```
backend/src/
  main.rs        Startup, inbound Nym message router
  config.rs      YAML config (nym data dir, Tor ports, DB path, log level)

  nym_client.rs  Nym SDK integration (native Rust)
                 - MixnetClientBuilder → persistent on-disk keys
                 - shared Nym address for all hosted users
                 - cover traffic handled automatically by Loopix (SDK)
                 - wire format: [prefix 1B][routing_tag 32B][payload]

  mailbox.rs     Offline message store
                 - SQLite via sqlx
                 - stores SealedEnvelope bytes + metadata per mailbox_addr
                 - 30-day TTL enforcement

  prekeys.rs     X3DH prekey management
                 - stores signed prekeys and one-time prekeys per mailbox_addr
                 - serves PreKeyBundle on Nym prekey requests

  onion.rs       Tor hidden service
                 - raw Tor control protocol
                 - creates and maintains .onion address

  store.rs       SQLite schema (idempotent CREATE IF NOT EXISTS)

  crypto.rs      Ed25519 auth + SPK signature verification, mailbox_addr derivation

  ws/
    mod.rs       axum WebSocket router, AppState
    auth.rs      Challenge-response auth, mailbox auto-registration on first connect
    handler.rs   FetchMessages, SendMessage (→ Nym), UploadPreKeys
    session.rs   Per-connection state + rate limiting
    errors.rs    Error code constants
```

---

## Android Architecture (Kotlin)

```
net.evanescent/
  crypto/
    KeyGenerator.kt        Ed25519 + X25519 key generation via Android Keystore
    X3DH.kt               X3DH session establishment
    DoubleRatchet.kt       Double Ratchet session management
    SealedSender.kt        Sealed sender construction and verification
    SafetyNumber.kt        Safety number computation

  provider/
    ProviderClient.kt      WebSocket client (OkHttp, routed through Orbot SOCKS5)
    MessageQueue.kt        Outbound message queue with SendAck tracking
    PreKeyManager.kt       Prekey upload and replenishment

  db/
    Database.kt            SQLCipher Room database
    ContactDao.kt
    SessionDao.kt
    MessageDao.kt
    PreKeyDao.kt

  ui/
    ConversationList.kt    Main screen
    Conversation.kt        Message thread
    ContactAdd.kt          QR code scanner for ContactBundle
    SafetyNumber.kt        Safety number verification screen
    Settings.kt

  model/
    Contact.kt
    Message.kt
    Session.kt

  service/
    ProviderService.kt     Background service maintaining WebSocket connection
```

---

## Threat Model Summary

| Adversary | Capability | Mitigation | Residual |
|---|---|---|---|
| Provider operator | Full server access | Sealed sender; Double Ratchet E2E; no logs | Knows Bob's mailbox received messages (count, timing) |
| Nym mix node | See incoming+outgoing packets for that node | Stratified topology; Poisson delay; Sphinx fixed size | Single node sees neither origin nor destination |
| GPA (full internet view) | Observe all traffic | Nym Loopix model; cover traffic from provider | Negligible — Poisson batching defeats statistical correlation |
| Provider sees Android IP | IP of connecting client | Tor .onion; Android connects via Orbot | Provider sees Tor exit node only |
| Provider's IP exposed | Server location | Tor hidden service | Provider IP hidden |
| Google via FCM | Push notification timing | No FCM — polling via Tor | Minor: poll interval reveals rough activity window |
| Device seizure | Full device access | SQLCipher + TEE-backed key | Past messages protected by forward secrecy |

For the full threat model analysis see [threat-model.md](threat-model.md).
