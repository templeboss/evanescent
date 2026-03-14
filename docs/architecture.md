# Evanescent — Architecture

## Overview

Evanescent is a privacy-first messaging system. Its goal is to protect message content, sender identity, and communication metadata from a well-resourced adversary, including entities with broad visibility into internet traffic.

The system provides three independent layers of protection:

- **Double Ratchet** (per-message forward secrecy, Signal protocol): only the recipient's device can decrypt messages
- **Sealed sender** (sender anonymity): the recipient's provider cannot identify who sent a given message
- **Tor transport**: all network paths run through Tor, concealing IP addresses and routing from passive observers

Transport is Tor-based, not mix-net-based. Tor provides strong IP anonymity and route concealment but does not provide the timing-correlation resistance of a Loopix-style mix-net. This trade-off is described honestly in the [threat model](threat-model.md).

---

## System Components

### 1. Android App

The only user interface. Holds the user's identity keypair. Performs all encryption and decryption locally.

- **Identity**: Ed25519 keypair generated on device. Private key stored in Android Keystore (TEE). Never transmitted.
- **Crypto**: X3DH session establishment, Double Ratchet per-message encryption, sealed sender construction and verification.
- **Storage**: SQLCipher (encrypted SQLite). Room ORM. All data encrypted at rest.
- **Transport**: Embedded Tor (tor-android library). Tor bootstraps silently on first launch; no external Tor client (Orbot) is required. All connections route through the embedded Tor instance. No direct internet connections.
- **Provider connection**: WebSocket to the provider's `.onion` address, over the embedded Tor.

### 2. Provider (Shared / Federated)

A Rust server that may host any number of users. It is each user's permanent network presence. Users install only the Android APK and connect to a provider of their choice; no server of their own is required.

**Default provider**: Evanescent ships with a default provider address. Users can switch to any compatible provider at setup time.

**Self-hosting**: Operators can run a provider on any Linux VPS or Raspberry Pi. A Docker Compose configuration is provided.

**Responsibilities:**
- Exposes a Tor hidden service (`.onion`) for Android client connections
- Routes outbound messages to other providers via HTTP over its own Tor SOCKS5 proxy (127.0.0.1:9050)
- Stores encrypted blobs for offline delivery to Android clients
- Serves X3DH prekey bundles to requesting providers
- Forwards prekey bundle responses to the requesting Android client
- Knows only: which mailboxes received messages (count, timing) — never plaintext, never sender identity

### 3. Tor

All network communication passes through Tor:

- Android clients use the embedded tor-android library. The app connects to its provider's `.onion` address via this embedded Tor instance.
- The provider exposes itself as a Tor hidden service. Its clearnet IP address is never published.
- Inter-provider communication (deliver and prekey requests) is made via HTTP to other providers' `.onion` addresses, routed through the provider's own Tor SOCKS5 proxy.

---

## Network Topology

```
Alice's Android (embedded Tor)
  │
  │  WebSocket over Tor (.onion)
  ▼
Alice's Provider (.onion)           ← shared, may host many users
  │
  │  HTTP over Tor SOCKS5 (127.0.0.1:9050)
  │  POST /api/v1/deliver  or  GET /api/v1/prekeys/{mailbox_hex}
  ▼
Bob's Provider (.onion)
  │
  │  WebSocket over Tor (.onion)
  ▼
Bob's Android (embedded Tor)
```

All arrows represent Tor-protected connections. No leg of this path is clearnet.

---

## Encryption Layers

Three independent layers. Each can be compromised independently without exposing the others.

### Layer 1 — Content (Double Ratchet)

- Applied by the Android app before sending to the provider.
- Only Bob's device can decrypt. The provider never sees plaintext.
- Forward secrecy: a compromised key does not expose past messages.
- Break-in recovery: the ratchet heals after a compromise — future messages are protected once new keys are exchanged.

### Layer 2 — Sender Identity (Sealed Sender)

- Applied by the Android app, wrapping the Double Ratchet ciphertext.
- Bob's provider stores a `SealedEnvelope` but cannot read the sender's identity.
- Bob's device decrypts the envelope and learns the sender identity only after successful decryption.
- Uses an ephemeral X25519 keypair per message; the ephemeral key is discarded after send.

### Layer 3 — Transport (Tor)

- All connections between Android and provider, and between providers, run over Tor.
- Neither the provider nor a network observer sees the client's real IP address.
- Provider-to-provider HTTP requests are routed through the provider's Tor SOCKS5 proxy, so Bob's provider sees a request arriving from Tor — not from Alice's provider's clearnet IP.

---

## Message Flow

### Sending (Alice → Bob)

```
1. Alice opens the app. The embedded Tor instance bootstraps (~10 seconds on first launch).
   Alice connects to her provider via WebSocket over Tor (.onion).

2. Alice needs Bob's prekeys (first message or prekey exhaustion):
   Alice's app sends GetPreKeys { provider_onion: bob_provider.onion, mailbox_addr: bob_mailbox }
   to her provider.

3. Alice's provider fetches Bob's prekeys:
   HTTP GET bob_provider.onion/api/v1/prekeys/{bob_mailbox_hex}  via Tor SOCKS5
   Bob's provider returns a PreKeyBundle proto.
   Alice's provider forwards the bundle to Alice's app as a PreKeys WS message.

4. X3DH key agreement:
   Alice's app runs X3DH locally using Bob's PreKeyBundle.
   Shared master secret → initialises Double Ratchet session.

5. Alice composes message. App encrypts:
   a. Double Ratchet → dr_ciphertext
   b. Sealed sender wraps dr_ciphertext → SealedEnvelope
   c. App sends SendMessage WS {
        to_provider_onion: bob_provider.onion,
        to_mailbox_addr:   bob_mailbox (32 bytes),
        sealed_envelope:   <bytes>
      }

6. Alice's provider delivers to Bob's provider:
   HTTP POST bob_provider.onion/api/v1/deliver  via Tor SOCKS5
   Body: DeliverRequest { mailbox_addr: bob_mailbox, sealed_envelope: <bytes> }
   Returns SendAck to Alice's Android.

7. Bob's provider stores the SealedEnvelope under Bob's mailbox slot.
   Records received_at timestamp.
   Does not log sender (sealed sender — sender unknown to the provider).
```

### Receiving (Bob fetches)

```
8. Bob's Android connects to his provider via WebSocket over Tor.

9. Android sends FetchMessages (with ack_ids of previously received messages).

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
mailbox_addr      BLAKE3(identity_key_public)[0:32], 32 bytes. Mailbox index and routing tag.
```

### Contact Exchange

Users share a `ContactBundle` out-of-band (QR code, secure link):

```
ContactBundle {
  identity_key:    <Ed25519 pubkey, 32 bytes>              field 1
  reserved:        <empty>                                  field 2  (was nym_address)
  provider_onion:  <provider's .onion address, string>      field 3
  version:         2                                        field 4
  mailbox_addr:    <BLAKE3(identity_key)[0:32], 32 bytes>   field 5
}
```

Encoded as base64url (no padding) for QR codes.

`provider_onion` identifies the provider; `mailbox_addr` identifies the user within the provider. Both are required to send a message.

### Safety Numbers

For out-of-band identity verification (preventing MITM during contact exchange):

```
safety_number = SHA256( sort(IK_alice, IK_bob) concatenated )[0:30]
Displayed as: 5 groups of 6 decimal digits
```

Users compare safety numbers in person or via a trusted channel to confirm no MITM occurred during contact exchange.

---

## Provider Architecture (Rust)

```
backend/src/
  main.rs        Startup, HTTP and WebSocket router, AppState initialisation

  config.rs      YAML config (Tor ports, DB path, onion key path, log level)

  relay.rs       Inter-provider relay
                 - outbound HTTP via Tor SOCKS5 (127.0.0.1:9050)
                 - POST /api/v1/deliver  → DeliverRequest proto
                 - GET  /api/v1/prekeys/{mailbox_hex}  → PreKeyBundle proto
                 - inbound /api/v1/deliver handler: validates mailbox_addr, stores envelope

  mailbox.rs     Offline message store
                 - SQLite via sqlx
                 - stores SealedEnvelope bytes + metadata per mailbox_addr
                 - 30-day TTL enforcement

  prekeys.rs     X3DH prekey management
                 - stores signed prekeys and one-time prekeys per mailbox_addr
                 - serves PreKeyBundle on inbound /api/v1/prekeys requests

  onion.rs       Tor hidden service
                 - raw Tor control protocol
                 - creates and maintains .onion address

  store.rs       SQLite schema (idempotent CREATE IF NOT EXISTS)

  crypto.rs      Ed25519 auth + SPK signature verification, mailbox_addr derivation

  ws/
    mod.rs       axum WebSocket router, AppState
    auth.rs      Challenge-response auth, mailbox auto-registration on first connect
    handler.rs   FetchMessages, SendMessage (→ relay.rs), UploadPreKeys,
                 GetPreKeys (→ relay.rs → PreKeys response), ProviderInfo on AuthOk
    session.rs   Per-connection state + rate limiting
    errors.rs    Error code constants
```

### Inter-Provider HTTP API

```
POST /api/v1/deliver
  Body:    DeliverRequest { mailbox_addr: bytes, sealed_envelope: bytes }
  Returns: 200 OK on success

GET /api/v1/prekeys/{mailbox_addr_hex}
  Returns: PreKeyBundle proto
```

Both endpoints are reachable only via the provider's `.onion` address.

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
    TorManager.kt          Embedded Tor lifecycle (tor-android library)
                           Bootstraps on app start, provides SOCKS5 on localhost
    ProviderClient.kt      WebSocket client (OkHttp, routed through embedded Tor SOCKS5)
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
| Provider operator | Full server access | Sealed sender; Double Ratchet E2E; no plaintext logs | Knows mailbox received messages (count, timing) |
| Network observer on one path | See traffic on that segment | Tor routing; onion encryption | Sees only Tor traffic, not content or parties |
| GPA (full internet view) | Observe all traffic simultaneously | Tor routes traffic through multiple hops | Tor-level protection only — timing correlation by a GPA is an acknowledged residual risk |
| Provider sees Android IP | IP of connecting client | Embedded Tor; .onion connection avoids exit nodes | Provider sees Tor, not client IP |
| Provider's IP exposed | Server location | Tor hidden service | Provider IP not published; hidden service deanonymisation is a known Tor limitation |
| Google via FCM | Push notification timing | No FCM — polling via WebSocket over Tor | Poll interval reveals rough activity window |
| Device seizure | Full device access | SQLCipher + TEE-backed key; Double Ratchet forward secrecy | Unlocked device exposes stored messages |

For the full threat model analysis see [threat-model.md](threat-model.md).
