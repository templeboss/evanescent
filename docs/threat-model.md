# Evanescent — Threat Model

## Adversary Definition

The primary adversary is a **Global Passive Adversary (GPA)**: an entity with read access to all network traffic at major internet exchange points. This corresponds to nation-state intelligence agencies operating surveillance programs at internet infrastructure level.

Secondary adversaries: malicious server operators, ISPs, and dragnet surveillance systems operating below GPA capability.

Out of scope: active adversaries who compromise endpoints (device seizure, malware). Partial mitigations exist but endpoint compromise is not a solved problem in any messaging system.

---

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| Message content | The actual text/media sent | Critical |
| Communication graph | Who talks to whom | Critical |
| Sender identity | Who sent a specific message | Critical |
| Message timing | When messages are sent/received | High |
| Social graph | Who a user's contacts are | High |
| Device identity | Linking a device to a real person | High |
| Location (IP) | Where the user is connecting from | High |
| Activity patterns | When a user is online | Medium |
| Message volume | How many messages sent | Medium |

---

## Threat Analysis

### T1 — Server reads message content

**Attack**: The provider operator (or an adversary who compromises the provider) reads stored messages.

**Mitigation**: Double Ratchet end-to-end encryption. The provider stores only ciphertext (`SealedEnvelope` bytes). The provider never possesses any key material needed to decrypt. Breaking this requires breaking X25519 or ChaCha20-Poly1305.

**Residual risk**: None under current cryptographic assumptions.

---

### T2 — Server identifies sender of a message

**Attack**: The provider sees that Alice sent a message to Bob's mailbox, leaking Alice → Bob communication.

**Mitigation**: Sealed sender. The `SealedEnvelope` contains no plaintext sender identity. Bob's provider cannot identify the sender without Bob's private key. Messages arrive via HTTP from Alice's provider's `.onion` address — Bob's provider sees a request originating from Tor, but not Alice's identity, not Alice's IP, and not which user on Alice's provider initiated the request.

**Residual risk**: None — Bob's provider cannot identify the sender from the envelope or the transport layer.

---

### T3 — GPA traffic correlation (timing attack)

**Attack**: A GPA observes traffic leaving Alice's device and correlates it with traffic arriving at Bob's provider, linking Alice and Bob via timing.

**Mitigation**: All traffic is routed through Tor. Alice's device connects to her provider via an embedded Tor instance over a `.onion` connection (no Tor exit node involved). Alice's provider connects to Bob's provider via its own Tor SOCKS5 proxy. A network observer on any single segment sees only Tor-encrypted traffic and cannot directly identify source or destination.

**Residual risk**: Tor provides strong protection against a passive observer on one network path. However, Tor itself is susceptible to long-term traffic correlation by a GPA watching both ends of a circuit simultaneously. Unlike a Loopix-style mix-net, Tor does not apply batching delays or generate synthetic cover traffic, so a sufficiently capable adversary with visibility of multiple Tor relays could attempt to correlate timing between Alice's outbound traffic and Bob's inbound traffic. This is an acknowledged residual risk. The degree of exposure depends on the adversary's Tor relay visibility and the volume of other Tor traffic at the time. This risk is not mitigated by the current design.

---

### T4 — GPA or ISP identifies Alice's IP

**Attack**: A GPA or Alice's ISP observes that Alice's device is connecting to a known Evanescent provider.

**Mitigation**: Alice's Android uses the embedded tor-android library. No external Tor client (such as Orbot) is required. All connections are routed through this embedded Tor instance. The provider is a Tor hidden service (`.onion`). Because the connection is `.onion`-to-`.onion`, no Tor exit node is involved — the connection is entirely within the Tor network. The provider sees only a Tor circuit endpoint, never Alice's real IP.

**Residual risk**: Tor-level deanonymisation risks apply. An adversary who controls both Alice's Tor guard node and the provider's Tor guard node could attempt circuit correlation. This is a known Tor limitation.

---

### T5 — Provider's IP exposed

**Attack**: An adversary identifies the physical location of the provider server (to seize it or compel the operator legally).

**Mitigation**: The provider is a Tor hidden service. Its clearnet IP is not published and is not included in the `ContactBundle`. The `.onion` address is the only public identifier. Incoming connections arrive via Tor and do not reveal the provider's clearnet IP to connecting clients.

**Residual risk**: If Tor hidden service deanonymisation attacks are applied (e.g., traffic analysis of Tor guard nodes over time), the provider's IP could potentially be identified. This is a known Tor limitation.

---

### T6 — Push notification metadata (FCM)

**Attack**: Push notifications via Google Firebase Cloud Messaging (FCM) reveal to Google and to adversaries with access to Google's infrastructure that Bob's device received a notification at a specific time, correlated with message arrival.

**Mitigation**: Evanescent does not use FCM. The Android app uses periodic polling via the established WebSocket connection over Tor. No third-party notification infrastructure is used.

**Residual risk**: The polling interval (configurable, default 30 seconds when connected) creates a window of up to 30 seconds between message arrival and delivery. The polling pattern reveals that the user's device is active during those windows, but not the content of communication or the identity of correspondents.

---

### T7 — Device seizure

**Attack**: An adversary seizes the Android device and attempts to recover messages or identity keys.

**Mitigation**:
- Identity keypair stored in Android Keystore backed by Trusted Execution Environment (TEE/StrongBox). Keys cannot be extracted even with physical access to the device.
- All local data (messages, contacts, sessions) stored in SQLCipher-encrypted SQLite. The encryption key is derived from the TEE-backed key.
- Without device unlock credentials, the TEE key is inaccessible.
- Forward secrecy: compromising current message keys does not expose past messages (Double Ratchet).

**Residual risk**: If the attacker has the device unlocked (or can compel biometric unlock), they obtain the database key and can read stored messages. Messages are stored decrypted in the SQLCipher database after receipt; SQLCipher's database encryption is the only at-rest protection for decrypted message text.

---

### T8 — Provider compromise and legal compulsion

**Attack**: The provider operator is compelled legally (court order, national security letter) to provide user data.

**Mitigation**:
- The provider stores only ciphertext (`SealedEnvelope` bytes) — no plaintext is available to hand over
- The provider does not know the sender's identity (sealed sender)
- The provider does not log message delivery times beyond the `received_at` timestamp in the messages table
- Messages are deleted 30 days after receipt, or immediately upon delivery confirmation from Android
- The provider does not know the user's real IP (Tor)
- Identity registration is pseudonymous: no phone number, email, or real-world identifier

**Residual risk**: The provider can confirm that a mailbox has received messages and approximately when. This establishes that someone using that mailbox address is communicating with someone — a fact, but without sender identity or content.

---

### T9 — Contact graph via prekey requests

**Attack**: Bob's provider logs prekey requests, revealing that some party is initiating a conversation with Bob.

**Mitigation**: Prekey requests are routed through Alice's provider, not sent directly from Alice's device to Bob's provider. Alice's app sends `GetPreKeys` to her own provider via the authenticated WebSocket. Alice's provider then makes an HTTP request to Bob's provider's `.onion` address over Tor to fetch the prekey bundle. Bob's provider sees an HTTP request arriving from Tor — it can observe that some provider's `.onion` address made the request, but it cannot identify which user on that provider initiated it, and the transport conceals the requesting provider's clearnet IP.

**Residual risk**: Bob's provider can record that a prekey request was made by Alice's provider at a given time. An adversary who has compromised both Alice's and Bob's providers could correlate this with a message arriving shortly after, circumstantially indicating a new conversation. This is weaker metadata than a clearnet request but stronger than what a mix-net would provide. No sender identity is revealed.

---

### T10 — Intersection attacks over time

**Attack**: Even without identifying individual messages, a GPA observing traffic patterns over an extended period can attempt to narrow down who Alice communicates with: observe which users are online when Alice sends traffic, and eliminate candidates over time.

**Mitigation**: All traffic is routed through Tor. The provider-to-provider channel uses `.onion` addresses, keeping inter-provider traffic within Tor. Alice's outbound traffic is not directly distinguishable from other Tor traffic at the ISP level.

**Residual risk**: Tor does not generate synthetic cover traffic or apply batching delays. A GPA with persistent visibility into Tor relay traffic could attempt long-term traffic correlation. This is an acknowledged limitation. Intersection attacks become more tractable as the anonymity set decreases (fewer active users) — this is a social and adoption problem as much as a technical one.

---

## Out of Scope

### Endpoint Compromise

If the device running the Android app is compromised by malware:
- The attacker can read messages as they are displayed
- The attacker can access the SQLCipher database (if the TEE key is accessible to the malware)
- The attacker can impersonate the user for future messages

This is out of scope. No messaging system protects against a fully compromised endpoint.

### Social Engineering

An adversary who tricks a user into scanning a malicious QR code can perform a MITM attack at contact exchange time. Safety number verification is the defence; it requires the user to act.

### Legal Compulsion of the User

If a user is compelled to provide their device and PIN, all stored messages are accessible.

### Anonymity Set Collapse

If Evanescent has very few users, the anonymity set is small and correlation attacks become more tractable. The cryptographic design cannot compensate for low adoption.

---

## What Evanescent Does Not Claim

- **Timing correlation resistance against a GPA**: Tor provides strong hop-by-hop concealment but does not provide the batching and cover traffic of a mix-net. A sufficiently capable adversary with visibility into Tor infrastructure can attempt timing correlation. This risk is explicitly acknowledged.
- **Anonymity against endpoint compromise**: It does not provide this.
- **Anonymity against Tor deanonymisation**: It relies on Tor and inherits Tor's known limitations.
- **Guaranteed delivery**: Messages may be lost if the provider is offline or if TTL expires before delivery.
- **Protection against Tor guard node correlation**: Long-term Tor guard node correlation attacks are a known open problem.
- **Plausible deniability of Tor usage**: Evanescent does not hide that a user is running Tor.
