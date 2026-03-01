# Evanescent — Threat Model

## Adversary Definition

The primary adversary is a **Global Passive Adversary (GPA)**: an entity with read access to all network traffic at major internet exchange points. This corresponds to nation-state intelligence agencies (e.g., NSA, GCHQ) operating under programs like PRISM or MUSCULAR.

Secondary adversaries: malicious server operators, ISPs, dragnet surveillance systems operating below GPA level.

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

**Mitigation**: Double Ratchet end-to-end encryption. The provider stores only ciphertext — `SealedEnvelope` bytes. The provider never possesses any key material needed to decrypt. Breaking this requires breaking X25519 or ChaCha20-Poly1305.

**Residual risk**: None under current cryptographic assumptions.

---

### T2 — Server identifies sender of a message

**Attack**: The provider sees that Alice sent a message to Bob's mailbox, leaking Alice → Bob communication.

**Mitigation**: Sealed sender. The `SealedEnvelope` contains no plaintext sender identity field. The provider cannot identify the sender without Bob's private key. Messages arrive via the Nym mix-net, so the provider sees the final Nym relay node's address, not the sender's Nym address.

**Residual risk**: None — the provider cannot identify the sender from stored data alone.

---

### T3 — GPA traffic correlation (timing attack)

**Attack**: A GPA observes Alice sending a packet into the mix-net and correlates it with a packet arriving at Bob's provider, linking Alice and Bob.

**Mitigation**: Nym mix-net with Loopix model:
- Sphinx packets are identical size (512 bytes) at every hop — no size fingerprinting
- Each mix node applies an independent Poisson-distributed delay — correlating timing across hops requires defeating Poisson statistics across multiple independent nodes
- Alice's provider generates cover traffic at a Poisson rate independent of real message activity — traffic volume from Alice's provider never reveals when real messages are sent

**Residual risk**: Computationally negligible under the Loopix security proof, given sufficient network size and honest mix nodes. Risk increases if the anonymity set is small (few active users).

---

### T4 — GPA identifies Alice's IP

**Attack**: A GPA or Alice's ISP observes that Alice's device is connecting to a known Evanescent provider address.

**Mitigation**: Alice's Android connects exclusively through Orbot (Tor). The provider is a Tor hidden service (`.onion`). The connection is therefore:
- Encrypted with Tor's onion layers
- Routed through 3 Tor hops
- The provider sees only a Tor exit node IP, never Alice's real IP
- The Tor network sees only that Alice is using Tor (not where she's connecting to)

**Residual risk**: Tor-level deanonymisation risks apply (traffic correlation against Tor itself is a separate research area). Using Tor for `.onion` connections (hidden service) avoids exit nodes, which is stronger than using Tor for clearnet connections.

---

### T5 — Provider's IP exposed

**Attack**: An adversary identifies the physical location of the provider server (e.g., to seize it or compel the operator legally).

**Mitigation**: The provider is a Tor hidden service. Its clearnet IP is not published and is not included in the `ContactBundle`. Senders send messages to the provider's Nym address (which does not reveal the server's IP). The `.onion` address is the only public identifier.

**Residual risk**: If Tor hidden service deanonymisation attacks are applied (e.g., traffic analysis of Tor guard nodes), the provider's IP could be exposed. This is a known Tor limitation and an active research area.

---

### T6 — Push notification metadata (FCM)

**Attack**: Push notifications via Google Firebase Cloud Messaging (FCM) reveal to Google (and to adversaries with access to Google's infrastructure) that Bob's device received a notification at a specific time, correlated with a message arriving at his mailbox.

**Mitigation**: Evanescent does not use FCM. The Android app uses periodic polling via the established Tor WebSocket connection. No third-party notification infrastructure is used.

**Residual risk**: The polling interval (configurable, default 30 seconds when connected) means there is a window of up to 30 seconds between message arrival and delivery. The polling pattern reveals that the user is active during polling windows — an adversary watching Tor traffic from Alice's device can infer when Alice's device is online, but not what she is communicating or with whom.

---

### T7 — Device seizure

**Attack**: An adversary seizes the Android device and attempts to recover messages or identity keys.

**Mitigation**:
- Identity keypair stored in Android Keystore backed by Trusted Execution Environment (TEE/StrongBox). Keys cannot be extracted even with physical access to the device.
- All local data (messages, contacts, sessions) stored in SQLCipher-encrypted SQLite. The encryption key is derived from the TEE-backed key.
- Without device unlock credentials, the TEE key is inaccessible.
- Forward secrecy: compromising current message keys does not expose past messages (Double Ratchet).

**Residual risk**: If the attacker has the device unlocked (or can compel biometric unlock), they access the database key and can read stored messages. Messages are not stored in encrypted form after decryption — SQLCipher's database encryption is the only at-rest protection for decrypted message text.

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

**Residual risk**: The provider can confirm that a mailbox has received messages and approximately when. This confirms that someone using that mailbox address is communicating with someone — a fact, but without sender identity or content.

---

### T9 — Contact graph via prekey requests

**Attack**: Bob's provider logs prekey requests, allowing an adversary to see that someone (presumably Alice) fetched Bob's prekeys, indicating Alice and Bob are starting a conversation.

**Mitigation**: Prekey requests are routed through the Nym mix-net anonymously. The provider sees a prekey request arrive via Nym but cannot identify the requester. Sealed sender and X3DH key agreement happen locally on Alice's device after receiving the prekey bundle.

**Residual risk**: The provider can confirm that someone (unknown) fetched Bob's prekeys at a given time. Correlated with message arrival shortly after, this could circumstantially indicate a new contact, but without sender identity.

---

### T10 — Intersection attacks over time

**Attack**: Even without identifying individual messages, a GPA observing traffic patterns over months can use intersection attacks to narrow down who Alice communicates with: observe who is online when Alice sends traffic, eliminate users over time.

**Mitigation**: Cover traffic from the provider operates at a constant Poisson rate regardless of Alice's activity. The Nym mix-net batches and reorders messages across multiple users. Intersection attacks require identifying Alice's traffic in the mix, which is defeated by cover traffic and Sphinx uniform packet sizes.

**Residual risk**: Against a sufficiently patient GPA with sufficient computing resources and a small network (small anonymity set), long-term statistical attacks remain theoretically possible. The primary defence is a large, active anonymity set — a social/adoption problem, not a cryptographic one.

---

## Out of Scope

### Endpoint Compromise

If the device running the Android app is compromised by malware:
- The attacker can read messages as they are displayed
- The attacker can access the SQLCipher database (if the TEE key is accessible to the malware)
- The attacker can impersonate the user for future messages

This is out of scope. No messaging system protects against a fully compromised endpoint.

### Social Engineering

An adversary who tricks a user into revealing their safety number comparison or scanning a malicious QR code can perform a MITM attack. User education is the only defence.

### Legal Compulsion of the User

If a user is compelled to provide their device and PIN, all stored messages are accessible.

### Anonymity Set Collapse

If Evanescent has very few users (e.g., < 1,000 active simultaneously), the anonymity set is small and intersection attacks become tractable. The cryptographic design cannot compensate for low adoption.

---

## What Evanescent Does Not Claim

- **Anonymity against endpoint compromise**: It does not provide this.
- **Anonymity against Tor deanonymisation**: It relies on Tor and inherits Tor's known limitations.
- **Guaranteed delivery**: Messages may be lost if the provider is offline or if TTL expires before delivery.
- **Protection against traffic analysis of Tor guard nodes**: Long-term Tor guard node correlation attacks are a known open problem.
- **Plausible deniability of communication**: Evanescent hides the *contents* and *parties* of communication. It does not hide that a user is running Evanescent or using Tor.
