# Evanescent — Android Client

## Role

The Android app is the only user interface. It holds the user's identity keypair and performs all encryption and decryption locally. The provider is a dumb relay from the app's perspective — it stores ciphertext blobs it cannot read.

**What the app does:**
1. Generates and protects the user's Ed25519 identity keypair in Android Keystore (TEE)
2. Performs X3DH key agreement and manages Double Ratchet sessions
3. Constructs sealed sender envelopes — the provider never learns who sent a message
4. Connects to the provider exclusively via embedded Tor (no Orbot required)
5. Stores all local data (messages, contacts, session state) in SQLCipher-encrypted SQLite
6. Provides a minimal, functional UI

**What the app does NOT do:**
- It never connects to clearnet. Every network call goes through Tor.
- It never sends the identity private key anywhere, for any reason.
- It never connects to Google services (no FCM, no Google Play Services dependency in the core).
- It does not implement any transport-layer cryptography — `.onion` connections are authenticated by the onion address itself.

---

## Technology Stack

| Component | Choice | Version / Notes |
|---|---|---|
| Language | Kotlin | 2.0+ |
| Min SDK | API 26 (Android 8.0) | Required for Android Keystore guarantees |
| Target SDK | API 35 | Latest stable |
| UI | Jetpack Compose | Material3 |
| Async | Kotlin Coroutines + Flow | |
| WebSocket | OkHttp | 4.x |
| Database | SQLCipher + Room | See setup below |
| Proto | `com.google.protobuf:protobuf-kotlin` | Code generated from `proto/` |
| Tor | tor-android (embedded) | Bootstraps on app startup |
| Crypto | Android Keystore + Bouncy Castle | See crypto section |
| QR codes | ZXing | For ContactBundle scanning/display |
| Build | Gradle (Kotlin DSL) | |

**No Google Play Services dependency** in the core app module. F-Droid compatibility is a requirement.

---

## Project Structure

```
android/
  app/
    build.gradle.kts
    src/
      main/
        kotlin/net/evanescent/
          App.kt                     Application class. Initialises DI, SQLCipher.

          crypto/
            KeyManager.kt            Generates/retrieves keypairs from Android Keystore.
                                     Ed25519 identity key. X25519 keys via Bouncy Castle.
            X3DH.kt                  X3DH session establishment. Consumes PreKeyBundle.
                                     Returns initialised DoubleRatchetSession.
            DoubleRatchet.kt         Double Ratchet encrypt/decrypt. Manages ratchet state.
            SealedSender.kt          Sealed sender envelope construction and decryption.
            SafetyNumber.kt          Computes and formats safety number from two identity keys.
            Hkdf.kt                  HKDF-SHA256 utility (thin wrapper, not a reimplementation).
            PreKeyGenerator.kt       Generates signed prekeys and one-time prekeys for upload.

          provider/
            ProviderClient.kt        WebSocket client. Handles connection lifecycle,
                                     authentication, send/receive dispatch.
                                     All connections go through the embedded Tor SOCKS5 port.
            TorManager.kt            Embedded Tor lifecycle: start, bootstrap wait, dynamic SOCKS5 port.
            MessageQueue.kt          Outbound queue. Tracks correlation_id → SendAck mapping.
            PreKeyUploader.kt        Watches one-time prekey count; triggers upload when < 20.
            ProviderService.kt       Foreground Service. Maintains persistent WebSocket connection.
                                     Shows persistent notification (required for foreground service).

          db/
            Database.kt              Room database initialisation with SQLCipher.
            ContactDao.kt
            SessionDao.kt            Stores serialised RatchetState proto per contact.
            MessageDao.kt
            PreKeyDao.kt             Local prekey pool (before upload to provider).
            Converters.kt            Room type converters (ByteArray, enums).

          model/
            Contact.kt               Data class. Wraps ContactBundle fields + local alias.
            Message.kt               Data class. Direction, status, plaintext, timestamp.
            Session.kt               Ratchet session state wrapper.
            MessageStatus.kt         Enum: SENDING, SENT, DELIVERED, FAILED.

          ui/
            MainActivity.kt          Nav host.
            conversation/
              ConversationListScreen.kt
              ConversationListViewModel.kt
              ConversationScreen.kt
              ConversationViewModel.kt
            contact/
              AddContactScreen.kt    QR code scanner for ContactBundle.
              SafetyNumberScreen.kt  Display and verify safety number.
            settings/
              SettingsScreen.kt      Provider address, onion address management.

          proto/                     Generated from ../proto/ — do not edit manually.

        res/
          layout/                    (minimal — Compose handles most UI)
          values/
            strings.xml
          xml/
            network_security_config.xml   Blocks all clearnet traffic.

      test/
        kotlin/net/evanescent/
          crypto/
            X3DHTest.kt              Must include Signal X3DH test vectors.
            DoubleRatchetTest.kt     Must include Signal Double Ratchet test vectors.
            SealedSenderTest.kt      Round-trip test.
            SafetyNumberTest.kt

      androidTest/
        kotlin/net/evanescent/
          ProviderClientTest.kt      Integration test against local provider (loopback).
          ConversationFlowTest.kt    Espresso: compose, send, receive.
```

---

## Crypto Implementation

**Do not implement cryptographic primitives from scratch.** Use established libraries.

### Key Storage (Android Keystore)

```kotlin
// Identity keypair
// Ed25519 is not directly supported by Android Keystore on all devices.
// Strategy: generate Ed25519 keypair via Bouncy Castle; store private key
// as an AES-256-GCM encrypted blob, where the AES key lives in Android Keystore (TEE).

// In KeyManager.kt:
// 1. Generate AES-256 key in Android Keystore:
//    KeyGenParameterSpec.Builder("evanescent_master_key", PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
//      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
//      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//      .setKeySize(256)
//      .setUserAuthenticationRequired(false)   // allow background operation
//      .build()
// 2. Generate Ed25519 keypair via Bouncy Castle
// 3. Encrypt private key bytes with Keystore AES key (AES-256-GCM)
// 4. Store encrypted private key in EncryptedSharedPreferences or SQLCipher
// 5. Store public key unencrypted (it's public)

// On subsequent launches:
// 1. Read encrypted private key bytes
// 2. Decrypt using Keystore AES key
// 3. Load Ed25519 keypair into memory for signing operations
// 4. Wipe from memory after use (as much as JVM GC allows)
```

### SQLCipher Setup

```kotlin
// In Database.kt:
val factory = SupportFactory(getDatabaseKey())  // key from Keystore

Room.databaseBuilder(context, AppDatabase::class.java, "evanescent.db")
    .openHelperFactory(factory)
    .build()

// getDatabaseKey(): derives a 32-byte key from the Keystore AES key.
// Use HKDF-SHA256(keystore_key_bytes, salt=app_id_bytes, info="Evanescent_DB_v1")
// The keystore_key_bytes are obtained by wrapping/unwrapping a random 32-byte value
// with the Keystore AES key.
```

### Bouncy Castle Usage

Add to `build.gradle.kts`:
```kotlin
implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
```

Use `org.bouncycastle.crypto.signers.Ed25519Signer` for Ed25519.
Use `org.bouncycastle.crypto.agreement.X25519Agreement` for X25519.
Use `org.bouncycastle.crypto.generators.HKDFBytesGenerator` for HKDF-SHA256.
Use `org.bouncycastle.crypto.engines.ChaCha7539Engine` + `org.bouncycastle.crypto.macs.Poly1305` for ChaCha20-Poly1305.

**Do not use** `javax.crypto` for X25519 or Ed25519 — Android API support is inconsistent below API 33.

---

## Tor Integration

The app embeds Tor via the tor-android library. No external Orbot app is required.

Dependency (`build.gradle.kts`):
```kotlin
implementation("info.guardianproject:tor-android:0.4.9.13")
```

`TorManager.kt`:
- Starts the embedded Tor daemon on app launch
- Waits for bootstrap (typically 5–15 seconds)
- Exposes the dynamic SOCKS5 port after bootstrap
- Provides a `ready()` suspend function that callers await before making connections

OkHttp proxy setup:
```kotlin
val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", TorManager.socksPort))
val client = OkHttpClient.Builder()
    .proxy(proxy)
    .connectTimeout(30, TimeUnit.SECONDS)
    .build()
```

If Tor fails to bootstrap, the app shows an error screen. **Never fall back to direct connections.**

### Network Security Config

`res/xml/network_security_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <!-- No trust anchors: all connections go through Tor, no TLS cert pinning needed.
                 .onion connections are authenticated by the onion address itself. -->
        </trust-anchors>
    </base-config>
</network-security-config>
```

This blocks all clearnet HTTP. All connections go through the embedded Tor SOCKS5 port to `.onion` addresses.

---

## Provider Connection

The app maintains one persistent WebSocket connection to the provider via embedded Tor.

### Connection Lifecycle

```
App launch
  → Start embedded Tor (TorManager)
  → Await TorManager.ready()
  → Start ProviderService (foreground service)
    → Connect WebSocket to <onion_address>:443/ws via SOCKS5
    → Authenticate (challenge-response — see standards.md §7)
    → Upload prekeys if pool empty
    → FetchMessages loop:
        send FetchMessages(ack_ids=[])
        receive Messages
        decrypt each message
        store to SQLCipher
        send FetchMessages(ack_ids=<delivered IDs>)
        wait 30 seconds
        repeat

App backgrounded
  → ProviderService continues as foreground service (persistent notification)
  → FetchMessages polling continues at 30-second intervals

Network lost
  → WebSocket closes
  → Reconnect with exponential backoff: 5s, 10s, 20s, 40s, max 120s
```

### Sending a Message

```kotlin
// In ConversationViewModel.kt:
suspend fun send(contact: Contact, plaintext: String) {
    val session = sessionDao.get(contact.identityKey)
        ?: establishSession(contact)           // X3DH if no session
    val drCiphertext = doubleRatchet.encrypt(session, plaintext.toByteArray())
    val envelope = sealedSender.seal(drCiphertext, contact.identityKey, myIdentityKey)
    val correlationId = UUID.randomUUID().toString()
    providerClient.send(correlationId, contact.providerOnion, envelope)
    // await SendAck with matching correlationId
}
```

---

## WebSocket Protocol

All frames are binary. Each frame contains one serialised `WsClientMessage` or `WsServerMessage` proto.

**Full specification**: [docs/standards.md — §7](../docs/standards.md#7-websocket-protocol-android--provider)

The Android client must:
- Never send a message before authentication completes
- Always await `SendAck` for each `SendMessage` before retrying
- Always include all un-acked message IDs in `FetchMessages.ack_ids`
- Handle `Error { code: PREKEY_EXHAUSTED }` by triggering prekey upload on next poll

---

## Proto Generation

Generate from repo root:
```bash
protoc \
  --kotlin_out=android/app/src/main/java \
  --java_out=android/app/src/main/java \
  proto/*.proto
```

Generated files are committed. Do not edit them manually.

---

## Building

```bash
cd android
./gradlew assembleDebug         # debug build
./gradlew assembleRelease       # release build (requires signing config)
./gradlew test                  # unit tests
./gradlew connectedAndroidTest  # instrumented tests (requires emulator/device)
```

---

## Testing

### Unit Tests (JVM)

```kotlin
// X3DHTest.kt — must include Signal's published test vectors
// DoubleRatchetTest.kt — must include Signal's published test vectors
// SealedSenderTest.kt — must include a round-trip test:
//   Alice seals → envelope → Bob unseals → original plaintext
// SafetyNumberTest.kt — deterministic output given two fixed keys
```

Any crypto test that passes but produces output differing from published Signal test vectors is a bug.

### Integration Tests

`ProviderClientTest.kt` runs against a local provider binary in test mode (no Tor, plain WebSocket on localhost). The integration test binary is part of `backend/cmd/integration_test/`.

---

## What NOT to Do

- Do not make any direct TCP/HTTP connection outside of the embedded Tor SOCKS5 port
- Do not use FCM or any Google push notification service
- Do not store the identity private key in SharedPreferences or unencrypted files
- Do not use `Math.random()` or `java.util.Random` for any cryptographic purpose — use `SecureRandom`
- Do not implement X25519 or Ed25519 from scratch — use Bouncy Castle
- Do not use JSON for the WebSocket wire format — use proto binary frames
- Do not display error messages that reveal internal cryptographic state to users
- Do not add any dependency that requires Google Play Services
- Do not cache decrypted message content outside of SQLCipher
- Do not log message plaintext at any log level
