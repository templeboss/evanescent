# Evanescent Provider — Launch Manual

This manual covers everything needed to build, configure, and run a Personal Provider
from a clean Linux server. It assumes a Debian/Ubuntu VPS but the steps are the same
on any systemd-based Linux.

---

## Table of Contents

1. [What the provider is](#1-what-the-provider-is)
2. [Server requirements](#2-server-requirements)
3. [Install the Rust toolchain](#3-install-the-rust-toolchain)
4. [Configure Tor](#4-configure-tor)
5. [Create the system user and directories](#5-create-the-system-user-and-directories)
6. [Build the binary](#6-build-the-binary)
7. [Write the config file](#7-write-the-config-file)
8. [First run](#8-first-run)
9. [Record your addresses](#9-record-your-addresses)
10. [Run as a systemd service](#10-run-as-a-systemd-service)
11. [Verify the service is healthy](#11-verify-the-service-is-healthy)
12. [Connect the Android app](#12-connect-the-android-app)
13. [Maintenance](#13-maintenance)
14. [Backup and recovery](#14-backup-and-recovery)
15. [Firewall](#15-firewall)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. What the provider is

The Personal Provider is a long-running Rust server that acts as your permanent
presence on the Nym mix-network. The Android app can go offline; the provider
cannot. It:

- Maintains a persistent Nym network connection with automatic cover traffic
- Stores encrypted messages when the Android app is offline
- Serves your X3DH prekey bundles to contacts initiating sessions
- Exposes a Tor hidden service (`.onion` address) so the Android app connects
  without revealing anyone's IP address

The provider never sees plaintext. It stores only opaque ciphertext blobs.

---

## 2. Server requirements

| Item | Minimum | Recommended |
|---|---|---|
| CPU | 1 vCPU | 2 vCPU |
| RAM | 512 MB | 1 GB |
| Disk | 2 GB | 10 GB |
| OS | Debian 12, Ubuntu 22.04 LTS | Debian 12 |
| Uptime | 24/7 | 24/7 |
| Outbound internet | Required | Required |
| Inbound ports | None needed | None needed |

Inbound port exposure is **not** required. Android connects to the provider via the
`.onion` address, which is established by the provider over an outbound Tor circuit.

---

## 3. Install the Rust toolchain

```bash
# Install rustup (as the user who will build the binary)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Verify
rustc --version    # expect: rustc 1.78 or later
cargo --version
```

Rust is only needed on the **build machine**. The compiled binary can be copied to
a separate server if preferred.

You also need a C compiler for `rusqlite` (which bundles SQLite from source):

```bash
sudo apt-get install -y build-essential
```

---

## 4. Configure Tor

The provider uses the Tor **control port** to create a v3 hidden service. It does not
need Tor to proxy its own traffic.

### Install Tor

```bash
sudo apt-get install -y tor
```

### Configure the control port

Edit `/etc/tor/torrc`:

```
# Add or uncomment these lines:
ControlPort 9051
CookieAuthentication 0
```

> `CookieAuthentication 0` means the control port accepts unauthenticated connections
> from localhost. This is safe because port 9051 is only accessible from 127.0.0.1
> by default. If you want stronger isolation, see
> [Appendix: Cookie authentication](#appendix-cookie-authentication).

Reload Tor:

```bash
sudo systemctl reload tor
sudo systemctl status tor    # must show "active (running)"
```

Verify the control port is listening:

```bash
nc -z 127.0.0.1 9051 && echo "OK" || echo "NOT listening"
```

---

## 5. Create the system user and directories

Run as root:

```bash
# Dedicated system user (no login shell)
useradd --system --no-create-home --shell /usr/sbin/nologin evanescent

# Data directories
mkdir -p /var/lib/evanescent/nym
mkdir -p /var/lib/evanescent/tor
chown -R evanescent:evanescent /var/lib/evanescent

# Config directory
mkdir -p /etc/evanescent
```

---

## 6. Build the binary

### Clone (or copy) the repository

```bash
git clone <your-repo-url> evanescent
cd evanescent/backend
```

### First build

The first build compiles the Nym SDK from source (large dependency — allow 5–15 minutes):

```bash
cargo build --release
```

If the build succeeds, the binary is at:

```
backend/target/release/evanescent-provider
```

### Install the binary

```bash
sudo install -o root -g root -m 755 \
    target/release/evanescent-provider \
    /usr/local/bin/evanescent-provider
```

---

## 7. Write the config file

Create `/etc/evanescent/provider.yaml`:

```yaml
nym:
  # Directory where the Nym SDK stores your Nym identity.
  # Must persist across restarts — your Nym address is derived from the key stored here.
  data_dir: /var/lib/evanescent/nym

  # Leave null to auto-select a gateway from the network.
  # After first run, pin to the gateway you were assigned to avoid address changes.
  # gateway: "GatewayIdentityKeyHere"

tor:
  # Port where Tor's control protocol is listening.
  control_port: 9051

  # Internal WebSocket port (loopback only — never exposed to internet).
  ws_port: 8765

  # Port exposed on the .onion address.
  # Android connects to <your-onion>.onion:443 over Tor.
  hidden_service_port: 443

storage:
  db_path: /var/lib/evanescent/provider.db

logging:
  level: info          # debug | info | warn | error
  format: json         # json (structured) | text (human-readable)
```

Set ownership:

```bash
sudo chown root:evanescent /etc/evanescent/provider.yaml
sudo chmod 640 /etc/evanescent/provider.yaml
```

---

## 8. First run

Run manually first to confirm everything works and to capture the generated addresses:

```bash
sudo -u evanescent evanescent-provider --config /etc/evanescent/provider.yaml
```

On a successful first run you will see output like:

```
=== Evanescent Provider Ready ===
Onion address : abc123def456....onion
Nym address   : <see log>
=================================
```

The Nym address appears in the structured log output before the banner:

```json
{"level":"INFO","msg":"nym address","nym_addr":"GkH7...@GatewayIdent..."}
```

**These two addresses are your permanent contact identifiers. Record them now.**
See [§9 Record your addresses](#9-record-your-addresses).

Press `Ctrl-C` to stop after recording.

### What happens on first run

1. SQLite database is created at `db_path` with WAL mode enabled
2. Nym SDK generates a new identity keypair in `nym.data_dir` and registers with a gateway — **this takes 30–120 seconds the first time**
3. A new Ed25519 `.onion` key is created by Tor via the control port — **the `.onion` address is permanent as long as Tor retains the key**
4. The WebSocket server starts listening on `127.0.0.1:8765`

> **Important:** The `.onion` address is managed by Tor's key storage, not by the
> provider. As long as you do not wipe Tor's data directory, restarting the provider
> gives you the same `.onion` address. The Nym address is similarly stable as long
> as `nym.data_dir` is preserved.

---

## 9. Record your addresses

After first run, immediately record both addresses. They are the inputs to your
**ContactBundle** — the QR code / link you share with contacts.

| Value | Where to find it |
|---|---|
| `.onion` address | Printed to stdout on startup |
| Nym address | JSON log line with field `nym_addr` |

Example:

```
Onion  : abcdefghijk234567890abcdefghijk234567890abcde.onion
Nym    : GkH7abc...@GatewayXyz...
```

Store these in a password manager or offline. If you lose the `.onion` address you
can recover it by running the provider again (it prints on every start). The Nym
address is similarly always printed at startup.

---

## 10. Run as a systemd service

Create `/etc/systemd/system/evanescent-provider.service`:

```ini
[Unit]
Description=Evanescent Personal Provider
Documentation=https://github.com/evanescent/evanescent
After=network-online.target tor.service
Wants=network-online.target
Requires=tor.service

[Service]
Type=simple
User=evanescent
Group=evanescent
ExecStart=/usr/local/bin/evanescent-provider --config /etc/evanescent/provider.yaml
Restart=on-failure
RestartSec=10s
# Limit restarts to avoid looping on a bad config
StartLimitInterval=60s
StartLimitBurst=5

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/evanescent
ProtectHome=yes

# Log all output to journald
StandardOutput=journal
StandardError=journal
SyslogIdentifier=evanescent-provider

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable evanescent-provider
sudo systemctl start evanescent-provider
```

Check status:

```bash
sudo systemctl status evanescent-provider
```

Expected:

```
● evanescent-provider.service - Evanescent Personal Provider
     Loaded: loaded (/etc/systemd/system/evanescent-provider.service; enabled)
     Active: active (running) since ...
```

---

## 11. Verify the service is healthy

### Confirm it printed the banner

```bash
sudo journalctl -u evanescent-provider -n 50
```

Look for:
- `"msg":"nym address"` — Nym SDK connected
- `"msg":"tor hidden service"` — `.onion` address created
- `"msg":"WebSocket server listening"` — accepting connections
- The `=== Evanescent Provider Ready ===` banner

### Confirm the WebSocket port is listening

```bash
ss -tlnp | grep 8765
```

Expected: `127.0.0.1:8765` in LISTEN state.

### Confirm Tor hidden service is registered

```bash
sudo journalctl -u evanescent-provider | grep onion
```

---

## 12. Connect the Android app

In the Android app, add your provider using the **ContactBundle**. For your own
account (not a contact's), navigate to:

> Settings → Provider → Add Provider

Enter:
- `.onion` address — `abc...onion`
- Nym address — `GkH7...@GatewayXyz...`

The app connects to the provider via Orbot (Tor SOCKS5 on `127.0.0.1:9050`).
Make sure Orbot is installed and running on the device.

**Prerequisites on Android:**
1. [Orbot](https://guardianproject.info/apps/org.torproject.android/) installed and connected
2. App permission to use Orbot's VPN or SOCKS5 proxy
3. The provider must be reachable (test: try again if first connection fails — Tor
   circuit establishment takes a few seconds)

---

## 13. Maintenance

### Update the binary

```bash
cd evanescent/backend
git pull
cargo build --release
sudo systemctl stop evanescent-provider
sudo install -o root -g root -m 755 \
    target/release/evanescent-provider \
    /usr/local/bin/evanescent-provider
sudo systemctl start evanescent-provider
```

### View live logs

```bash
# Structured JSON logs
sudo journalctl -u evanescent-provider -f

# Human-readable (change format: text in provider.yaml first)
sudo journalctl -u evanescent-provider -f -o cat
```

### Check database size

```bash
ls -lh /var/lib/evanescent/provider.db
```

Messages older than 30 days are automatically deleted by the TTL cleaner.
Expect the database to grow proportionally to unread message backlog.

### Rotate logs (journald handles this automatically)

journald rotates logs by default. No additional configuration needed.

---

## 14. Backup and recovery

### What to back up

| Path | Contents | Priority |
|---|---|---|
| `/var/lib/evanescent/nym/` | Nym identity keypair and gateway state | **Critical** — losing this changes your Nym address |
| `/var/lib/evanescent/provider.db` | Mailbox messages, prekeys | **High** — losing messages means unread messages are gone |
| `/etc/evanescent/provider.yaml` | Config | Low — easy to recreate |

> The `.onion` address key is managed by Tor, stored in Tor's data directory
> (usually `/var/lib/tor/`). Back it up if you want to preserve the address across
> full server wipes.

### Backup command

```bash
sudo systemctl stop evanescent-provider

sudo tar -czf evanescent-backup-$(date +%Y%m%d).tar.gz \
    /var/lib/evanescent/ \
    /etc/evanescent/ \
    /var/lib/tor/hidden_service_*   # may vary by Tor version

sudo systemctl start evanescent-provider
```

### Restore on a new server

```bash
# After installing dependencies (Rust, Tor, build tools):
sudo tar -xzf evanescent-backup-YYYYMMDD.tar.gz -C /
sudo chown -R evanescent:evanescent /var/lib/evanescent
# Restore Tor hidden service key (adjust path as needed)
sudo systemctl restart tor
sudo systemctl start evanescent-provider
```

---

## 15. Firewall

The provider needs **no inbound ports open**. All connections are initiated outbound:

- Nym SDK → Nym network (outbound TCP 443 or 1789)
- Tor daemon → Tor network (outbound TCP 443 or 9001)

If you run a firewall, allow outbound TCP on ports 80, 443, and 9001:

```bash
# ufw example
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh    # adjust to your SSH port
sudo ufw enable
```

No `ufw allow 8765` — the WebSocket port is loopback-only.

---

## 16. Troubleshooting

### Provider exits immediately

```bash
sudo journalctl -u evanescent-provider -n 100
```

Common causes:

| Error message | Fix |
|---|---|
| `connect to Tor control port 9051` | Tor is not running or `ControlPort 9051` not in torrc |
| `Tor authentication failed` | Add `CookieAuthentication 0` to torrc and reload Tor |
| `open sqlite: /var/lib/evanescent/provider.db` | Directory does not exist or wrong ownership — run §5 again |
| `nym builder` / `connect to mixnet` | Nym network unreachable; check outbound internet; retry — first connection can take 60s+ |

### Provider loops restarting

If systemd shows `start-limit-hit`:

```bash
sudo systemctl reset-failed evanescent-provider
sudo journalctl -u evanescent-provider -n 200
# Diagnose the root cause before restarting
sudo systemctl start evanescent-provider
```

### `.onion` address changed after restart

The `.onion` key is held by Tor, not the provider. If Tor's data was wiped or a new
Tor installation was used, a new key (new `.onion` address) is generated. To recover:

1. If you have a backup: restore `/var/lib/tor/` from backup
2. If you do not: the old `.onion` address is gone. You must share your new
   ContactBundle with all contacts

### Android cannot connect

1. Confirm Orbot is running on the device (green indicator)
2. Confirm the `.onion` address in the app matches what the provider prints
3. Check the provider's WebSocket port is listening: `ss -tlnp | grep 8765`
4. Confirm Tor is running on the server: `systemctl status tor`
5. Tor circuit establishment can take 15–30 seconds on first connection — retry

### Nym SDK first-run timeout

The Nym SDK takes 30–120 seconds to connect on the first run because it must
fetch the network topology and complete gateway registration. This is normal.
If it hangs beyond 5 minutes, check outbound internet access from the server:

```bash
curl -sI https://nymtech.net | head -1   # must return HTTP/2 200
```

---

## Appendix: Cookie authentication

If you prefer stronger Tor control port isolation, use cookie authentication:

```
# /etc/tor/torrc
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```

Add the `evanescent` user to the `debian-tor` group (or `tor` group, depending on distro):

```bash
sudo usermod -aG debian-tor evanescent
# Then log out and back in, or restart the service
```

The provider's `onion.rs` currently sends `AUTHENTICATE ""` (empty password). To use
cookie auth, `onion.rs` must be updated to read the cookie file and send it as the
authenticate token. This is noted as a future hardening task.
