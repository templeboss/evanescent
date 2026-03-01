use anyhow::{bail, Context, Result};
use std::path::Path;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tracing::{debug, info};

/// Connect to the Tor control port and create a persistent v3 hidden service.
///
/// The ED25519-V3 private key is read from `key_path` on subsequent calls so
/// the same `.onion` address is reused across restarts. The key file is created
/// on first run.
///
/// Returns the `<service_id>.onion` address.
pub async fn start_hidden_service(
    control_port: u16,
    ws_port: u16,
    external_port: u16,
    key_path: &Path,
) -> Result<String> {
    let stream = TcpStream::connect(format!("127.0.0.1:{control_port}"))
        .await
        .with_context(|| format!("connect to Tor control port {control_port}"))?;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // ── Authenticate ───────────────────────────────────────────────────────
    authenticate(&mut reader, &mut write_half).await?;

    // ── Add or restore onion service ───────────────────────────────────────
    let key_blob = read_onion_key(key_path)?;
    let key_arg = match &key_blob {
        Some(k) => k.clone(),       // reuse: "ED25519-V3:<base64>"
        None => "NEW:ED25519-V3".to_string(), // first run: generate
    };

    let cmd = format!("ADD_ONION {key_arg} Port={external_port},127.0.0.1:{ws_port}\r\n");
    write_half.write_all(cmd.as_bytes()).await.context("write ADD_ONION")?;
    let onion_lines = read_response(&mut reader).await.context("ADD_ONION response")?;
    debug!("Tor ADD_ONION: {:?}", onion_lines);

    // Parse ServiceID from response.
    let service_id = onion_lines
        .iter()
        .find_map(|line| {
            let l = line.trim_start_matches("250-").trim_start_matches("250 ");
            l.strip_prefix("ServiceID=")
        })
        .ok_or_else(|| {
            anyhow::anyhow!("ServiceID not found in ADD_ONION response: {:?}", onion_lines)
        })?
        .trim()
        .to_string();

    // Persist the private key on first run.
    if key_blob.is_none() {
        if let Some(priv_line) = onion_lines.iter().find_map(|line| {
            let l = line.trim_start_matches("250-").trim_start_matches("250 ");
            l.strip_prefix("PrivKey=")
        }) {
            save_onion_key(key_path, priv_line.trim())?;
            info!("Tor: new onion key saved to {}", key_path.display());
        }
    }

    Ok(format!("{service_id}.onion"))
}

// ── Authentication ─────────────────────────────────────────────────────────

async fn authenticate(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    // Ask Tor what auth methods it supports.
    writer.write_all(b"PROTOCOLINFO 1\r\n").await.context("write PROTOCOLINFO")?;
    let info_lines = read_response(reader).await.context("PROTOCOLINFO response")?;
    debug!("Tor PROTOCOLINFO: {:?}", info_lines);

    // Parse: 250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/path/to/cookie"
    let auth_line = info_lines.iter().find(|l| l.contains("AUTH METHODS="));
    let methods: Vec<&str> = auth_line
        .and_then(|l| {
            l.split("METHODS=")
                .nth(1)
                .map(|s| s.split_whitespace().next().unwrap_or(""))
        })
        .map(|s| s.split(',').collect())
        .unwrap_or_default();

    let cookie_file: Option<String> = auth_line
        .and_then(|l| l.split("COOKIEFILE=\"").nth(1))
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string());

    debug!("Tor auth methods: {:?}, cookie file: {:?}", methods, cookie_file);

    // Try COOKIE auth if available, otherwise NULL.
    if (methods.contains(&"COOKIE") || methods.contains(&"SAFECOOKIE"))
        && cookie_file.is_some()
    {
        let path = cookie_file.unwrap();
        match tokio::fs::read(&path).await {
            Ok(cookie_bytes) => {
                let cookie_hex = hex::encode(&cookie_bytes);
                let cmd = format!("AUTHENTICATE {cookie_hex}\r\n");
                writer.write_all(cmd.as_bytes()).await.context("write AUTHENTICATE (cookie)")?;
                let resp = read_response(reader).await.context("AUTHENTICATE cookie response")?;
                if resp.iter().any(|l| l.starts_with("250")) {
                    debug!("Tor: cookie auth succeeded");
                    return Ok(());
                }
                // Fall through to null auth on failure.
                debug!("Tor: cookie auth failed, trying null auth");
            }
            Err(e) => {
                debug!("Tor: could not read cookie file {path}: {e}, trying null auth");
            }
        }
    }

    // NULL auth (requires `CookieAuthentication 0` in torrc, or no auth configured).
    writer.write_all(b"AUTHENTICATE \"\"\r\n").await.context("write AUTHENTICATE (null)")?;
    let resp = read_response(reader).await.context("AUTHENTICATE null response")?;
    if resp.iter().any(|l| l.starts_with("250")) {
        debug!("Tor: null auth succeeded");
        return Ok(());
    }

    bail!("Tor authentication failed. Check control port auth settings. Response: {:?}", resp);
}

// ── Key persistence ────────────────────────────────────────────────────────

/// Read the stored onion private key ("ED25519-V3:<base64>") from disk.
/// Returns None if the file does not exist yet (first run).
fn read_onion_key(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("read onion key {}: {e}", path.display())),
    }
}

fn save_onion_key(path: &Path, key_blob: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    std::fs::write(path, key_blob).with_context(|| format!("write onion key {}", path.display()))
}

// ── Control protocol helpers ───────────────────────────────────────────────

/// Read Tor control protocol response lines until a terminal `250 ...` line.
async fn read_response(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.context("read control response")?;
        let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n');
        if trimmed.is_empty() {
            continue;
        }
        lines.push(trimmed.to_string());
        // Terminal line: "250 " (with space, not dash).
        if trimmed.starts_with("250 ") || trimmed == "250" {
            break;
        }
        // Error responses.
        if trimmed.starts_with('4') || trimmed.starts_with('5') {
            bail!("Tor error response: {trimmed}");
        }
    }
    Ok(lines)
}
