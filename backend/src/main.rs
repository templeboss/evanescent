mod config;
mod crypto;
mod mailbox;
mod nym_client;
mod onion;
mod prekeys;
mod proto;
mod store;
mod ws;

use anyhow::{Context, Result};
use mailbox::MailboxStore;
use nym_client::{InboundKind, NymHandle, PREFIX_PREKEY_BUNDLE};
use prekeys::PrekeyStore;
use prost::Message as ProstMessage;
use std::{path::Path, sync::Arc};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;
use ws::AppState;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    // ── CLI args ──────────────────────────────────────────────────────────────
    let config_path = parse_config_arg();

    // ── Config ────────────────────────────────────────────────────────────────
    let cfg = config::load(config_path.as_deref()).context("load config")?;

    // ── Logging ───────────────────────────────────────────────────────────────
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cfg.logging.level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        );
    if cfg.logging.format == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
    info!("evanescent provider starting, version={VERSION}");

    // ── SQLite ────────────────────────────────────────────────────────────────
    let db = store::open(&cfg.storage.db_path).await.context("open db")?;
    let mailbox_store = MailboxStore::new(db.clone());
    let prekey_store = PrekeyStore::new(db);

    // ── Background maintenance tasks ──────────────────────────────────────────
    mailbox_store.clone().spawn_ttl_cleaner();
    prekey_store.clone().spawn_rotation();

    // ── Nym SDK client ────────────────────────────────────────────────────────
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<nym_client::InboundMessage>(256);
    let nym = nym_client::init(Path::new(&cfg.nym.data_dir), inbound_tx)
        .await
        .context("init nym client")?;
    info!("nym address: {}", nym.nym_addr);

    // ── Tor hidden service ────────────────────────────────────────────────────
    // Key path sits next to the database so it is included in the backup.
    let onion_key_path = Path::new(&cfg.storage.db_path)
        .with_file_name("onion.key");
    let onion_addr = onion::start_hidden_service(
        cfg.tor.control_port,
        cfg.tor.ws_port,
        cfg.tor.hidden_service_port,
        &onion_key_path,
    )
    .await
    .context("start tor hidden service")?;
    info!("tor hidden service: {}", onion_addr);

    // ── Inbound message router ────────────────────────────────────────────────
    {
        let mailbox = mailbox_store.clone();
        let prekeys = prekey_store.clone();
        let nym_handle = nym.clone();
        tokio::spawn(async move {
            route_inbound(&mut inbound_rx, &mailbox, &prekeys, &nym_handle).await;
        });
    }

    // ── WebSocket server ──────────────────────────────────────────────────────
    let nym_addr = nym.nym_addr.clone();
    let state = AppState {
        mailbox: mailbox_store,
        prekeys: prekey_store,
        nym: Arc::new(nym),
        onion_addr: onion_addr.clone(),
    };
    let router = ws::router(state);
    let bind_addr = format!("127.0.0.1:{}", cfg.tor.ws_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("bind ws server {bind_addr}"))?;
    info!("WebSocket server listening on {bind_addr}");

    // ── Ready ─────────────────────────────────────────────────────────────────
    println!();
    println!("=== Evanescent Provider Ready ===");
    println!("Onion address : {onion_addr}");
    println!("Nym address   : {nym_addr}");
    println!("=================================");
    println!();

    // ── Serve (runs until SIGINT / SIGTERM) ───────────────────────────────────
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum serve")?;

    info!("shutting down");
    Ok(())
}

/// Route messages arriving from Nym to the appropriate handler.
async fn route_inbound(
    rx: &mut mpsc::Receiver<nym_client::InboundMessage>,
    mailbox: &MailboxStore,
    prekeys: &PrekeyStore,
    nym: &NymHandle,
) {
    while let Some(msg) = rx.recv().await {
        match msg.kind {
            InboundKind::PrekeyRequest => {
                // payload[0] = 0x01 prefix; payload[1..] = PreKeyRequest proto bytes.
                let proto_bytes = &msg.payload[1..];
                handle_prekey_request(proto_bytes, mailbox, prekeys, nym).await;
            }
            InboundKind::PrekeyBundleResponse => {
                // payload[0] = 0x04 prefix; payload[1..] = PreKeyBundle proto bytes.
                // Store in the local mailbox with a "pkb." id so the Android
                // client can distinguish it from sealed envelopes.
                let proto_bytes = &msg.payload[1..];
                let addr = match mailbox.first_mailbox_addr().await {
                    Ok(Some(a)) => a,
                    Ok(None) => {
                        warn!("nym: received prekey bundle but no mailbox registered");
                        continue;
                    }
                    Err(e) => {
                        error!("nym: first_mailbox_addr: {e}");
                        continue;
                    }
                };
                let id = format!("pkb.{}", Uuid::new_v4());
                if let Err(e) = mailbox.store_message(&id, &addr, proto_bytes).await {
                    error!("nym: store prekey bundle: {e}");
                }
            }
            InboundKind::MailboxMessage => {
                let addr = match mailbox.first_mailbox_addr().await {
                    Ok(Some(a)) => a,
                    Ok(None) => {
                        warn!("nym: received message but no mailbox registered");
                        continue;
                    }
                    Err(e) => {
                        error!("nym: first_mailbox_addr: {e}");
                        continue;
                    }
                };
                let id = Uuid::new_v4().to_string();
                if let Err(e) = mailbox.store_message(&id, &addr, &msg.payload).await {
                    error!("nym: store_message: {e}");
                }
            }
        }
    }
}

/// Handle an inbound PreKeyRequest: look up the prekey bundle and send it back.
async fn handle_prekey_request(
    proto_bytes: &[u8],
    mailbox: &MailboxStore,
    prekeys: &PrekeyStore,
    nym: &NymHandle,
) {
    // Parse PreKeyRequest proto (field 1: bytes reply_nym_address).
    let request = match proto::PreKeyRequest::decode(proto_bytes) {
        Ok(r) => r,
        Err(e) => {
            warn!("nym: invalid PreKeyRequest proto: {e}");
            return;
        }
    };

    let reply_addr = match String::from_utf8(request.reply_nym_address.clone()) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            warn!("nym: PreKeyRequest has invalid reply_nym_address");
            return;
        }
    };

    // For a single-user provider the first (and only) mailbox is the user's.
    let mailbox_addr = match mailbox.first_mailbox_addr().await {
        Ok(Some(a)) => a,
        Ok(None) => {
            warn!("nym: prekey request but no mailbox registered");
            return;
        }
        Err(e) => {
            error!("nym: first_mailbox_addr in prekey request: {e}");
            return;
        }
    };

    // Fetch identity key for the mailbox.
    let identity_key = match mailbox.identity_key_for(&mailbox_addr).await {
        Ok(Some(k)) => k,
        Ok(None) => {
            warn!("nym: prekey request but no identity key for mailbox");
            return;
        }
        Err(e) => {
            error!("nym: identity_key_for: {e}");
            return;
        }
    };

    // Get the active signed prekey.
    let spk = match prekeys.active_signed_prekey(&mailbox_addr).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            warn!("nym: prekey request but no signed prekey available");
            return;
        }
        Err(e) => {
            error!("nym: active_signed_prekey: {e}");
            return;
        }
    };

    // Pop a one-time prekey (optional).
    let opk = match prekeys.pop_one_time_prekey(&mailbox_addr).await {
        Ok(o) => o,
        Err(e) => {
            error!("nym: pop_one_time_prekey: {e}");
            None
        }
    };

    // Build PreKeyBundle.
    let bundle = proto::PreKeyBundle {
        identity_key,
        signed_prekey_id: spk.prekey_id,
        signed_prekey: spk.public_key,
        signed_prekey_sig: spk.signature,
        one_time_prekey_id: opk.as_ref().map(|o| o.prekey_id).unwrap_or(0),
        one_time_prekey: opk.map(|o| o.public_key).unwrap_or_default(),
    };

    // Encode with PREFIX_PREKEY_BUNDLE prefix.
    let mut payload = vec![PREFIX_PREKEY_BUNDLE];
    payload.extend_from_slice(&bundle.encode_to_vec());

    if let Err(e) = nym.send(&reply_addr, &payload).await {
        error!("nym: failed to send prekey bundle to {reply_addr}: {e}");
    } else {
        info!("nym: sent prekey bundle to {reply_addr}");
    }
}

/// Parse `--config <path>` from argv.
fn parse_config_arg() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            return args.next();
        }
    }
    None
}

/// Future that resolves on SIGINT or SIGTERM.
async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        signal::ctrl_c().await.expect("ctrl-c handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
