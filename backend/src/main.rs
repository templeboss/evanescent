mod config;
mod crypto;
mod mailbox;
mod onion;
mod prekeys;
mod proto;
mod relay;
mod store;
mod ws;

use anyhow::{Context, Result};
use mailbox::MailboxStore;
use prekeys::PrekeyStore;
use relay::RelayClient;
use std::{path::Path, sync::Arc};
use tracing::info;
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

    // ── Relay client (outbound HTTP via Tor SOCKS5) ───────────────────────────
    let relay = RelayClient::new(cfg.tor.socks_port).context("init relay client")?;

    // ── Tor hidden service ────────────────────────────────────────────────────
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

    // ── WebSocket + HTTP API server ───────────────────────────────────────────
    let state = AppState {
        mailbox: mailbox_store,
        prekeys: prekey_store,
        relay: Arc::new(relay),
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
