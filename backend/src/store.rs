use anyhow::{Context, Result};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};
use std::str::FromStr;

pub type Db = SqlitePool;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS mailboxes (
    mailbox_addr TEXT PRIMARY KEY,
    identity_key BLOB NOT NULL,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id           TEXT PRIMARY KEY,
    mailbox_addr TEXT NOT NULL,
    envelope     BLOB NOT NULL,
    received_at  INTEGER NOT NULL,
    delivered    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS signed_prekeys (
    mailbox_addr TEXT NOT NULL,
    prekey_id    INTEGER NOT NULL,
    key_data     BLOB NOT NULL,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (mailbox_addr, prekey_id)
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    mailbox_addr TEXT NOT NULL,
    prekey_id    INTEGER NOT NULL,
    key_data     BLOB NOT NULL,
    used         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mailbox_addr, prekey_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_mailbox ON messages(mailbox_addr, received_at);
CREATE INDEX IF NOT EXISTS idx_otpk_mailbox ON one_time_prekeys(mailbox_addr, used);
";

pub async fn open(path: &str) -> Result<Db> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))
        .with_context(|| format!("parse sqlite path: {path}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .with_context(|| format!("open sqlite: {path}"))?;

    // Run schema (all statements are CREATE IF NOT EXISTS — idempotent).
    sqlx::query(SCHEMA)
        .execute(&pool)
        .await
        .context("schema migration")?;

    Ok(pool)
}
