use crate::store::Db;
use anyhow::{Context, Result};
use sqlx::Row;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{interval, Duration};
use tracing::{error, info};

const MSG_TTL_MS: i64 = 30 * 24 * 3600 * 1000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[derive(Debug)]
pub struct StoredMsg {
    pub id: String,
    pub mailbox_addr: String,
    pub envelope: Vec<u8>,
    pub received_at: i64,
}

#[derive(Clone)]
pub struct MailboxStore {
    db: Db,
}

impl MailboxStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn register_mailbox(
        &self,
        mailbox_addr: &str,
        identity_key: &[u8],
        nym_address: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO mailboxes (mailbox_addr, identity_key, nym_address, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(mailbox_addr)
        .bind(identity_key)
        .bind(nym_address)
        .bind(now_ms())
        .execute(&self.db)
        .await
        .context("register_mailbox")?;
        Ok(())
    }

    pub async fn identity_key_for(&self, mailbox_addr: &str) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query("SELECT identity_key FROM mailboxes WHERE mailbox_addr = ?")
            .bind(mailbox_addr)
            .fetch_optional(&self.db)
            .await
            .context("identity_key_for")?;
        Ok(row.map(|r| r.get("identity_key")))
    }

    pub async fn store_message(&self, id: &str, mailbox_addr: &str, envelope: &[u8]) -> Result<()> {
        sqlx::query(
            "INSERT INTO messages (id, mailbox_addr, envelope, received_at, delivered)
             VALUES (?, ?, ?, ?, 0)",
        )
        .bind(id)
        .bind(mailbox_addr)
        .bind(envelope)
        .bind(now_ms())
        .execute(&self.db)
        .await
        .context("store_message")?;
        Ok(())
    }

    pub async fn pending_messages(&self, mailbox_addr: &str) -> Result<Vec<StoredMsg>> {
        let rows = sqlx::query(
            "SELECT id, envelope, received_at
             FROM messages
             WHERE mailbox_addr = ? AND delivered = 0
             ORDER BY received_at ASC",
        )
        .bind(mailbox_addr)
        .fetch_all(&self.db)
        .await
        .context("pending_messages")?;

        Ok(rows
            .into_iter()
            .map(|r| StoredMsg {
                id: r.get("id"),
                mailbox_addr: mailbox_addr.to_string(),
                envelope: r.get("envelope"),
                received_at: r.get("received_at"),
            })
            .collect())
    }

    pub async fn ack_messages(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut tx = self.db.begin().await.context("ack begin tx")?;
        for id in ids {
            sqlx::query("DELETE FROM messages WHERE id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("ack {id}"))?;
        }
        tx.commit().await.context("ack commit")?;
        Ok(())
    }

    /// Returns the mailbox_addr of the first registered user, or None.
    pub async fn first_mailbox_addr(&self) -> Result<Option<String>> {
        let row =
            sqlx::query("SELECT mailbox_addr FROM mailboxes ORDER BY created_at ASC LIMIT 1")
                .fetch_optional(&self.db)
                .await
                .context("first_mailbox_addr")?;
        Ok(row.map(|r| r.get("mailbox_addr")))
    }

    async fn clean_expired(&self) {
        let cutoff = now_ms() - MSG_TTL_MS;
        match sqlx::query("DELETE FROM messages WHERE received_at < ?")
            .bind(cutoff)
            .execute(&self.db)
            .await
        {
            Ok(r) if r.rows_affected() > 0 => {
                info!("ttl cleanup: deleted {} messages", r.rows_affected())
            }
            Ok(_) => {}
            Err(e) => error!("ttl cleanup failed: {e}"),
        }
    }

    pub fn spawn_ttl_cleaner(self) {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(24 * 3600));
            loop {
                ticker.tick().await;
                self.clean_expired().await;
            }
        });
    }
}
