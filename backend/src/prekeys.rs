use crate::{
    proto::{OneTimePreKey, SignedPreKey},
    store::Db,
};
use anyhow::{Context, Result};
use prost::Message;
use sqlx::Row;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{interval, Duration};
use tracing::error;

pub const OTPK_REPLENISH_THRESHOLD: usize = 20;
pub const OTPK_INITIAL_BATCH: usize = 100;
/// 14 days in milliseconds (retention after rotation)
const SPK_RETENTION_MS: i64 = 14 * 24 * 3600 * 1000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[derive(Clone)]
pub struct PrekeyStore {
    db: Db,
}

impl PrekeyStore {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn upsert_signed_prekey(&self, mailbox_addr: &str, spk: &SignedPreKey) -> Result<()> {
        let key_data = spk.encode_to_vec();
        let expires_at = now_ms() + SPK_RETENTION_MS;
        sqlx::query(
            "INSERT OR REPLACE INTO signed_prekeys (mailbox_addr, prekey_id, key_data, expires_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(mailbox_addr)
        .bind(spk.prekey_id as i64)
        .bind(key_data)
        .bind(expires_at)
        .execute(&self.db)
        .await
        .context("upsert_signed_prekey")?;
        Ok(())
    }

    /// Returns the most recent non-expired SPK, falling back to the most recent if all expired.
    pub async fn active_signed_prekey(&self, mailbox_addr: &str) -> Result<Option<SignedPreKey>> {
        let now = now_ms();
        // Try non-expired first.
        let row = sqlx::query(
            "SELECT key_data FROM signed_prekeys
             WHERE mailbox_addr = ? AND expires_at > ?
             ORDER BY prekey_id DESC LIMIT 1",
        )
        .bind(mailbox_addr)
        .bind(now)
        .fetch_optional(&self.db)
        .await
        .context("active_spk query")?;

        let key_data: Option<Vec<u8>> = match row {
            Some(r) => Some(r.get("key_data")),
            None => {
                // Fall back to most recent regardless of expiry.
                sqlx::query(
                    "SELECT key_data FROM signed_prekeys
                     WHERE mailbox_addr = ?
                     ORDER BY prekey_id DESC LIMIT 1",
                )
                .bind(mailbox_addr)
                .fetch_optional(&self.db)
                .await
                .context("active_spk fallback")?
                .map(|r| r.get("key_data"))
            }
        };

        match key_data {
            None => Ok(None),
            Some(data) => {
                let spk = SignedPreKey::decode(data.as_slice()).context("decode spk")?;
                Ok(Some(spk))
            }
        }
    }

    pub async fn store_one_time_prekey(
        &self,
        mailbox_addr: &str,
        opk: &OneTimePreKey,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO one_time_prekeys (mailbox_addr, prekey_id, key_data, used)
             VALUES (?, ?, ?, 0)",
        )
        .bind(mailbox_addr)
        .bind(opk.prekey_id as i64)
        .bind(&opk.public_key)
        .execute(&self.db)
        .await
        .context("store_otpk")?;
        Ok(())
    }

    /// Atomically pops one unused OTPK (FIFO). Returns None if the pool is empty.
    pub async fn pop_one_time_prekey(&self, mailbox_addr: &str) -> Result<Option<OneTimePreKey>> {
        let mut tx = self.db.begin().await.context("pop_otpk begin")?;

        let row = sqlx::query(
            "SELECT prekey_id, key_data FROM one_time_prekeys
             WHERE mailbox_addr = ? AND used = 0
             ORDER BY prekey_id ASC LIMIT 1",
        )
        .bind(mailbox_addr)
        .fetch_optional(&mut *tx)
        .await
        .context("pop_otpk select")?;

        let (id, key_data): (i64, Vec<u8>) = match row {
            None => return Ok(None),
            Some(r) => (r.get("prekey_id"), r.get("key_data")),
        };

        sqlx::query(
            "DELETE FROM one_time_prekeys WHERE mailbox_addr = ? AND prekey_id = ?",
        )
        .bind(mailbox_addr)
        .bind(id)
        .execute(&mut *tx)
        .await
        .context("pop_otpk delete")?;

        tx.commit().await.context("pop_otpk commit")?;

        Ok(Some(OneTimePreKey {
            prekey_id: id as u32,
            public_key: key_data,
        }))
    }

    pub async fn otpk_count(&self, mailbox_addr: &str) -> Result<usize> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM one_time_prekeys WHERE mailbox_addr = ? AND used = 0",
        )
        .bind(mailbox_addr)
        .fetch_one(&self.db)
        .await
        .context("otpk_count")?;
        Ok(row.get::<i64, _>("cnt") as usize)
    }

    async fn delete_expired_spks(&self) {
        let now = now_ms();
        if let Err(e) = sqlx::query("DELETE FROM signed_prekeys WHERE expires_at < ?")
            .bind(now)
            .execute(&self.db)
            .await
        {
            error!("SPK rotation prune failed: {e}");
        }
    }

    pub fn spawn_rotation(self) {
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(24 * 3600));
            loop {
                ticker.tick().await;
                self.delete_expired_spks().await;
            }
        });
    }
}
