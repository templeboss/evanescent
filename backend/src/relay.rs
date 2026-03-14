//! Outbound HTTP relay for inter-provider communication.
//!
//! All requests are made via Tor SOCKS5 to target provider .onion addresses.

use anyhow::{Context, Result};
use prost::Message as ProstMessage;
use reqwest::Client;
use std::time::Duration;

use crate::proto::{DeliverRequest, PreKeyBundle};

#[derive(Clone)]
pub struct RelayClient {
    client: Client,
}

impl RelayClient {
    pub fn new(tor_socks_port: u16) -> Result<Self> {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{}", tor_socks_port))
            .context("build tor socks proxy")?;
        let client = Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(30))
            .build()
            .context("build relay http client")?;
        Ok(Self { client })
    }

    /// Deliver a sealed envelope to a mailbox on a remote provider.
    pub async fn deliver_message(
        &self,
        provider_onion: &str,
        mailbox_addr: &[u8],
        sealed_envelope: &[u8],
    ) -> Result<()> {
        let req = DeliverRequest {
            mailbox_addr: mailbox_addr.to_vec(),
            sealed_envelope: sealed_envelope.to_vec(),
        };
        let url = format!("http://{}/api/v1/deliver", provider_onion);
        self.client
            .post(&url)
            .header("content-type", "application/x-protobuf")
            .body(req.encode_to_vec())
            .send()
            .await
            .with_context(|| format!("deliver to {}", provider_onion))?
            .error_for_status()
            .with_context(|| format!("deliver response from {}", provider_onion))?;
        Ok(())
    }

    /// Fetch a prekey bundle for a mailbox from a remote provider.
    pub async fn fetch_prekeys(
        &self,
        provider_onion: &str,
        mailbox_addr_hex: &str,
    ) -> Result<PreKeyBundle> {
        let url = format!("http://{}/api/v1/prekeys/{}", provider_onion, mailbox_addr_hex);
        let resp = self
            .client
            .get(&url)
            .header("accept", "application/x-protobuf")
            .send()
            .await
            .with_context(|| format!("fetch prekeys from {}", provider_onion))?
            .error_for_status()
            .with_context(|| format!("prekeys response from {}", provider_onion))?;
        let bytes = resp.bytes().await.context("read prekeys response body")?;
        PreKeyBundle::decode(bytes).context("decode PreKeyBundle")
    }
}
