//! Nym mixnet integration via the native Rust SDK.
//!
//! Wire format for all Nym messages (shared provider model):
//!   byte[0]    prefix byte
//!   byte[1..33] routing_tag — 32 raw bytes of the target/reply mailbox address
//!   byte[33..]  payload
//!
//! Prefix bytes:
//!   0x01 → PreKeyRequest  (routing_tag = target mailbox whose bundle is wanted)
//!   0x02 → loop cover     (no routing_tag; discard)
//!   0x03 → drop cover     (no routing_tag; discard)
//!   0x04 → PreKeyBundle response (routing_tag = requester's mailbox for storage)
//!   0x05 → sealed envelope for mailbox (routing_tag = recipient mailbox)

use anyhow::{Context, Result};
use bytes::Bytes;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use nym_sdk::mixnet::{MixnetClientBuilder, MixnetMessageSender, Recipient, StoragePaths};

pub const PREFIX_PREKEY_REQUEST:  u8 = 0x01;
pub const PREFIX_LOOP_COVER:      u8 = 0x02;
pub const PREFIX_DROP_COVER:      u8 = 0x03;
pub const PREFIX_PREKEY_BUNDLE:   u8 = 0x04;
pub const PREFIX_MAILBOX_MSG:     u8 = 0x05;

/// Length of the routing tag that follows every non-cover prefix byte.
pub const ROUTING_TAG_LEN: usize = 32;

/// Minimum valid message length for prefixed messages that carry a routing tag.
const MIN_ROUTED_LEN: usize = 1 + ROUTING_TAG_LEN;

/// All Nym messages are padded to a multiple of this many bytes to prevent
/// length-based traffic analysis (standards.md §10, §12).
const PAD_BLOCK: usize = 512;

/// Handle for sending messages via Nym. Cheaply clonable.
#[derive(Clone)]
pub struct NymHandle {
    outbound_tx: mpsc::Sender<(String, Bytes)>,
    pub nym_addr: String,
}

impl NymHandle {
    /// Send `[prefix][routing_tag][payload]` to the given Nym recipient address.
    /// The full message is padded to a multiple of PAD_BLOCK before sending.
    pub async fn send_routed(
        &self,
        to_addr: &str,
        prefix: u8,
        routing_tag: &[u8; ROUTING_TAG_LEN],
        payload: &[u8],
    ) -> Result<()> {
        let mut msg = Vec::with_capacity(1 + ROUTING_TAG_LEN + payload.len());
        msg.push(prefix);
        msg.extend_from_slice(routing_tag);
        msg.extend_from_slice(payload);
        let padded = pad_to_block(&msg);
        self.outbound_tx
            .send((to_addr.to_string(), Bytes::from(padded)))
            .await
            .map_err(|_| anyhow::anyhow!("nym outbound channel closed"))
    }
}

/// Pad `data` with zero bytes to the next multiple of PAD_BLOCK.
fn pad_to_block(data: &[u8]) -> Vec<u8> {
    let remainder = data.len() % PAD_BLOCK;
    if remainder == 0 {
        data.to_vec()
    } else {
        let mut padded = data.to_vec();
        padded.resize(data.len() + (PAD_BLOCK - remainder), 0);
        padded
    }
}

/// Inbound routed message.
pub struct InboundMessage {
    pub kind:         InboundKind,
    /// 32-byte mailbox address extracted from the routing tag.
    pub routing_tag:  [u8; ROUTING_TAG_LEN],
    /// Payload bytes (everything after the 33-byte header).
    pub payload:      Vec<u8>,
}

pub enum InboundKind {
    PrekeyRequest,
    PrekeyBundleResponse,
    MailboxMessage,
}

/// Initialise the Nym SDK client, spawn its event loop, and return a handle.
///
/// `inbound_tx` receives all routed mailbox messages and prekey requests.
pub async fn init(
    data_dir: &Path,
    inbound_tx: mpsc::Sender<InboundMessage>,
) -> Result<NymHandle> {
    let paths = StoragePaths::new_from_dir(data_dir).context("nym storage paths")?;

    let mut client = MixnetClientBuilder::new_with_default_storage(paths)
        .await
        .context("nym builder")?
        .build()
        .context("nym build")?
        .connect_to_mixnet()
        .await
        .context("connect to mixnet")?;

    let nym_addr = client.nym_address().to_string();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<(String, Bytes)>(128);

    tokio::spawn(async move {
        loop {
            // Drain the outbound queue without blocking.
            loop {
                match outbound_rx.try_recv() {
                    Ok((addr, payload)) => match Recipient::from_str(&addr) {
                        Ok(recipient) => {
                            if let Err(e) = client.send_plain_message(recipient, &payload).await {
                                warn!("nym send error: {e}");
                            }
                        }
                        Err(e) => warn!("invalid nym recipient '{addr}': {e}"),
                    },
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
                }
            }

            // Wait for inbound messages with a short timeout.
            match tokio::time::timeout(Duration::from_millis(50), client.wait_for_messages()).await
            {
                Ok(Some(msgs)) => {
                    for msg in msgs {
                        let raw = msg.message;

                        // Cover traffic: no routing tag.
                        match raw.first().copied() {
                            Some(PREFIX_LOOP_COVER) | Some(PREFIX_DROP_COVER) => {
                                debug!("nym: discarding cover message");
                                continue;
                            }
                            _ => {}
                        }

                        // All other messages must have at least 1 + ROUTING_TAG_LEN bytes.
                        if raw.len() < MIN_ROUTED_LEN {
                            warn!("nym: received message too short ({} bytes), dropping", raw.len());
                            continue;
                        }

                        let prefix = raw[0];
                        let mut routing_tag = [0u8; ROUTING_TAG_LEN];
                        routing_tag.copy_from_slice(&raw[1..1 + ROUTING_TAG_LEN]);
                        // Strip padding: keep only the payload after the header.
                        let payload = raw[1 + ROUTING_TAG_LEN..].to_vec();

                        let kind = match prefix {
                            PREFIX_PREKEY_REQUEST => {
                                debug!("nym: received prekey request");
                                InboundKind::PrekeyRequest
                            }
                            PREFIX_PREKEY_BUNDLE => {
                                debug!("nym: received prekey bundle response");
                                InboundKind::PrekeyBundleResponse
                            }
                            PREFIX_MAILBOX_MSG => InboundKind::MailboxMessage,
                            other => {
                                warn!("nym: unknown prefix byte 0x{other:02x}, dropping");
                                continue;
                            }
                        };

                        if inbound_tx
                            .send(InboundMessage { kind, routing_tag, payload })
                            .await
                            .is_err()
                        {
                            error!("nym: inbound channel closed, shutting down");
                            return;
                        }
                    }
                }
                Ok(None) => {
                    error!("nym: client returned None from wait_for_messages");
                    return;
                }
                Err(_timeout) => {} // Normal — loop again to check outbound.
            }
        }
    });

    Ok(NymHandle {
        outbound_tx,
        nym_addr,
    })
}
