//! Nym mixnet integration via the native Rust SDK.
//!
//! The SDK handles cover traffic automatically (Loopix loop/drop messages) —
//! no manual cover traffic implementation is needed.
//!
//! Inbound routing prefix bytes:
//!   0x01 → prekey bundle request
//!   0x02 → loop cover (discard)
//!   0x03 → drop cover (discard)
//!   0x04 → prekey bundle response (inbound to requester's provider)
//!   other → sealed envelope for mailbox store

use anyhow::{Context, Result};
use bytes::Bytes;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use nym_sdk::mixnet::{MixnetClientBuilder, MixnetMessageSender, Recipient, StoragePaths};

pub const PREFIX_PREKEY_REQUEST: u8 = 0x01;
pub const PREFIX_LOOP_COVER: u8 = 0x02;
pub const PREFIX_DROP_COVER: u8 = 0x03;
pub const PREFIX_PREKEY_BUNDLE: u8 = 0x04;

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
    /// Send a payload to the given Nym recipient address.
    /// The payload is padded to a multiple of PAD_BLOCK bytes before sending.
    pub async fn send(&self, to_addr: &str, payload: &[u8]) -> Result<()> {
        let padded = pad_to_block(payload);
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
    pub kind: InboundKind,
    pub payload: Vec<u8>,
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
            // Drain the outbound queue without blocking (non-blocking try_recv).
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

            // Wait for inbound messages with a short timeout so sends are not
            // starved when the provider is under load.
            match tokio::time::timeout(Duration::from_millis(50), client.wait_for_messages()).await
            {
                Ok(Some(msgs)) => {
                    for msg in msgs {
                        let payload = msg.message;
                        let kind = match payload.first().copied() {
                            Some(PREFIX_PREKEY_REQUEST) => {
                                debug!("nym: received prekey request");
                                InboundKind::PrekeyRequest
                            }
                            Some(PREFIX_PREKEY_BUNDLE) => {
                                debug!("nym: received prekey bundle response");
                                InboundKind::PrekeyBundleResponse
                            }
                            Some(PREFIX_LOOP_COVER) | Some(PREFIX_DROP_COVER) => {
                                debug!("nym: discarding cover message");
                                continue;
                            }
                            _ => InboundKind::MailboxMessage,
                        };
                        if inbound_tx
                            .send(InboundMessage { kind, payload })
                            .await
                            .is_err()
                        {
                            error!("nym: inbound channel closed, shutting down");
                            return;
                        }
                    }
                }
                Ok(None) => {
                    // Client disconnected.
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
