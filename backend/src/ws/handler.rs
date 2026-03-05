use crate::{
    crypto::verify_spk,
    mailbox::MailboxStore,
    nym_client::{NymHandle, PREFIX_MAILBOX_MSG, PREFIX_PREKEY_REQUEST, ROUTING_TAG_LEN},
    prekeys::PrekeyStore,
    proto::{
        ws_server_message, Error, FetchMessages, Messages, Pong, SendAck, SendMessage,
        StoredMessage, UploadPreKeys, WsServerMessage,
    },
    ws::{errors::*, session::Session},
};
use prost::Message as ProstMessage;
use tracing::{error, warn};

const MAX_MESSAGE_BYTES: usize = 32 * 1024;

pub async fn handle_fetch(
    sess: &Session,
    req: FetchMessages,
    mailbox: &MailboxStore,
) -> Vec<Vec<u8>> {
    let mailbox_addr = match sess.mailbox_addr() {
        Some(a) => a,
        None => return vec![error_frame(ERR_AUTH_REQUIRED)],
    };

    if !req.ack_ids.is_empty() {
        if let Err(e) = mailbox.ack_messages(&req.ack_ids).await {
            error!("fetch: ack failed for {}: {e}", mask_addr(mailbox_addr));
        }
    }

    let msgs = match mailbox.pending_messages(mailbox_addr).await {
        Ok(m) => m,
        Err(e) => {
            error!("fetch: pending failed: {e}");
            return vec![error_frame(ERR_INTERNAL)];
        }
    };

    let items = msgs
        .into_iter()
        .map(|m| StoredMessage {
            id: m.id,
            sealed_envelope: m.envelope,
            received_at: m.received_at,
        })
        .collect();

    let reply = WsServerMessage {
        body: Some(ws_server_message::Body::Messages(Messages { items })),
    };
    vec![reply.encode_to_vec()]
}

pub async fn handle_send(sess: &mut Session, req: SendMessage, nym: &NymHandle) -> Vec<Vec<u8>> {
    if !sess.check_send_rate() {
        let reply = WsServerMessage {
            body: Some(ws_server_message::Body::SendAck(SendAck {
                correlation_id: req.correlation_id,
                ok: false,
                error_code: ERR_RATE_LIMITED.to_string(),
            })),
        };
        return vec![reply.encode_to_vec()];
    }

    if req.sealed_envelope.len() > MAX_MESSAGE_BYTES {
        let reply = WsServerMessage {
            body: Some(ws_server_message::Body::SendAck(SendAck {
                correlation_id: req.correlation_id,
                ok: false,
                error_code: ERR_MESSAGE_TOO_LARGE.to_string(),
            })),
        };
        return vec![reply.encode_to_vec()];
    }

    // The to_mailbox_addr must be exactly 32 bytes — the raw BLAKE3 routing tag.
    if req.to_mailbox_addr.len() != ROUTING_TAG_LEN {
        let reply = WsServerMessage {
            body: Some(ws_server_message::Body::SendAck(SendAck {
                correlation_id: req.correlation_id,
                ok: false,
                error_code: ERR_INVALID_MESSAGE.to_string(),
            })),
        };
        return vec![reply.encode_to_vec()];
    }
    let mut routing_tag = [0u8; ROUTING_TAG_LEN];
    routing_tag.copy_from_slice(&req.to_mailbox_addr);

    let nym_prefix = if req.nym_prefix == PREFIX_PREKEY_REQUEST as u32 {
        PREFIX_PREKEY_REQUEST
    } else {
        PREFIX_MAILBOX_MSG
    };

    let (ok, error_code) = match nym
        .send_routed(&req.to_nym_address, nym_prefix, &routing_tag, &req.sealed_envelope)
        .await
    {
        Ok(_) => (true, String::new()),
        Err(e) => {
            warn!("handler: send via nym failed: {e}");
            (false, ERR_INTERNAL.to_string())
        }
    };

    let reply = WsServerMessage {
        body: Some(ws_server_message::Body::SendAck(SendAck {
            correlation_id: req.correlation_id,
            ok,
            error_code,
        })),
    };
    vec![reply.encode_to_vec()]
}

pub async fn handle_upload_prekeys(
    sess: &Session,
    req: UploadPreKeys,
    prekeys: &PrekeyStore,
) -> Vec<Vec<u8>> {
    let mailbox_addr = match sess.mailbox_addr() {
        Some(a) => a,
        None => return vec![error_frame(ERR_AUTH_REQUIRED)],
    };

    let identity_key = match sess.identity_key.as_deref() {
        Some(k) => k,
        None => return vec![error_frame(ERR_AUTH_REQUIRED)],
    };

    for spk in &req.signed_prekeys {
        // Verify the SPK signature before storing. Reject invalid SPKs.
        if let Err(e) = verify_spk(identity_key, &spk.public_key, &spk.signature) {
            warn!("upload: invalid SPK signature (id={}): {e}", spk.prekey_id);
            return vec![error_frame(ERR_INVALID_MESSAGE)];
        }
        if let Err(e) = prekeys.upsert_signed_prekey(mailbox_addr, spk).await {
            error!("upload: upsert SPK: {e}");
        }
    }
    for opk in &req.one_time_prekeys {
        if let Err(e) = prekeys.store_one_time_prekey(mailbox_addr, opk).await {
            error!("upload: store OPK: {e}");
        }
    }
    vec![]
}

pub fn handle_ping() -> Vec<Vec<u8>> {
    let reply = WsServerMessage {
        body: Some(ws_server_message::Body::Pong(Pong {})),
    };
    vec![reply.encode_to_vec()]
}

fn error_frame(code: &str) -> Vec<u8> {
    let msg = WsServerMessage {
        body: Some(ws_server_message::Body::Error(Error {
            code: code.to_string(),
            message: String::new(),
        })),
    };
    msg.encode_to_vec()
}

fn mask_addr(addr: &str) -> String {
    if addr.len() <= 8 {
        return "***".to_string();
    }
    format!("{}...{}", &addr[..4], &addr[addr.len() - 4..])
}
