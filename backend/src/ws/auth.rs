use crate::{
    crypto::{mailbox_addr_from_key, verify_auth},
    mailbox::MailboxStore,
    proto::{ws_server_message, AuthChallenge, AuthOk, Error, ProviderInfo, WsServerMessage},
    ws::{errors::*, session::Session},
};
use anyhow::Result;
use prost::Message as ProstMessage;
use rand::RngCore;

/// Generate a 32-byte nonce and return an AuthChallenge frame.
pub fn start_challenge(sess: &mut Session) -> Result<Vec<u8>> {
    let mut nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    sess.set_nonce(nonce.clone());

    let msg = WsServerMessage {
        body: Some(ws_server_message::Body::AuthChallenge(AuthChallenge {
            nonce,
        })),
    };
    Ok(msg.encode_to_vec())
}

/// Verify AuthResponse and authenticate the session if valid.
///
/// On success returns two frames: [AuthOk, ProviderInfo].
/// On failure returns one frame: [Error].
pub async fn verify_response(
    sess: &mut Session,
    identity_key: &[u8],
    signature: &[u8],
    mailbox_store: &MailboxStore,
    provider_nym_addr: &str,
    provider_onion_addr: &str,
) -> Result<Vec<Vec<u8>>> {
    let nonce = match sess.nonce.take() {
        Some(n) => n,
        None => return Ok(vec![error_frame(ERR_AUTH_REQUIRED)]),
    };

    if let Err(e) = verify_auth(identity_key, &nonce, signature) {
        tracing::debug!("auth failed: {e}");
        return Ok(vec![error_frame(ERR_AUTH_FAILED)]);
    }

    let mailbox_addr = mailbox_addr_from_key(identity_key);

    if let Err(e) = mailbox_store
        .register_mailbox(&mailbox_addr, identity_key, "")
        .await
    {
        tracing::error!("register mailbox: {e}");
        return Ok(vec![error_frame(ERR_INTERNAL)]);
    }

    sess.authenticate(identity_key.to_vec(), mailbox_addr);

    let auth_ok = WsServerMessage {
        body: Some(ws_server_message::Body::AuthOk(AuthOk {
            session_token: vec![],
        })),
    };
    let provider_info = WsServerMessage {
        body: Some(ws_server_message::Body::ProviderInfo(ProviderInfo {
            nym_address: provider_nym_addr.to_string(),
            onion_address: provider_onion_addr.to_string(),
        })),
    };
    Ok(vec![auth_ok.encode_to_vec(), provider_info.encode_to_vec()])
}

pub fn error_frame(code: &str) -> Vec<u8> {
    let msg = WsServerMessage {
        body: Some(ws_server_message::Body::Error(Error {
            code: code.to_string(),
            message: String::new(),
        })),
    };
    msg.encode_to_vec()
}
