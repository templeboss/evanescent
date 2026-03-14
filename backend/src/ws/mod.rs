pub mod auth;
pub mod errors;
pub mod handler;
pub mod session;

use crate::{
    mailbox::MailboxStore,
    prekeys::PrekeyStore,
    proto::{ws_client_message, DeliverRequest, PreKeyBundle, WsClientMessage},
    relay::RelayClient,
    ws::{auth as auth_mod, errors::*, session::Session},
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

const MAX_FRAME_SIZE: usize = 512 * 1024;
const OUTBOUND_QUEUE: usize = 100;

#[derive(Clone)]
pub struct AppState {
    pub mailbox: MailboxStore,
    pub prekeys: PrekeyStore,
    pub relay: Arc<RelayClient>,
    pub onion_addr: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/v1/deliver", axum::routing::post(deliver_handler))
        .route("/api/v1/prekeys/:mailbox_addr", axum::routing::get(prekeys_handler))
        .with_state(state)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.max_message_size(MAX_FRAME_SIZE)
        .on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sink, mut stream) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE);

    tokio::spawn(async move {
        while let Some(data) = outbound_rx.recv().await {
            if sink.send(Message::Binary(data)).await.is_err() {
                break;
            }
        }
    });

    let mut sess = Session::new();

    while let Some(result) = stream.next().await {
        let data = match result {
            Ok(Message::Binary(d)) => d,
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(e) => {
                debug!("ws read error: {e}");
                break;
            }
        };

        let msg = match WsClientMessage::decode(data.as_ref()) {
            Ok(m) => m,
            Err(_) => {
                let _ = outbound_tx.try_send(auth_mod::error_frame(ERR_INVALID_MESSAGE));
                break;
            }
        };

        let replies = dispatch(&mut sess, msg, &state).await;
        for frame in replies {
            if outbound_tx.try_send(frame).is_err() {
                warn!("ws: outbound queue full");
                let _ = outbound_tx.try_send(auth_mod::error_frame(ERR_QUEUE_FULL));
                break;
            }
        }
    }
}

async fn dispatch(
    sess: &mut Session,
    msg: WsClientMessage,
    state: &AppState,
) -> Vec<Vec<u8>> {
    use ws_client_message::Body;

    match msg.body {
        Some(Body::AuthChallengeRequest(_)) => match auth_mod::start_challenge(sess) {
            Ok(frame) => vec![frame],
            Err(e) => {
                tracing::error!("auth challenge: {e}");
                vec![auth_mod::error_frame(ERR_INTERNAL)]
            }
        },

        Some(Body::AuthResponse(resp)) => {
            match auth_mod::verify_response(
                sess,
                &resp.identity_key,
                &resp.signature,
                &state.mailbox,
                &state.onion_addr,
            )
            .await
            {
                Ok(frames) => frames,
                Err(e) => {
                    tracing::error!("auth verify: {e}");
                    vec![auth_mod::error_frame(ERR_INTERNAL)]
                }
            }
        }

        body => {
            if !sess.authed {
                return vec![auth_mod::error_frame(ERR_AUTH_REQUIRED)];
            }
            match body {
                Some(Body::FetchMessages(req)) => {
                    handler::handle_fetch(sess, req, &state.mailbox).await
                }
                Some(Body::SendMessage(req)) => {
                    handler::handle_send(sess, req, &state.relay).await
                }
                Some(Body::UploadPreKeys(req)) => {
                    handler::handle_upload_prekeys(sess, req, &state.prekeys).await
                }
                Some(Body::GetPreKeys(req)) => {
                    handler::handle_get_prekeys(sess, req, &state.relay).await
                }
                Some(Body::Ping(_)) => handler::handle_ping(),
                _ => vec![],
            }
        }
    }
}

async fn deliver_handler(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> impl axum::response::IntoResponse {
    use axum::http::StatusCode;
    use uuid::Uuid;

    let req = match DeliverRequest::decode(body) {
        Ok(r) => r,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if req.mailbox_addr.len() != 32 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let mailbox_addr = hex::encode(&req.mailbox_addr);
    let id = Uuid::new_v4().to_string();
    match state.mailbox.store_message(&id, &mailbox_addr, &req.sealed_envelope).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!("deliver: store_message: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn prekeys_handler(
    State(state): State<AppState>,
    axum::extract::Path(mailbox_addr_hex): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    use axum::http::StatusCode;

    if mailbox_addr_hex.len() != 64 || !mailbox_addr_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let spk = match state.prekeys.active_signed_prekey(&mailbox_addr_hex).await {
        Ok(Some(s)) => s,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("prekeys: active_signed_prekey: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let identity_key = match state.mailbox.identity_key_for(&mailbox_addr_hex).await {
        Ok(Some(k)) => k,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("prekeys: identity_key_for: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let opk = state.prekeys.pop_one_time_prekey(&mailbox_addr_hex).await.ok().flatten();
    let bundle = PreKeyBundle {
        identity_key,
        signed_prekey_id: spk.prekey_id,
        signed_prekey: spk.public_key,
        signed_prekey_sig: spk.signature,
        one_time_prekey_id: opk.as_ref().map(|o| o.prekey_id).unwrap_or(0),
        one_time_prekey: opk.map(|o| o.public_key).unwrap_or_default(),
    };

    (
        StatusCode::OK,
        [("content-type", "application/x-protobuf")],
        bundle.encode_to_vec(),
    ).into_response()
}
