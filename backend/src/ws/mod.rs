pub mod auth;
pub mod errors;
pub mod handler;
pub mod session;

use crate::{
    mailbox::MailboxStore,
    nym_client::NymHandle,
    prekeys::PrekeyStore,
    proto::{ws_client_message, WsClientMessage},
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
    pub nym: Arc<NymHandle>,
    pub onion_addr: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ws", get(ws_handler))
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
                &state.nym.nym_addr,
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
                    handler::handle_send(sess, req, &*state.nym).await
                }
                Some(Body::UploadPreKeys(req)) => {
                    handler::handle_upload_prekeys(sess, req, &state.prekeys).await
                }
                Some(Body::Ping(_)) => handler::handle_ping(),
                _ => vec![],
            }
        }
    }
}
