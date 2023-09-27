use axum::{
    body::Bytes,
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use parity_scale_codec::Decode;

use crate::{
    signing_client::{protocol_transport::handle_socket, ProtocolErr},
    AppState,
};

pub const SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;

/// HTTP POST endpoint called by the off-chain worker (propagation pallet) during proactive refresh.
/// The http request takes a parity scale encoded [ValidatorInfo] which tells us which validators
/// are in the registration group and will perform a proactive_refresh.
pub async fn proactive_refresh(
    State(app_state): State<AppState>,
    encoded_data: Bytes,
) -> Result<StatusCode, ProtocolErr> {
    let data = entropy_shared::ValidatorInfo::decode(&mut encoded_data.as_ref()).unwrap();
    Ok(StatusCode::OK)
}

/// Handle an incoming websocket connection
pub async fn ws_handler(
    State(app_state): State<AppState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket_result(socket, app_state))
}

async fn handle_socket_result(socket: WebSocket, app_state: AppState) {
    if let Err(err) = handle_socket(socket, app_state).await {
        tracing::warn!("Websocket connection closed unexpectedly {:?}", err);
        // TODO here we should inform the chain that signing failed
    };
}
