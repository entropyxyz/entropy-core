use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};

use crate::{signing_client::protocol_transport::handle_socket, AppState};

pub const SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;

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
