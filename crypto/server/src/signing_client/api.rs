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
    chain_api::get_api,
    helpers::{user::{check_in_registration_group, send_key}, validator::get_signer, substrate::{get_subgroup, return_all_addresses_of_subgroup}},
    signing_client::{protocol_transport::handle_socket, ProtocolErr},
    user::api::UserRegistrationInfo,
    validator::api::get_all_keys,
    AppState,
};

pub const SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;
pub const KEY_AMOUNT_PROACTIVE_REFRESH: usize = 1000;
/// HTTP POST endpoint called by the off-chain worker (propagation pallet) during proactive refresh.
/// The http request takes a parity scale encoded [ValidatorInfo] which tells us which validators
/// are in the registration group and will perform a proactive_refresh.
pub async fn proactive_refresh(
    State(app_state): State<AppState>,
    encoded_data: Bytes,
) -> Result<StatusCode, ProtocolErr> {
    let validators_info =
        Vec::<entropy_shared::ValidatorInfo>::decode(&mut encoded_data.as_ref()).unwrap();
    let api = get_api(&app_state.configuration.endpoint).await.unwrap();
    let signer = get_signer(&app_state.kv_store).await.unwrap();
    check_in_registration_group(&validators_info, signer.account_id()).unwrap();
    // TODO batch the network keys into smaller groups per session
    let all_keys = get_all_keys(&api, KEY_AMOUNT_PROACTIVE_REFRESH).await.unwrap();
    let (subgroup, stash_address) = get_subgroup(&api, &signer).await.unwrap();
    let my_subgroup = subgroup.unwrap();//subgroup.ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    let mut addresses_in_subgroup = return_all_addresses_of_subgroup(&api, my_subgroup).await.unwrap();

    for key in all_keys {
        // do proactive refresh

        let new_key_info = UserRegistrationInfo { key, value: vec![10], proactive_refresh: true };

        app_state.kv_store.kv().delete(&new_key_info.key).await?;
        let reservation = app_state.kv_store.kv().reserve_key(new_key_info.key.clone()).await?;
        app_state.kv_store.kv().put(reservation, new_key_info.value.clone()).await?;

        send_key(&api, &stash_address, &mut addresses_in_subgroup, new_key_info, &signer);
    }
    // TODO: Tell chain refresh is done?
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
