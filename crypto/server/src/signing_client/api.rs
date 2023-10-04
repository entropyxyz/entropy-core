use std::{net::SocketAddrV4, str::FromStr, time::Duration};

use axum::{
    body::Bytes,
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use entropy_protocol::{
    execute_protocol::{execute_proactive_refresh, Channels},
    KeyParams, ValidatorInfo,
};
use kvdb::kv_manager::{
    helpers::{serialize as key_serialize, deserialize},
};
use synedrion::{KeyShare, KeyShareChange};
use entropy_shared::{SETUP_TIMEOUT_SECONDS};
use parity_scale_codec::Decode;
use sp_core::crypto::AccountId32;
use subxt::{
    ext::sp_core::sr25519, tx::PairSigner, utils::AccountId32 as SubxtAccountId32,
};
use tokio::time::timeout;

use crate::{
    chain_api::{get_api, EntropyConfig},
    helpers::{
        substrate::{get_subgroup, return_all_addresses_of_subgroup},
        user::{check_in_registration_group, send_key},
        validator::{get_signer, get_subxt_signer},
    },
    signing_client::{
        protocol_transport::{handle_socket, open_protocol_connections},
        Listener, ListenerState, ProtocolErr,
    },
    user::api::UserRegistrationInfo,
    validation::{derive_static_secret},
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
    let my_subgroup = subgroup.unwrap(); // subgroup.ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    let mut addresses_in_subgroup =
        return_all_addresses_of_subgroup(&api, my_subgroup).await.unwrap();
    let subxt_signer = get_subxt_signer(&app_state.kv_store).await.unwrap();
    for key in all_keys {
        let sig_request_address = AccountId32::from_str(&key).unwrap();

        // TODO: check key visibility don't do private (requires user to be online)
        // key should always exist, figure out how to handle
        let exists_result = app_state.kv_store.kv().exists(&key).await.unwrap();
        if exists_result {
            let old_key_share = app_state.kv_store.kv().get(&key).await?;
            let deserialized_old_key: KeyShare<KeyParams> = deserialize(&old_key_share).unwrap();
            // do proactive refresh
            let key_share_changes = do_proactive_refresh(&validators_info, &signer, &app_state.listener_state, sig_request_address, &my_subgroup, &subxt_signer).await.unwrap();
            let new_key_share = deserialized_old_key.update(key_share_changes);
            let serialized_key_share = key_serialize(&new_key_share)
                .map_err(|_| ProtocolErr::KvSerialize("Kv Serialize Error".to_string()))?;
            let new_key_info = UserRegistrationInfo { key, value: serialized_key_share, proactive_refresh: true };

            app_state.kv_store.kv().delete(&new_key_info.key).await?;
            let reservation = app_state.kv_store.kv().reserve_key(new_key_info.key.clone()).await?;
            app_state.kv_store.kv().put(reservation, new_key_info.value.clone()).await?;
            send_key(&api, &stash_address, &mut addresses_in_subgroup, new_key_info, &signer);
        }
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

pub async fn do_proactive_refresh(
    validators_info: &Vec<entropy_shared::ValidatorInfo>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    state: &ListenerState,
    sig_request_account: AccountId32,
    my_subgroup: &u8,
    subxt_signer: &subxt_signer::sr25519::Keypair,
) -> Result<KeyShareChange<KeyParams>, ProtocolErr> {
    let session_uid = sig_request_account.to_string();
    let account_id = SubxtAccountId32(*signer.account_id().clone().as_ref());
    let mut converted_validator_info = vec![];
    let mut tss_accounts = vec![];
    for validator_info in validators_info {
        let address_slice: &[u8; 32] = &validator_info
            .tss_account
            .clone()
            .try_into()
            .map_err(|_| ProtocolErr::AddressConversionError("Invalid Length".to_string()))?;
        let tss_account = SubxtAccountId32(*address_slice);
        let validator_info = ValidatorInfo {
            x25519_public_key: validator_info.x25519_public_key,
            ip_address: SocketAddrV4::from_str(std::str::from_utf8(&validator_info.ip_address)?)?,
            tss_account: tss_account.clone(),
        };
        converted_validator_info.push(validator_info);
        tss_accounts.push(tss_account);
    }

    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(converted_validator_info.clone(), &account_id, None);
    state
   .listeners
   .lock()
   .map_err(|_| ProtocolErr::SessionError("Error getting lock".to_string()))?
   // TODO: using signature ID as session ID. Correct?
   .insert(session_uid.clone(), listener);
    let x25519_secret_key = derive_static_secret(signer.signer());

    open_protocol_connections(
        &converted_validator_info,
        &session_uid,
        subxt_signer,
        state,
        &x25519_secret_key,
    )
    .await
    .unwrap();
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };
    let result = execute_proactive_refresh(channels, subxt_signer, tss_accounts, my_subgroup).await?; 
    Ok(result)
}
