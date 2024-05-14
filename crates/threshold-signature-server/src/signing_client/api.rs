// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use blake2::{Blake2s256, Digest};
use entropy_protocol::{
    execute_protocol::{execute_proactive_refresh, Channels},
    KeyParams, Listener, SessionId, ValidatorInfo,
};
use parity_scale_codec::Encode;

use entropy_kvdb::kv_manager::{
    helpers::{deserialize, serialize as key_serialize},
    KvManager,
};
use entropy_shared::{KeyVisibility, OcwMessageProactiveRefresh, SETUP_TIMEOUT_SECONDS};
use parity_scale_codec::Decode;
use sp_core::Pair;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    ext::sp_core::sr25519,
    tx::PairSigner,
    utils::{AccountId32 as SubxtAccountId32, Static},
    OnlineClient,
};
use synedrion::KeyShare;
use tokio::time::timeout;
use x25519_dalek::StaticSecret;

use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_staking_extension::pallet::RefreshInfo},
        get_api, get_rpc, EntropyConfig,
    },
    helpers::{
        launch::LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH,
        substrate::{
            get_registered_details, get_stash_address, get_subgroup, query_chain,
            return_all_addresses_of_subgroup,
        },
        user::{check_in_registration_group, send_key},
        validator::get_signer_and_x25519_secret,
    },
    signing_client::{
        protocol_transport::{handle_socket, open_protocol_connections},
        ListenerState, ProtocolErr,
    },
    user::api::UserRegistrationInfo,
    AppState,
};

pub const SUBSCRIBE_TIMEOUT_SECONDS: u64 = 10;

/// HTTP POST endpoint called by the a Substrate node during proactive refresh.
///
/// In particular, it is the Propogation pallet, with the use of an off-chain worker, which
/// initiates this request.
///
/// The HTTP request takes a Parity SCALE encoded [ValidatorInfo] which indicates which validators
/// are in the registration group and will perform a proactive refresh.
#[tracing::instrument(skip_all)]
pub async fn proactive_refresh(
    State(app_state): State<AppState>,
    encoded_data: Bytes,
) -> Result<StatusCode, ProtocolErr> {
    let ocw_data = OcwMessageProactiveRefresh::decode(&mut encoded_data.as_ref())?;
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    let (signer, x25519_secret_key) = get_signer_and_x25519_secret(&app_state.kv_store)
        .await
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;

    check_in_registration_group(&ocw_data.validators_info, signer.account_id())
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    validate_proactive_refresh(&api, &rpc, &app_state.kv_store, &ocw_data).await?;

    let subgroup = get_subgroup(&api, &rpc, signer.account_id())
        .await
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;

    let stash_address = get_stash_address(&api, &rpc, signer.account_id())
        .await
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;

    let mut addresses_in_subgroup = return_all_addresses_of_subgroup(&api, &rpc, subgroup)
        .await
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;

    for encoded_key in ocw_data.proactive_refresh_keys {
        let key = hex::encode(&encoded_key);
        let key_visibility = get_registered_details(&api, &rpc, encoded_key.clone())
            .await
            .map_err(|e| ProtocolErr::UserError(e.to_string()))?
            .key_visibility
            .0;

        // Check key visibility and don't do proactive refresh if it is private as this would require the user to be online
        if key_visibility == KeyVisibility::Public {
            // key should always exist, figure out how to handle
            let exists_result = app_state.kv_store.kv().exists(&key).await?;
            if exists_result {
                let old_key_share = app_state.kv_store.kv().get(&key).await?;
                let deserialized_old_key: KeyShare<KeyParams> = deserialize(&old_key_share)
                    .ok_or_else(|| {
                        ProtocolErr::Deserialization("Failed to load KeyShare".into())
                    })?;

                let new_key_share = do_proactive_refresh(
                    &ocw_data.validators_info,
                    &signer,
                    &x25519_secret_key,
                    &app_state.listener_state,
                    encoded_key,
                    deserialized_old_key,
                    ocw_data.block_number,
                )
                .await?;
                let serialized_key_share = key_serialize(&new_key_share)
                    .map_err(|_| ProtocolErr::KvSerialize("Kv Serialize Error".to_string()))?;
                let new_key_info = UserRegistrationInfo {
                    key,
                    value: serialized_key_share,
                    proactive_refresh: true,
                    sig_request_address: None,
                };

                app_state.kv_store.kv().delete(&new_key_info.key).await?;
                let reservation =
                    app_state.kv_store.kv().reserve_key(new_key_info.key.clone()).await?;
                app_state.kv_store.kv().put(reservation, new_key_info.value.clone()).await?;
                send_key(
                    &api,
                    &rpc,
                    &stash_address,
                    &mut addresses_in_subgroup,
                    new_key_info,
                    &signer,
                )
                .await
                .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
            }
        }
    }
    // TODO: Tell chain refresh is done?
    Ok(StatusCode::OK)
}

/// Handle an incoming websocket connection
#[tracing::instrument(skip(app_state))]
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

#[tracing::instrument(
    skip_all,
    fields(validators_info, verifying_key, my_subgroup),
    level = tracing::Level::DEBUG
)]
pub async fn do_proactive_refresh(
    validators_info: &Vec<entropy_shared::ValidatorInfo>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    x25519_secret_key: &StaticSecret,
    state: &ListenerState,
    verifying_key: Vec<u8>,
    old_key: KeyShare<KeyParams>,
    block_number: u32,
) -> Result<KeyShare<KeyParams>, ProtocolErr> {
    tracing::debug!("Preparing to perform proactive refresh");
    tracing::debug!("Signing with {:?}", &signer.signer().public());

    let session_id = SessionId::ProactiveRefresh { verifying_key, block_number };
    let account_id = SubxtAccountId32(signer.signer().public().0);
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
            ip_address: std::str::from_utf8(&validator_info.ip_address)?.to_string(),
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
        .insert(session_id.clone(), listener);

    open_protocol_connections(
        &converted_validator_info,
        &session_id,
        signer.signer(),
        state,
        x25519_secret_key,
    )
    .await?;
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };
    let result =
        execute_proactive_refresh(session_id, channels, signer.signer(), tss_accounts, old_key)
            .await?;
    Ok(result)
}

///
/// Validates proactive refresh call.
///
/// It checks that:
/// - the data matches what is on-chain
/// - the data is not repeated on-chain
pub async fn validate_proactive_refresh(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    kv_manager: &KvManager,
    ocw_data: &OcwMessageProactiveRefresh,
) -> Result<(), ProtocolErr> {
    let last_block_number_recorded =
        kv_manager.kv().get(LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH).await?;

    let latest_block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| ProtocolErr::OptionUnwrapError("Failed to get block number".to_string()))?
        .number;
    // prevents multiple repeated messages being sent
    if u32::from_be_bytes(
        last_block_number_recorded
            .try_into()
            .map_err(|_| ProtocolErr::Conversion("Block number conversion"))?,
    ) >= latest_block_number
        && latest_block_number != 0
    {
        return Err(ProtocolErr::RepeatedData);
    }

    let proactive_info_query = entropy::storage().staking_extension().proactive_refresh();
    let proactive_info = query_chain(api, rpc, proactive_info_query, None)
        .await?
        .ok_or_else(|| ProtocolErr::ChainFetch("Error getting Proactive Refresh data"))?;
    let mut hasher_chain_data = Blake2s256::new();
    let ocw_data_refresh_info = RefreshInfo {
        proactive_refresh_keys: ocw_data.proactive_refresh_keys.clone(),
        validators_info: ocw_data.validators_info.clone().into_iter().map(Static).collect(),
    };
    hasher_chain_data.update(ocw_data_refresh_info.encode());
    let chain_data_hash = hasher_chain_data.finalize();
    let mut hasher_verifying_data = Blake2s256::new();
    hasher_verifying_data.update(proactive_info.encode());
    let verifying_data_hash = hasher_verifying_data.finalize();
    // checks validity of data
    if verifying_data_hash != chain_data_hash {
        return Err(ProtocolErr::InvalidData);
    }

    kv_manager.kv().delete(LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH).await?;
    let reservation =
        kv_manager.kv().reserve_key(LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH.to_string()).await?;
    kv_manager.kv().put(reservation, latest_block_number.to_be_bytes().to_vec()).await?;
    Ok(())
}
