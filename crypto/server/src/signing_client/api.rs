use std::{str::FromStr, time::Duration};

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
    KeyParams, ValidatorInfo,
};
use parity_scale_codec::Encode;

use entropy_shared::{
    KeyVisibility, OcwMessageProactiveRefresh, REFRESHES_PRE_SESSION, SETUP_TIMEOUT_SECONDS,
};
use kvdb::kv_manager::{
    helpers::{deserialize, serialize as key_serialize},
    KvManager,
};
use parity_scale_codec::Decode;
use sp_core::crypto::AccountId32;
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32, OnlineClient,
};
use synedrion::KeyShare;
use tokio::time::timeout;

use crate::{
    chain_api::{entropy, get_api, get_rpc, EntropyConfig},
    helpers::{
        launch::LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH,
        substrate::{
            get_key_visibility, get_refreshes_done, get_subgroup, return_all_addresses_of_subgroup,
        },
        user::{check_in_registration_group, send_key},
        validator::{get_signer, get_subxt_signer},
    },
    signing_client::{
        protocol_transport::{handle_socket, open_protocol_connections},
        Listener, ListenerState, ProtocolErr,
    },
    user::api::UserRegistrationInfo,
    validation::derive_static_secret,
    validator::api::get_all_keys,
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
    let ocw_data = OcwMessageProactiveRefresh::decode(&mut encoded_data.as_ref())?;
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    let signer =
        get_signer(&app_state.kv_store).await.map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    check_in_registration_group(&ocw_data.validators_info, signer.account_id())
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    validate_proactive_refresh(&api, &rpc, &app_state.kv_store, &ocw_data).await?;
    // TODO batch the network keys into smaller groups per session
    let all_keys =
        get_all_keys(&api, &rpc).await.map_err(|e| ProtocolErr::ValidatorErr(e.to_string()))?;
    let refreshes_done = get_refreshes_done(&api, &rpc).await?;
    let proactive_refresh_keys = partition_all_keys(refreshes_done, all_keys)?;
    let (subgroup, stash_address) = get_subgroup(&api, &rpc, &signer)
        .await
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    let my_subgroup = subgroup.ok_or_else(|| ProtocolErr::SubgroupError("Subgroup Error"))?;
    let mut addresses_in_subgroup = return_all_addresses_of_subgroup(&api, &rpc, my_subgroup)
        .await
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    let subxt_signer = get_subxt_signer(&app_state.kv_store)
        .await
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    for key in proactive_refresh_keys {
        let sig_request_address = AccountId32::from_str(&key).map_err(ProtocolErr::StringError)?;
        let key_visibility =
            get_key_visibility(&api, &rpc, &sig_request_address.clone().into()).await.unwrap();
        if key_visibility != KeyVisibility::Public && key_visibility != KeyVisibility::Permissioned
        {
            return Ok(StatusCode::ACCEPTED);
        }
        // TODO: check key visibility don't do private (requires user to be online)
        // key should always exist, figure out how to handle
        let exists_result = app_state.kv_store.kv().exists(&key).await?;
        if exists_result {
            let old_key_share = app_state.kv_store.kv().get(&key).await?;
            let deserialized_old_key: KeyShare<KeyParams> = deserialize(&old_key_share)
                .ok_or_else(|| ProtocolErr::Deserialization("Failed to load KeyShare".into()))?;

            let new_key_share = do_proactive_refresh(
                &ocw_data.validators_info,
                &signer,
                &app_state.listener_state,
                sig_request_address,
                &my_subgroup,
                &subxt_signer,
                deserialized_old_key,
            )
            .await?;
            let serialized_key_share = key_serialize(&new_key_share)
                .map_err(|_| ProtocolErr::KvSerialize("Kv Serialize Error".to_string()))?;
            let new_key_info =
                UserRegistrationInfo { key, value: serialized_key_share, proactive_refresh: true };

            app_state.kv_store.kv().delete(&new_key_info.key).await?;
            let reservation = app_state.kv_store.kv().reserve_key(new_key_info.key.clone()).await?;
            app_state.kv_store.kv().put(reservation, new_key_info.value.clone()).await?;
            send_key(&api, &rpc, &stash_address, &mut addresses_in_subgroup, new_key_info, &signer)
                .await
                .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
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
    old_key: KeyShare<KeyParams>,
) -> Result<KeyShare<KeyParams>, ProtocolErr> {
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
    .await?;
    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };
    let result =
        execute_proactive_refresh(channels, subxt_signer, tss_accounts, my_subgroup, old_key)
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

    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| ProtocolErr::OptionUnwrapError("Error getting block hash".to_string()))?;
    let proactive_info_query = entropy::storage().staking_extension().proactive_refresh();
    let proactive_info =
        api.storage().at(block_hash).fetch(&proactive_info_query).await?.ok_or_else(|| {
            ProtocolErr::OptionUnwrapError("Error getting Proactive Refresh data".to_string())
        })?;

    let mut hasher_chain_data = Blake2s256::new();
    hasher_chain_data.update(ocw_data.validators_info.encode());
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

/// Partitions all registered keys into a subset of the network (REFRESHES_PRE_SESSION)
/// Currently rotates between a moving batch of all keys
/// https://github.com/entropyxyz/entropy-core/issues/510
pub fn partition_all_keys(
    refreshes_done: u32,
    all_keys: Vec<String>,
) -> Result<Vec<String>, ProtocolErr> {
    let all_keys_length = all_keys.len() as u32;

    // just return all keys no need to partition network
    if REFRESHES_PRE_SESSION > all_keys_length {
        return Ok(all_keys);
    }

    let mut refresh_keys: Vec<String> = vec![];
    // handles early on refreshes before refreshes done > all keys
    if refreshes_done + REFRESHES_PRE_SESSION <= all_keys_length {
        let lower = refreshes_done as usize;
        let upper = (refreshes_done + REFRESHES_PRE_SESSION) as usize;
        refresh_keys = all_keys[lower..upper].to_vec();
    }

    // normalize refreshes done down to a partition of the network
    let normalized_refreshes_done = refreshes_done % all_keys_length;

    if normalized_refreshes_done + REFRESHES_PRE_SESSION <= all_keys_length {
        let lower = normalized_refreshes_done as usize;
        let upper = (normalized_refreshes_done + REFRESHES_PRE_SESSION) as usize;

        refresh_keys = all_keys[lower..upper].to_vec();
    }

    // handles if number does not perfectly fit
    // loops around the partiton adding the beginning of the network to the end
    if normalized_refreshes_done + REFRESHES_PRE_SESSION > all_keys_length {
        let lower = normalized_refreshes_done as usize;
        let upper = all_keys.len();
        refresh_keys = all_keys[lower..upper].to_vec();

        let leftover =
            (REFRESHES_PRE_SESSION - (all_keys_length - normalized_refreshes_done)) as usize;

        let mut post_turnaround_keys = all_keys[0..leftover].to_vec();
        refresh_keys.append(&mut post_turnaround_keys);
    }

    Ok(refresh_keys)
}
