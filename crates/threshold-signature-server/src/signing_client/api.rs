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
    execute_protocol::{execute_reshare, Channels},
    KeyParams, Listener, PartyId, SessionId, ValidatorInfo,
};
use parity_scale_codec::Encode;
use std::{collections::BTreeSet, time::Duration};

use entropy_client::substrate::PairSigner;
use entropy_shared::{OcwMessageProactiveRefresh, SETUP_TIMEOUT_SECONDS};
use parity_scale_codec::Decode;
use sp_core::Pair;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    utils::{AccountId32 as SubxtAccountId32, Static},
    OnlineClient,
};
use synedrion::{AuxInfo, KeyResharing, NewHolder, OldHolder, ThresholdKeyShare};
use tokio::time::timeout;
use x25519_dalek::StaticSecret;

use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_staking_extension::pallet::RefreshInfo},
        get_api, get_rpc, EntropyConfig,
    },
    helpers::{
        app_state::{BlockNumberFields, Cache},
        substrate::query_chain,
        user::check_in_registration_group,
    },
    signing_client::{
        protocol_transport::{handle_socket, open_protocol_connections},
        ListenerState, ProtocolErr,
    },
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
    if !app_state.cache.is_ready() {
        return Err(ProtocolErr::NotReady);
    }

    let ocw_data = OcwMessageProactiveRefresh::decode(&mut encoded_data.as_ref())?;
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    check_in_registration_group(&ocw_data.validators_info, &app_state.subxt_account_id())
        .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    validate_proactive_refresh(&api, &rpc, &app_state.cache, &ocw_data).await?;

    if let Some(old_key_share) = app_state.network_key_share()? {
        let new_key_share = do_proactive_refresh(
            &ocw_data.validators_info,
            &app_state.signer(),
            &app_state.x25519_secret,
            &app_state.cache.listener_state,
            old_key_share.0,
            ocw_data.block_number,
            old_key_share.1,
        )
        .await?;

        app_state.update_network_key_share(Some(new_key_share)).await?;
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
    };
}

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
#[tracing::instrument(
    skip_all,
    fields(validators_info, verifying_key, my_subgroup),
    level = tracing::Level::DEBUG
)]
pub async fn do_proactive_refresh(
    validators_info: &Vec<entropy_shared::ValidatorInfo>,
    signer: &PairSigner,
    x25519_secret_key: &StaticSecret,
    state: &ListenerState,
    old_key: ThresholdKeyShare<KeyParams, PartyId>,
    block_number: u32,
    aux_info: AuxInfo<KeyParams, PartyId>,
) -> Result<(ThresholdKeyShare<KeyParams, PartyId>, AuxInfo<KeyParams, PartyId>), ProtocolErr> {
    tracing::debug!("Preparing to perform proactive refresh");
    tracing::debug!("Signing with {:?}", &signer.signer().public());
    let verifying_key = old_key.verifying_key()?;
    let verifying_key_vec = verifying_key.to_encoded_point(true).as_bytes().to_vec();

    let session_id = SessionId::Reshare { verifying_key: verifying_key_vec, block_number };
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

    let party_ids: BTreeSet<PartyId> = tss_accounts.iter().cloned().map(PartyId::new).collect();

    let inputs = KeyResharing::new(
        Some(OldHolder { key_share: old_key.clone() }),
        Some(NewHolder {
            verifying_key,
            old_threshold: party_ids.len(),
            old_holders: party_ids.clone(),
        }),
        party_ids.clone(),
        old_key.threshold(),
    );

    let channels = get_channels(
        state,
        converted_validator_info,
        account_id,
        &session_id,
        signer,
        x25519_secret_key,
    )
    .await?;

    let result =
        execute_reshare(session_id, channels, signer.signer(), inputs, &party_ids, Some(aux_info))
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
    cache: &Cache,
    ocw_data: &OcwMessageProactiveRefresh,
) -> Result<(), ProtocolErr> {
    let latest_block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| ProtocolErr::OptionUnwrapError("Failed to get block number".to_string()))?
        .number;

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

    let last_block_number_recorded = cache
        .read_write_to_block_numbers(BlockNumberFields::ProactiveRefresh, latest_block_number)?;

    // prevents multiple repeated messages being sent
    if last_block_number_recorded >= latest_block_number {
        return Err(ProtocolErr::RepeatedData);
    }
    Ok(())
}

pub async fn get_channels(
    state: &ListenerState,
    converted_validator_info: Vec<ValidatorInfo>,
    account_id: SubxtAccountId32,
    session_id: &SessionId,
    signer: &PairSigner,
    x25519_secret_key: &StaticSecret,
) -> Result<Channels, ProtocolErr> {
    // subscribe to all other participating parties. Listener waits for other subscribers.
    let (rx_ready, rx_from_others, listener) =
        Listener::new(converted_validator_info.clone(), &account_id);
    state
        .listeners
        .lock()
        .map_err(|_| ProtocolErr::SessionError("Error getting lock".to_string()))?
        .insert(session_id.clone(), listener);

    open_protocol_connections(
        &converted_validator_info,
        session_id,
        signer.signer(),
        state,
        x25519_secret_key,
    )
    .await?;

    match timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await {
        Ok(ready) => {
            let broadcast_out = ready??;
            Ok(Channels(broadcast_out, rx_from_others))
        },
        Err(e) => {
            let unsubscribed_peers = state.unsubscribed_peers(session_id).map_err(|_| {
                ProtocolErr::SessionError(format!(
                    "Unable to get unsubscribed peers for `SessionId` {session_id:?}",
                ))
            })?;
            Err(ProtocolErr::Timeout { source: e, inactive_peers: unsubscribed_peers })
        },
    }
}
