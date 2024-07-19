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

use crate::{
    chain_api::{
        entropy::{self},
        get_api, get_rpc, EntropyConfig,
    },
    get_signer_and_x25519_secret,
    helpers::{
        launch::FORBIDDEN_KEYS,
        substrate::{get_validators_info, query_chain},
        user::check_in_registration_group,
    },
    signing_client::{
        protocol_transport::{handle_socket, open_protocol_connections},
        ListenerState, ProtocolErr,
    },
    validator::errors::ValidatorErr,
    AppState,
};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
pub use entropy_protocol::{
    decode_verifying_key,
    errors::ProtocolExecutionErr,
    execute_protocol::{execute_protocol_generic, Channels, PairWrapper},
    KeyParams, Listener, PartyId, SessionId, ValidatorInfo,
};
use entropy_shared::{OcwMessageReshare, SETUP_TIMEOUT_SECONDS};
use parity_scale_codec::Decode;
use rand_core::OsRng;
use sp_core::Pair;
use std::{str::FromStr, time::Duration};
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, OnlineClient};
use synedrion::{make_key_resharing_session, KeyResharingInputs, NewHolder, OldHolder};
use tokio::time::timeout;

/// HTTP POST endpoint called by the off-chain worker (propagation pallet) during user registration.
///
/// The HTTP request takes a Parity SCALE encoded [OcwMessageDkg] which indicates which validators
/// are in the validator group.
///
/// This will trigger the Distributed Key Generation (DKG) process.
#[tracing::instrument(skip_all)]
pub async fn new_reshare(
    State(app_state): State<AppState>,
    encoded_data: Bytes,
) -> Result<StatusCode, ValidatorErr> {
    let data = OcwMessageReshare::decode(&mut encoded_data.as_ref()).unwrap();

    // get block number from encoded data
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    let signers_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(&api, &rpc, signers_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Error getting signers"))?;

    let next_signers_query = entropy::storage().staking_extension().signers();
    let next_signers = query_chain(&api, &rpc, next_signers_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Error getting next signers"))?;

    let validators_info = get_validators_info(&api, &rpc, next_signers).await.unwrap();
    let (signer, x25519_secret_key) =
        get_signer_and_x25519_secret(&app_state.kv_store).await.unwrap();
    // .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    let verifying_key_query = entropy::storage().registry().jump_start_progress();
    let verifying_key =
        query_chain(&api, &rpc, verifying_key_query, None).await?.unwrap().verifying_key.unwrap().0;
    let decoded_verifying_key =
        decode_verifying_key(&verifying_key.clone().try_into().unwrap()).unwrap();

    let is_proper_signer = &validators_info
        .iter()
        .any(|validator_info| validator_info.tss_account == *signer.account_id());
    dbg!(is_proper_signer);
    if !is_proper_signer {
        return Ok(StatusCode::MISDIRECTED_REQUEST);
    }
    // dbg!(verifying_key);
    // get old key if have it
    let old_holder: Option<OldHolder<KeyParams, PartyId>> = None;
    let mut party_ids: Vec<PartyId> =
        validators_info.iter().cloned().map(|x| PartyId::new(x.tss_account)).collect();
    party_ids.sort();
    let new_holder = NewHolder {
        verifying_key: decoded_verifying_key,
        old_threshold: party_ids.len(),
        old_holders: party_ids.clone(),
    };
    // need a network verifying key
    let inputs = KeyResharingInputs {
        old_holder,
        new_holder: Some(new_holder),
        // todo get from chain
        new_holders: party_ids.clone(),
        new_threshold: 2,
    };
    // TODO rename to Reshare
    let session_id = SessionId::ProactiveRefresh { verifying_key, block_number: data.block_number };
    let account_id = AccountId32(signer.signer().public().0);
    let session_id_hash = session_id.blake2(None).unwrap();
    let pair = PairWrapper(signer.signer().clone());

    let mut converted_validator_info = vec![];
    let mut tss_accounts = vec![];
    for validator_info in validators_info {
        let validator_info = ValidatorInfo {
            x25519_public_key: validator_info.x25519_public_key,
            ip_address: validator_info.ip_address,
            tss_account: validator_info.tss_account.clone(),
        };
        converted_validator_info.push(validator_info.clone());
        tss_accounts.push(validator_info.tss_account.clone());
    }

    let (rx_ready, rx_from_others, listener) =
        Listener::new(converted_validator_info.clone(), &account_id);
    app_state.listener_state
    .listeners
    .lock()
    .unwrap()
    // .map_err(|_| ProtocolErr::SessionError("Error getting lock".to_string()))?
    .insert(session_id.clone(), listener);

    open_protocol_connections(
        &converted_validator_info,
        &session_id,
        signer.signer(),
        &app_state.listener_state,
        &x25519_secret_key,
    )
    .await
    .unwrap();

    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await.unwrap();
        let broadcast_out = ready.unwrap().unwrap();
        Channels(broadcast_out, rx_from_others)
    };

    let session =
        make_key_resharing_session(&mut OsRng, &session_id_hash, pair, &party_ids, &inputs)
            .unwrap();
    // .map_err(ProtocolExecutionErr::SessionCreation)?;

    let new_key_share =
        execute_protocol_generic(channels, session, session_id_hash).await.unwrap().0.unwrap();
    // new_key_share.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)

    // new_key_share.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)
    // validate message came from chain (check reshare block # against current block number)
    // If so do reshare call confirm_reshare (delete key when done)
    Ok(StatusCode::OK)
}

/// Validation for if an account can cover tx fees for a tx
pub async fn check_balance_for_fees(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    address: String,
    min_balance: u128,
) -> Result<bool, ValidatorErr> {
    let balance_query = entropy::storage()
        .system()
        .account(AccountId32::from_str(&address).expect("Error converting address"));
    let account_info = query_chain(api, rpc, balance_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Account does not exist, add balance"))?;
    let balance = account_info.data.free;
    let mut is_min_balance = false;
    if balance >= min_balance {
        is_min_balance = true
    };
    Ok(is_min_balance)
}

pub fn check_forbidden_key(key: &str) -> Result<(), ValidatorErr> {
    let forbidden = FORBIDDEN_KEYS.contains(&key);
    if forbidden {
        return Err(ValidatorErr::ForbiddenKey);
    }
    Ok(())
}
