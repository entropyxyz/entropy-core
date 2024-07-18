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
use entropy_shared::OcwMessageReshare;
use parity_scale_codec::Decode;
use std::str::FromStr;
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, OnlineClient};

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
        .ok_or_else(|| ValidatorErr::ChainFetch("Max instructions per program error"))?;

    let next_signers_query = entropy::storage().staking_extension().signers();
    let next_signers = query_chain(&api, &rpc, next_signers_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Max instructions per program error"))?;

    let validators_info = get_validators_info(&api, &rpc, next_signers).await.unwrap();
    dbg!(validators_info);
    let (signer, x25519_secret_key) =
        get_signer_and_x25519_secret(&app_state.kv_store).await.unwrap();
    // .map_err(|e| ProtocolErr::UserError(e.to_string()))?;
    // let verifying_key_query = entropy::storage().registry().jump_start_progress();
    // let verifying_key =
    //     query_chain(&api, &rpc, verifying_key_query, None).await?.unwrap().verifying_key;

    // let is_in_current_signer = validators_info
    //         .iter()
    //         .any(|validator_info| validator_info.tss_account == validator_address.0.to_vec());
    // .ok_or_else(|| ValidatorErr::ChainFetch("Max instructions per program error"))?;
    // dbg!(verifying_key);
    // get old key if have it
    // let old_holder = None;
    // let new_holder = None;

    // need a network verifying key
    // let inputs = KeyResharingInputs {
    //     old_holder: Some(OldHolder { key_share: old_key }),
    //     new_holder: Some(NewHolder {
    //         verifying_key,
    //         old_threshold: party_ids.len(),
    //         old_holders: party_ids.clone(),
    //     }),
    //     new_holders: party_ids.clone(),
    //     new_threshold: threshold,
    // };
    // let session =
    //     make_key_resharing_session(&mut OsRng, &session_id_hash, pair, &party_ids, &inputs)
    //         .map_err(ProtocolExecutionErr::SessionCreation)?;

    // let new_key_share = execute_protocol_generic(chans, session, session_id_hash).await?.0;

    // new_key_share.ok_or(ProtocolExecutionErr::NoOutputFromReshareProtocol)
    // validate message came from chain (check reshare block # against current block number)
    // get next signers see if I am one
    // If so do reshare call confirm_reshare (delete key when done)
    // If not terminate
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
