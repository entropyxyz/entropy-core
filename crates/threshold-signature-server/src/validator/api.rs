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
        substrate::{get_stash_address, get_validators_info, query_chain},
    },
    signing_client::{protocol_transport::open_protocol_connections, ProtocolErr},
    validator::errors::ValidatorErr,
    AppState,
};
use axum::{body::Bytes, extract::State, http::StatusCode};
use entropy_kvdb::kv_manager::helpers::serialize as key_serialize;
pub use entropy_protocol::{
    decode_verifying_key,
    errors::ProtocolExecutionErr,
    execute_protocol::{execute_protocol_generic, Channels, PairWrapper},
    KeyParams, KeyShareWithAuxInfo, Listener, PartyId, SessionId, ValidatorInfo,
};
use entropy_shared::{OcwMessageReshare, NETWORK_PARENT_KEY, SETUP_TIMEOUT_SECONDS};
use parity_scale_codec::{Decode, Encode};
use rand_core::OsRng;
use sp_core::Pair;
use std::{collections::BTreeSet, str::FromStr, time::Duration};
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, OnlineClient};
use synedrion::{
    make_key_resharing_session, sessions::SessionId as SynedrionSessionId, KeyResharingInputs,
    NewHolder, OldHolder,
};
use tokio::time::timeout;

/// HTTP POST endpoint called by the off-chain worker (propagation pallet) during network reshare.
///
/// The HTTP request takes a Parity SCALE encoded [OcwMessageReshare] which indicates which validator is joining
///
/// This will trigger the key reshare process.
#[tracing::instrument(skip_all)]
pub async fn new_reshare(
    State(app_state): State<AppState>,
    encoded_data: Bytes,
) -> Result<StatusCode, ValidatorErr> {
    let data = OcwMessageReshare::decode(&mut encoded_data.as_ref())?;
    // TODO: validate message came from chain (check reshare block # against current block number) see #941

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

    let validators_info = get_validators_info(&api, &rpc, next_signers)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;
    let (signer, x25519_secret_key) = get_signer_and_x25519_secret(&app_state.kv_store)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;

    let verifying_key_query = entropy::storage().registry().jump_start_progress();
    let verifying_key = query_chain(&api, &rpc, verifying_key_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Parent verifying key error"))?
        .verifying_key
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Failed to get verifying key".to_string()))?
        .0;

    let decoded_verifying_key = decode_verifying_key(
        &verifying_key
            .clone()
            .try_into()
            .map_err(|_| ValidatorErr::Conversion("Verifying key conversion"))?,
    )
    .map_err(|e| ValidatorErr::VerifyingKeyError(e.to_string()))?;

    let is_proper_signer = &validators_info
        .iter()
        .any(|validator_info| validator_info.tss_account == *signer.account_id());

    if !is_proper_signer {
        return Ok(StatusCode::MISDIRECTED_REQUEST);
    }
    // get old key if have it
    let my_stash_address = get_stash_address(&api, &rpc, signer.account_id())
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;
    let old_holder: Option<OldHolder<KeyParams, PartyId>> =
        if data.new_signer == my_stash_address.encode() {
            None
        } else {
            let kvdb_result = app_state.kv_store.kv().get(&hex::encode(NETWORK_PARENT_KEY)).await?;
            let key_share: KeyShareWithAuxInfo =
                entropy_kvdb::kv_manager::helpers::deserialize(&kvdb_result)
                    .ok_or_else(|| ValidatorErr::KvDeserialize("Failed to load KeyShare".into()))?;
            Some(OldHolder { key_share: key_share.0 })
        };
    let party_ids: BTreeSet<PartyId> =
        validators_info.iter().cloned().map(|x| PartyId::new(x.tss_account)).collect();

    let old_holders_info = get_validators_info(&api, &rpc, signers)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;
    let old_holders: BTreeSet<PartyId> =
        old_holders_info.iter().cloned().map(|x| PartyId::new(x.tss_account)).collect();

    let new_holder = NewHolder {
        verifying_key: decoded_verifying_key,
        // TODO: get from chain see #941
        old_threshold: party_ids.len(),
        old_holders,
    };
    let key_info_query = entropy::storage().parameters().signers_info();
    let threshold = query_chain(&api, &rpc, key_info_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Failed to get signers info"))?
        .threshold;

    let inputs = KeyResharingInputs {
        old_holder,
        new_holder: Some(new_holder),
        new_holders: party_ids.clone(),
        new_threshold: threshold as usize,
    };

    let session_id = SessionId::Reshare { verifying_key, block_number: data.block_number };
    let account_id = AccountId32(signer.signer().public().0);
    let session_id_hash = session_id.blake2(None)?;
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
    app_state
        .listener_state
        .listeners
        .lock()
        .map_err(|_| ValidatorErr::SessionError("Error getting lock".to_string()))?
        .insert(session_id.clone(), listener);

    open_protocol_connections(
        &converted_validator_info,
        &session_id,
        signer.signer(),
        &app_state.listener_state,
        &x25519_secret_key,
    )
    .await?;

    let channels = {
        let ready = timeout(Duration::from_secs(SETUP_TIMEOUT_SECONDS), rx_ready).await?;
        let broadcast_out = ready??;
        Channels(broadcast_out, rx_from_others)
    };

    let session = make_key_resharing_session(
        &mut OsRng,
        SynedrionSessionId::from_seed(session_id_hash.as_slice()),
        pair,
        &party_ids,
        inputs,
    )
    .map_err(ProtocolExecutionErr::SessionCreation)?;

    let new_key_share = execute_protocol_generic(channels, session, session_id_hash)
        .await
        .map_err(|_| ValidatorErr::ProtocolError("Error executing protocol".to_string()))?
        .0
        .ok_or(ValidatorErr::NoOutputFromReshareProtocol)?;
    let _serialized_key_share = key_serialize(&new_key_share)
        .map_err(|_| ProtocolErr::KvSerialize("Kv Serialize Error".to_string()))?;
    // TODO: do reshare call confirm_reshare (delete key when done) see #941
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
