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
        launch::{FORBIDDEN_KEYS, LATEST_BLOCK_NUMBER_RESHARE},
        substrate::{get_stash_address, get_validators_info, query_chain, submit_transaction},
    },
    signing_client::{api::get_channels, ProtocolErr},
    validator::errors::ValidatorErr,
    AppState,
};
use axum::{body::Bytes, extract::State, http::StatusCode};
use entropy_kvdb::kv_manager::{helpers::serialize as key_serialize, KvManager};
pub use entropy_protocol::{
    decode_verifying_key,
    errors::ProtocolExecutionErr,
    execute_protocol::{execute_protocol_generic, execute_reshare, Channels, PairWrapper},
    KeyParams, KeyShareWithAuxInfo, Listener, PartyId, SessionId, ValidatorInfo,
};
use entropy_shared::{OcwMessageReshare, NETWORK_PARENT_KEY, NEXT_NETWORK_PARENT_KEY};
use parity_scale_codec::{Decode, Encode};
use sp_core::Pair;
use std::{collections::BTreeSet, str::FromStr};
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner, utils::AccountId32,
    OnlineClient,
};
use synedrion::{KeyResharingInputs, NewHolder, OldHolder};

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

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    validate_new_reshare(&api, &rpc, &data, &app_state.kv_store).await?;

    let next_signers_query = entropy::storage().staking_extension().next_signers();
    let next_signers = query_chain(&api, &rpc, next_signers_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Error getting next signers"))?
        .next_signers;

    let validators_info = get_validators_info(&api, &rpc, next_signers)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;

    let (signer, x25519_secret_key) = get_signer_and_x25519_secret(&app_state.kv_store)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;

    let verifying_key_query = entropy::storage().staking_extension().jump_start_progress();
    let parent_key_details = query_chain(&api, &rpc, verifying_key_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Parent verifying key error"))?;

    let verifying_key = parent_key_details
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

    let is_proper_signer = validators_info
        .iter()
        .any(|validator_info| validator_info.tss_account == *signer.account_id());

    if !is_proper_signer {
        return Ok(StatusCode::MISDIRECTED_REQUEST);
    }

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

    let pruned_old_holders =
        prune_old_holders(&api, &rpc, data.new_signer, validators_info.clone()).await?;

    let old_holders: BTreeSet<PartyId> =
        pruned_old_holders.into_iter().map(|x| PartyId::new(x.tss_account)).collect();

    let new_holder = NewHolder {
        verifying_key: decoded_verifying_key,
        old_threshold: parent_key_details.parent_key_threshold as usize,
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

    let channels = get_channels(
        &app_state.listener_state,
        converted_validator_info,
        account_id,
        &session_id,
        &signer,
        &x25519_secret_key,
    )
    .await?;

    let (new_key_share, aux_info) =
        execute_reshare(session_id.clone(), channels, signer.signer(), inputs, None).await?;

    let serialized_key_share = key_serialize(&(new_key_share, aux_info))
        .map_err(|_| ProtocolErr::KvSerialize("Kv Serialize Error".to_string()))?;
    let next_network_parent_key = hex::encode(NEXT_NETWORK_PARENT_KEY);

    if app_state.kv_store.kv().exists(&next_network_parent_key).await? {
        app_state.kv_store.kv().delete(&next_network_parent_key).await?
    };

    let reservation = app_state.kv_store.kv().reserve_key(next_network_parent_key).await?;
    app_state.kv_store.kv().put(reservation, serialized_key_share.clone()).await?;

    // TODO: Error handling really complex needs to be thought about.
    confirm_key_reshare(&api, &rpc, &signer).await?;
    Ok(StatusCode::OK)
}

// HTTP POST endpoint called by the off-chain worker (propagation pallet) after  network reshare.
///
/// This roatates network key.
#[tracing::instrument(skip_all)]
pub async fn rotate_network_key(
    State(app_state): State<AppState>,
) -> Result<StatusCode, ValidatorErr> {
    // validate from chain
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    validate_rotate_network_key(&api, &rpc).await?;

    let (signer, _) = get_signer_and_x25519_secret(&app_state.kv_store)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;

    let signers_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(&api, &rpc, signers_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Error getting signers"))?;

    let validators_info = get_validators_info(&api, &rpc, signers)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;

    let is_proper_signer = is_signer_or_delete_parent_key(
        signer.account_id(),
        validators_info.clone(),
        &app_state.kv_store,
    )
    .await?;

    if !is_proper_signer {
        return Ok(StatusCode::MISDIRECTED_REQUEST);
    }

    let network_parent_key_heading = hex::encode(NETWORK_PARENT_KEY);
    let next_network_parent_key_heading = hex::encode(NEXT_NETWORK_PARENT_KEY);

    let new_parent_key = app_state.kv_store.kv().get(&next_network_parent_key_heading).await?;

    if app_state.kv_store.kv().exists(&network_parent_key_heading).await? {
        app_state.kv_store.kv().delete(&network_parent_key_heading).await?;
    };

    app_state.kv_store.kv().delete(&next_network_parent_key_heading).await?;

    let reservation = app_state.kv_store.kv().reserve_key(network_parent_key_heading).await?;
    app_state.kv_store.kv().put(reservation, new_parent_key).await?;
    Ok(StatusCode::OK)
}

// Validates new reshare endpoint
/// Checks the chain for validity of data and block number of data matches current block
pub async fn validate_new_reshare(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    chain_data: &OcwMessageReshare,
    kv_manager: &KvManager,
) -> Result<(), ValidatorErr> {
    let last_block_number_recorded = kv_manager.kv().get(LATEST_BLOCK_NUMBER_RESHARE).await?;
    if u32::from_be_bytes(
        last_block_number_recorded
            .try_into()
            .map_err(|_| ValidatorErr::Conversion("Block number conversion"))?,
    ) >= chain_data.block_number
    {
        return Err(ValidatorErr::RepeatedData);
    }

    let latest_block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Failed to get block number".to_string()))?
        .number;

    // we subtract 1 as the message info is coming from the previous block
    if latest_block_number.saturating_sub(1) != chain_data.block_number {
        return Err(ValidatorErr::StaleData);
    }

    let reshare_data_info_query = entropy::storage().staking_extension().reshare_data();
    let reshare_data = query_chain(api, rpc, reshare_data_info_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Not Currently in a reshare"))?;

    if reshare_data.new_signer != chain_data.new_signer
        || chain_data.block_number != reshare_data.block_number
    {
        return Err(ValidatorErr::InvalidData);
    }
    kv_manager.kv().delete(LATEST_BLOCK_NUMBER_RESHARE).await?;
    let reservation = kv_manager.kv().reserve_key(LATEST_BLOCK_NUMBER_RESHARE.to_string()).await?;
    kv_manager.kv().put(reservation, chain_data.block_number.to_be_bytes().to_vec()).await?;

    Ok(())
}

/// Validates rotate_network_key
/// Checks the chain that the reshare was completed recently
/// We only care that this happens after a reshare so we just check that message isn't stale
pub async fn validate_rotate_network_key(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<(), ValidatorErr> {
    let latest_block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Failed to get block number".to_string()))?
        .number;

    let rotate_keyshares_info_query = entropy::storage().staking_extension().rotate_keyshares();
    let rotate_keyshare_block = query_chain(api, rpc, rotate_keyshares_info_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Rotate Keyshare not in progress"))?;

    if latest_block_number > rotate_keyshare_block {
        return Err(ValidatorErr::StaleData);
    }

    Ok(())
}
/// Confirms that a validator has succefully reshared.
pub async fn confirm_key_reshare(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(), ValidatorErr> {
    // TODO error handling + return error
    // TODO fire and forget, or wait for in block maybe Ddos error
    // TODO: Understand this better, potentially use sign_and_submit_default
    // or other method under sign_and_*
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| ValidatorErr::OptionUnwrapError("Error getting block hash".to_string()))?;

    let nonce_call = entropy::apis().account_nonce_api().account_nonce(signer.account_id().clone());
    let nonce = api.runtime_api().at(block_hash).call(nonce_call).await?;

    let confirm_key_reshare_request = entropy::tx().staking_extension().confirm_key_reshare();
    submit_transaction(api, rpc, signer, &confirm_key_reshare_request, Some(nonce)).await?;
    Ok(())
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

/// Filters out new signer from next signers to get old holders
pub async fn prune_old_holders(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    new_signer: Vec<u8>,
    validators_info: Vec<ValidatorInfo>,
) -> Result<Vec<ValidatorInfo>, ValidatorErr> {
    Ok(if !new_signer.is_empty() {
        let address_slice: &[u8; 32] = &new_signer.clone().try_into().unwrap();
        let new_signer_address = AccountId32(*address_slice);
        let new_signer_info = &get_validators_info(api, rpc, vec![new_signer_address])
            .await
            .map_err(|e| ValidatorErr::UserError(e.to_string()))?[0];
        validators_info
            .iter()
            .filter(|x| x.tss_account != new_signer_info.tss_account)
            .cloned()
            .collect()
    } else {
        validators_info.clone()
    })
}

/// Checks if TSS is a proper signer and if isn't deletes their parent key if they have one
pub async fn is_signer_or_delete_parent_key(
    account_id: &AccountId32,
    validators_info: Vec<ValidatorInfo>,
    kv_manager: &KvManager,
) -> Result<bool, ValidatorErr> {
    let is_proper_signer =
        validators_info.iter().any(|validator_info| validator_info.tss_account == *account_id);
    if is_proper_signer {
        Ok(true)
    } else {
        // delete old keyshare if has it and not next_signer
        let network_key = hex::encode(NETWORK_PARENT_KEY);
        if kv_manager.kv().exists(&network_key).await? {
            kv_manager.kv().delete(&network_key).await?
        }
        Ok(false)
    }
}
