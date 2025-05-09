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
    helpers::{
        app_state::{BlockNumberFields, Cache},
        substrate::{get_stash_address, get_validators_info, query_chain, submit_transaction},
    },
    signing_client::api::get_channels,
    validator::errors::ValidatorErr,
    AppState,
};
use axum::{body::Bytes, extract::State, http::StatusCode};
pub use entropy_protocol::{
    decode_verifying_key,
    errors::ProtocolExecutionErr,
    execute_protocol::{execute_protocol_generic, execute_reshare, Channels, PairWrapper},
    KeyParams, KeyShareWithAuxInfo, Listener, PartyId, SessionId, ValidatorInfo,
};
use entropy_shared::OcwMessageReshare;
use parity_scale_codec::{Decode, Encode};
use std::{collections::BTreeSet, str::FromStr};
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner, utils::AccountId32,
    OnlineClient,
};
use synedrion::{KeyResharing, NewHolder, OldHolder};

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
    if !app_state.cache.is_ready() {
        return Err(ValidatorErr::NotReady);
    }

    let data = OcwMessageReshare::decode(&mut encoded_data.as_ref())?;

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    validate_new_reshare(&api, &rpc, &data, &app_state.cache).await?;

    let next_signers_query = entropy::storage().staking_extension().next_signers();
    let next_signers = query_chain(&api, &rpc, next_signers_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Error getting next signers"))?
        .next_signers;
    let validators_info = get_validators_info(&api, &rpc, next_signers)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;

    let is_proper_signer = validators_info
        .iter()
        .any(|validator_info| validator_info.tss_account == app_state.subxt_account_id());

    if !is_proper_signer {
        return Ok(StatusCode::MISDIRECTED_REQUEST);
    }

    let app_state = app_state.clone();
    // Do reshare in a separate task so we can already respond
    tokio::spawn(async move {
        if let Err(err) = do_reshare(&api, &rpc, data, validators_info, app_state).await {
            tracing::error!("Error during reshare: {err}");
        }
    });
    Ok(StatusCode::OK)
}

async fn do_reshare(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    data: OcwMessageReshare,
    validators_info: Vec<ValidatorInfo>,
    app_state: AppState,
) -> Result<(), ValidatorErr> {
    let verifying_key_query = entropy::storage().staking_extension().jump_start_progress();
    let parent_key_details = query_chain(api, rpc, verifying_key_query, None)
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
    let my_stash_address = get_stash_address(api, rpc, &app_state.subxt_account_id())
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;

    let old_holder: Option<OldHolder<KeyParams, PartyId>> =
        if data.new_signers.contains(&my_stash_address.encode()) {
            None
        } else {
            let key_share = app_state.network_keyshare()?.unwrap();
            Some(OldHolder { key_share: key_share.0 })
        };

    // new_holders -> From chain next_signers (old_holders (currently forced to be t) + new_holders)
    // also acts as verifiers as is everyone in the party
    let new_holders: BTreeSet<PartyId> =
        validators_info.iter().cloned().map(|x| PartyId::new(x.tss_account)).collect();
    // old holders -> next_signers - new_signers (will be at least t)
    let old_holders =
        &prune_old_holders(api, rpc, data.new_signers, validators_info.clone()).await?;
    let old_holders: BTreeSet<PartyId> =
        old_holders.iter().map(|x| PartyId::new(x.tss_account.clone())).collect();

    let new_holder = NewHolder {
        verifying_key: decoded_verifying_key,
        old_threshold: parent_key_details.parent_key_threshold as usize,
        old_holders,
    };
    let key_info_query = entropy::storage().parameters().signers_info();
    let threshold = query_chain(api, rpc, key_info_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Failed to get signers info"))?
        .threshold;

    let inputs =
        KeyResharing::new(old_holder, Some(new_holder), new_holders.clone(), threshold as usize);

    let session_id = SessionId::Reshare { verifying_key, block_number: data.block_number };
    let account_id = app_state.subxt_account_id();

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
        &app_state.cache.listener_state,
        converted_validator_info,
        account_id,
        &session_id,
        &app_state.signer(),
        &app_state.x25519_secret,
    )
    .await?;
    let (new_key_share, aux_info) =
        execute_reshare(session_id.clone(), channels, &app_state.pair, inputs, &new_holders, None)
            .await?;

    app_state.update_next_network_keyshare(Some((new_key_share, aux_info))).await?;

    // TODO: Error handling really complex needs to be thought about.
    confirm_key_reshare(api, rpc, &app_state.signer()).await?;
    Ok(())
}

/// HTTP POST endpoint called by the off-chain worker (propagation pallet) after a network key reshare.
///
/// This rotates network key, deleting the previous network parent key.
#[tracing::instrument(skip_all)]
pub async fn rotate_network_key(
    State(app_state): State<AppState>,
) -> Result<StatusCode, ValidatorErr> {
    if !app_state.cache.is_ready() {
        return Err(ValidatorErr::NotReady);
    }

    // validate from chain
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    validate_rotate_network_key(&api, &rpc).await?;

    let signers_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(&api, &rpc, signers_query, None)
        .await?
        .ok_or_else(|| ValidatorErr::ChainFetch("Error getting signers"))?;

    let validators_info = get_validators_info(&api, &rpc, signers)
        .await
        .map_err(|e| ValidatorErr::UserError(e.to_string()))?;

    let is_proper_signer = is_signer_or_delete_parent_key(
        &app_state.subxt_account_id(),
        validators_info.clone(),
        &app_state,
    )
    .await?;

    if !is_proper_signer {
        return Ok(StatusCode::MISDIRECTED_REQUEST);
    }
    tracing::info!("Rotating network key");
    app_state.rotate_keyshare().await?;

    Ok(StatusCode::OK)
}

/// Validates new reshare endpoint
/// Checks the chain for validity of data and block number of data matches current block
pub async fn validate_new_reshare(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    chain_data: &OcwMessageReshare,
    cache: &Cache,
) -> Result<(), ValidatorErr> {
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

    if chain_data.block_number != reshare_data.block_number
        || chain_data.new_signers != reshare_data.new_signers
    {
        return Err(ValidatorErr::InvalidData);
    }

    let last_block_number_recorded =
        cache.read_write_to_block_numbers(BlockNumberFields::Reshare, chain_data.block_number)?;
    if last_block_number_recorded >= chain_data.block_number {
        return Err(ValidatorErr::RepeatedData);
    }

    Ok(())
}

/// Checks the chain that the reshare was completed recently.
///
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

/// Filters out new signer from next signers to get old holders
pub async fn prune_old_holders(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    new_signers: Vec<Vec<u8>>,
    validators_info: Vec<ValidatorInfo>,
) -> Result<Vec<ValidatorInfo>, ValidatorErr> {
    Ok(if !new_signers.is_empty() {
        let mut filtered_validators_info = vec![];
        for new_signer in new_signers {
            let address_slice: &[u8; 32] = &new_signer.clone().try_into().unwrap();
            let new_signer_address = AccountId32(*address_slice);
            let new_signer_info = &get_validators_info(api, rpc, vec![new_signer_address])
                .await
                .map_err(|e| ValidatorErr::UserError(e.to_string()))?[0];
            filtered_validators_info = validators_info
                .iter()
                .filter(|x| x.tss_account != new_signer_info.tss_account)
                .cloned()
                .collect::<Vec<_>>();
        }
        filtered_validators_info
    } else {
        validators_info.clone()
    })
}

/// Checks if TSS is a proper signer and if isn't deletes their parent key if they have one
pub async fn is_signer_or_delete_parent_key(
    account_id: &AccountId32,
    validators_info: Vec<ValidatorInfo>,
    app_state: &AppState,
) -> Result<bool, ValidatorErr> {
    let is_proper_signer =
        validators_info.iter().any(|validator_info| validator_info.tss_account == *account_id);
    if is_proper_signer {
        Ok(true)
    } else {
        app_state.update_network_keyshare(None).await?;
        Ok(false)
    }
}
