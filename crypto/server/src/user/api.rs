use std::{str::FromStr, sync::Arc};

use bip39::{Language, Mnemonic};
use entropy_constraints::{
    Architecture, Error as ConstraintsError, Evaluate, Evm, GetReceiver, GetSender, Parse,
};
use axum::{
    routing::{get, post},
    http::StatusCode,
    response::IntoResponse,
    Json, Router,
	extract::State,
};
use entropy_shared::{
    types::{Acl, AclKind, Arch, Constraints},
    Message, SIGNING_PARTY_SIZE,
};
use futures::future::{join_all, FutureExt};
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KvManager,
};
use log::info;
use num::{bigint::BigInt, FromPrimitive, Num, ToPrimitive};
use parity_scale_codec::DecodeAll;
// use rocket::{
//     response::stream::EventStream,
//     serde::json::{to_string, Json},
//     Shutdown,
// };
use serde::{Deserialize, Serialize};
use subxt::{
    ext::{
        sp_core::{crypto::Ss58Codec, sr25519, Pair},
        sp_runtime::AccountId32,
    },
    tx::PairSigner,
    Config, OnlineClient,
};
use tracing::instrument;
use zeroize::Zeroize;

use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{entropy, entropy::constraints::calls::UpdateConstraints, get_api, EntropyConfig},
    helpers::{
        signing::{create_unique_tx_id, do_signing, SignatureState},
        substrate::{get_constraints, get_subgroup, is_registered},
        validator::get_signer,
    },
    signing_client::SignerState,
    validation::SignedMessage,
    Configuration, AppState
};

/// Represents an unparsed, transaction request coming from the client.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UserTransactionRequest {
    /// 'eth', etc.
    pub arch: String,
    /// ETH: RLP encoded transaction request
    pub transaction_request: String,
    pub validator_ips: Vec<parity_scale_codec::alloc::vec::Vec<u8>>,
    pub message: Message,
}
/// Represents an unparsed, transaction request coming from the client.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct GenericTransactionRequest {
    /// 'eth', etc.
    pub arch: String,
    /// ETH: RLP encoded transaction request
    pub transaction_request: String,
}

/// Called by a user to initiate the signing process for a message
///
/// Takes an encrypted [SignedMessage] containing a JSON serialized [UserTransactionRequest]
pub async fn sign_tx(
	State(app_state): State<AppState>,
    // TODO make new type with only info needed
	Json(signed_msg): Json<SignedMessage>,
) -> Result<StatusCode, UserErr> {
    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }

    let signer = get_signer(&app_state.kv_store).await?;
    let signing_address = signed_msg.account_id().to_ss58check();

    let api = get_api(&app_state.configuration.endpoint).await?;

    let signing_address_converted =
        AccountId32::from_str(&signing_address).map_err(UserErr::StringError)?;
    is_registered(&api, &signing_address_converted).await?;

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;

    let user_tx_req: UserTransactionRequest = serde_json::from_slice(&decrypted_message)?;
    let parsed_tx =
        <Evm as Architecture>::TransactionRequest::parse(user_tx_req.transaction_request.clone())?;

    let sig_hash = hex::encode(parsed_tx.sighash().as_bytes());
    let subgroup_signers = get_current_subgroup_signers(&api, &sig_hash).await?;
    check_signing_group(subgroup_signers, signer.account_id())?;
    let tx_id = create_unique_tx_id(&signing_address, &sig_hash);
    match user_tx_req.arch.as_str() {
        "evm" => {
            let message = user_tx_req.message;
            let evm_acl = get_constraints(&api, &signing_address_converted)
                .await?
                .evm_acl
                .ok_or(UserErr::Parse("No constraints found for this account."))?;

            evm_acl.eval(parsed_tx)?;

            do_signing(message.clone(), &app_state.signer_state, &app_state.kv_store, &app_state.signature_state, tx_id).await?;
        },
        _ => {
            return Err(UserErr::Parse("Unknown \"arch\". Must be one of: [\"evm\"]"));
        },
    }
    Ok(StatusCode::OK)
}

/// Submits a new transaction to the KVDB for inclusion in a threshold
/// signing scheme at a later block.
///
/// Maps a tx hash -> unsigned transaction in the kvdb.
#[axum_macros::debug_handler]
pub async fn store_tx(
	State(app_state): State<AppState>,
	Json(signed_msg): Json<SignedMessage>,
) -> Result<StatusCode, UserErr> {
    // Verifies the message contains a valid sr25519 signature from the sender.
    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(&app_state.kv_store).await?;
    let signing_address = signed_msg.account_id().to_ss58check();

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;
    let generic_tx_req: GenericTransactionRequest = serde_json::from_slice(&decrypted_message)?;
    match generic_tx_req.arch.as_str() {
        "evm" => {
            let api = get_api(&app_state.configuration.endpoint);
            let parsed_tx = <Evm as Architecture>::TransactionRequest::parse(
                generic_tx_req.transaction_request.clone(),
            )?;

            let sig_hash = hex::encode(parsed_tx.sighash().as_bytes());
            let tx_id = create_unique_tx_id(&signing_address, &sig_hash);
            // check if user submitted tx to chain already
            let message_json = app_state.kv_store.kv().get(&tx_id).await?;
            // parse their transaction request
            let message: Message = serde_json::from_str(&String::from_utf8(message_json)?)?;
            let signing_address_converted =
                AccountId32::from_str(&signing_address).map_err(UserErr::StringError)?;

            let substrate_api = api.await?;
            let evm_acl = get_constraints(&substrate_api, &signing_address_converted)
                .await?
                .evm_acl
                .ok_or(UserErr::Parse("No constraints found for this account."))?;

            evm_acl.eval(parsed_tx)?;
            app_state.kv_store.kv().delete(&tx_id).await?;
            do_signing(message, &app_state.signer_state, &app_state.kv_store, &app_state.signature_state, tx_id).await?;
        },
        _ => {
            return Err(UserErr::Parse("Unknown \"arch\". Must be one of: [\"evm\"]"));
        },
    }
    Ok(StatusCode::OK)
}

/// HTTP POST endoint called by the user when registering.
///
/// This adds a new Keyshare to this node's set of known Keyshares and stores the it in the [kvdb].
///
/// The http request takes a [SignedMessage] containing a bincode-encoded
/// [KeyShare](synedrion::KeyShare).
pub async fn new_user(
    State(app_state): State<AppState>,
	Json(signed_msg): Json<SignedMessage>,
) -> Result<StatusCode, UserErr> {
    let api = get_api(&app_state.configuration.endpoint).await?;
    // Verifies the message contains a valid sr25519 signature from the sender.
    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(&app_state.kv_store).await?;
    // Checks if the user has registered onchain first.
    let key = signed_msg.account_id();
    let is_swapping = register_info(&api, &key).await?;

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;
    // store new user data in kvdb or deletes and replaces it if swapping
    let subgroup = get_subgroup(&api, &signer)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    if is_swapping {
        app_state.kv_store.kv().delete(&key.to_string()).await?;
    }
    let reservation = app_state.kv_store.kv().reserve_key(key.to_string()).await?;
    app_state.kv_store.kv().put(reservation, decrypted_message).await?;
    // TODO: Error handling really complex needs to be thought about.
    confirm_registered(&api, key, subgroup, &signer).await?;
    Ok(StatusCode::OK)
}
/// Returns wether an account is registering or swapping. If it is not, it returns error
pub async fn register_info(
    api: &OnlineClient<EntropyConfig>,
    who: &AccountId32,
) -> Result<bool, UserErr> {
    let registering_info_query = entropy::storage().relayer().registering(who);
    let register_info = api
        .storage()
        .fetch(&registering_info_query, None)
        .await?
        .ok_or_else(|| UserErr::NotRegistering("Register Onchain first"))?;
    if !register_info.is_swapping && !register_info.is_registering {
        return Err(UserErr::NotRegistering("Declare swap Onchain first"));
    }

    Ok(register_info.is_swapping)
}

/// Confirms that a address has finished registering on chain.
pub async fn confirm_registered(
    api: &OnlineClient<EntropyConfig>,
    who: AccountId32,
    subgroup: u8,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(), subxt::error::Error> {
    // TODO error handling + return error
    // TODO fire and forget, or wait for in block maybe Ddos error
    // TODO: Understand this better, potentially use sign_and_submit_default
    // or other method under sign_and_*
    let registration_tx = entropy::tx().relayer().confirm_register(who, subgroup);
    let _ = api
        .tx()
        .sign_and_submit_then_watch_default(&registration_tx, signer)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}
/// Gets the current signing committee
/// The signing committee is composed as the validators at the index into each subgroup
/// Where the index is computed as the user's sighash as an integer modulo the number of subgroups
pub async fn get_current_subgroup_signers(
    api: &OnlineClient<EntropyConfig>,
    sig_hash: &str,
) -> Result<Vec<AccountId32>, UserErr> {
    let mut subgroup_signers = vec![];
    let number = Arc::new(BigInt::from_str_radix(sig_hash, 16)?);
    let futures = (0..SIGNING_PARTY_SIZE)
        .map(|i| {
            let owned_number = Arc::clone(&number);
            async move {
                let subgroup_info_query =
                    entropy::storage().staking_extension().signing_groups(i as u8);
                let subgroup_info = api
                    .storage()
                    .fetch(&subgroup_info_query, None)
                    .await?
                    .ok_or(UserErr::SubgroupError("Subgroup Fetch Error"))?;

                let index_of_signer_big = &*owned_number % subgroup_info.len();
                let index_of_signer =
                    index_of_signer_big.to_usize().ok_or(UserErr::Usize("Usize error"))?;

                let threshold_address_query = entropy::storage()
                    .staking_extension()
                    .threshold_servers(subgroup_info[index_of_signer].clone());
                let threshold_address = api
                    .storage()
                    .fetch(&threshold_address_query, None)
                    .await?
                    .ok_or(UserErr::SubgroupError("Stash Fetch Error"))?
                    .tss_account;

                Ok::<_, UserErr>(threshold_address)
            }
        })
        .collect::<Vec<_>>();
    let results = join_all(futures).await;
    for result in results.into_iter() {
        subgroup_signers.push(result?);
    }
    Ok(subgroup_signers)
}
/// Checks if a validator is in the current selected signing committee
pub fn check_signing_group(
    subgroup_signers: Vec<AccountId32>,
    validator_address: &AccountId32,
) -> Result<(), UserErr> {
    let is_proper_signer = subgroup_signers.contains(validator_address);
    if !is_proper_signer {
        return Err(UserErr::InvalidSigner("Invalid Signer in Signing group"));
    }
    Ok(())
}
