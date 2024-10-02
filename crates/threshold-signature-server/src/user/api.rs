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

use std::str::FromStr;

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::StatusCode,
    Json,
};
use base64::prelude::{Engine, BASE64_STANDARD};
use entropy_client::substrate::get_registered_details;
use entropy_kvdb::kv_manager::{helpers::serialize as key_serialize, KvManager};
use entropy_programs_runtime::{Config as ProgramConfig, Runtime, SignatureRequest};
use entropy_protocol::SigningSessionInfo;
use entropy_shared::{HashingAlgorithm, OcwMessageDkg, NETWORK_PARENT_KEY};
use futures::{channel::mpsc, future::join_all, StreamExt};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    ext::sp_core::{sr25519, sr25519::Signature, Pair},
    tx::PairSigner,
    utils::AccountId32 as SubxtAccountId32,
    OnlineClient,
};
use x25519_dalek::StaticSecret;

use super::UserErr;
use crate::chain_api::entropy::runtime_types::pallet_registry::pallet::RegisteredInfo;
use crate::{
    chain_api::{entropy, get_api, get_rpc, EntropyConfig},
    helpers::{
        launch::LATEST_BLOCK_NUMBER_NEW_USER,
        signing::do_signing,
        substrate::{
            get_oracle_data, get_program, get_signers_from_chain, get_validators_info, query_chain,
            submit_transaction,
        },
        user::{check_in_registration_group, compute_hash, do_dkg},
        validator::get_signer_and_x25519_secret,
    },
    validation::{check_stale, EncryptedSignedMessage},
    AppState,
};

pub use entropy_client::user::{RelayerSignatureRequest, UserSignatureRequest};
pub const REQUEST_KEY_HEADER: &str = "REQUESTS";

/// Type for validators to send user key's back and forth
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct UserRegistrationInfo {
    /// Signing request key (also kvdb key)
    pub key: String,
    /// User threshold signing key
    pub value: Vec<u8>,
    /// Is this a proactive refresh message
    pub proactive_refresh: bool,
    /// The sig_req_account to check if user is registering
    pub sig_request_address: Option<SubxtAccountId32>,
}

/// Type that gets stored for request limit checks
#[derive(Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct RequestLimitStorage {
    pub block_number: u32,
    pub request_amount: u32,
}

/// Called by a user to initiate the signing process for a message
///
/// Takes an [EncryptedSignedMessage] containing a JSON serialized [UserSignatureRequest]
///
/// Chooses signers and relays transactions to them and then results back to user
#[tracing::instrument(skip_all, fields(request_author))]
pub async fn relay_tx(
    State(app_state): State<AppState>,
    Json(encrypted_msg): Json<EncryptedSignedMessage>,
) -> Result<(StatusCode, Body), UserErr> {
    let (signer, x25519_secret) = get_signer_and_x25519_secret(&app_state.kv_store).await?;
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    // make sure is a validator and not a signer
    let validators_query = entropy::storage().session().validators();
    let validators = query_chain(&api, &rpc, validators_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Error getting validators"))?;

    let validators_info = get_validators_info(&api, &rpc, validators).await?;

    validators_info
        .iter()
        .find(|validator| validator.tss_account == *signer.account_id())
        .ok_or_else(|| UserErr::NotValidator)?;

    let (selected_signers, all_signers) = get_signers_from_chain(&api, &rpc).await?;

    let signers_info = get_validators_info(&api, &rpc, all_signers).await?;

    signers_info
        .iter()
        .find(|signer_info| signer_info.tss_account == *signer.account_id())
        .map_or(Ok(()), |_| Err(UserErr::RelayMessageSigner))?;

    let signed_message = encrypted_msg.decrypt(&x25519_secret, &[])?;

    tracing::Span::current().record("request_author", signed_message.account_id().to_string());

    let user_signature_request: UserSignatureRequest =
        serde_json::from_slice(&signed_message.message.0)?;
    let relayer_sig_req =
        RelayerSignatureRequest { user_signature_request, validators_info: selected_signers };
    let block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error Getting Block Number".to_string()))?
        .number;

    let string_verifying_key =
        hex::encode(relayer_sig_req.user_signature_request.signature_verifying_key.clone());

    let _ = pre_sign_checks(
        &api,
        &rpc,
        relayer_sig_req.user_signature_request.clone(),
        block_number,
        string_verifying_key,
    )
    .await?;

    // relay message
    let (mut response_tx, response_rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let result: Result<(), UserErr> = async {
            let client = reqwest::Client::new();
            let results = join_all(
                relayer_sig_req
                    .validators_info
                    .iter()
                    .map(|signer_info| async {
                        let signed_message = EncryptedSignedMessage::new(
                            signer.signer(),
                            serde_json::to_vec(&relayer_sig_req.clone())?,
                            &signer_info.x25519_public_key,
                            &[],
                        )?;

                        let url = format!("http://{}/user/sign_tx", signer_info.ip_address.clone());

                        let response = client
                            .post(url)
                            .header("Content-Type", "application/json")
                            .body(serde_json::to_string(&signed_message)?)
                            .send()
                            .await?;

                        Ok::<_, UserErr>(response)
                    })
                    .collect::<Vec<_>>(),
            )
            .await;

            let mut send_back = vec![];

            for result in results {
                let mut resp = result?;
                let chunk = resp
                    .chunk()
                    .await?
                    .ok_or(UserErr::OptionUnwrapError("No chunk data".to_string()))?;

                if resp.status() == 200 {
                    let signing_result: Result<(String, Signature), String> =
                        serde_json::from_slice(&chunk)?;
                    send_back.push(signing_result);
                } else {
                    send_back.push(Err(String::from_utf8(chunk.to_vec())?));
                }
            }

            if response_tx.try_send(serde_json::to_string(&send_back)?).is_err() {
                tracing::warn!("Cannot send signing protocol output - connection is closed");
            }

            Ok(())
        }
        .await;

        if let Err(e) = result {
            tracing::error!("Error in tokio::spawn task: {:?}", e);
        }
    });

    let result_stream = response_rx.map(Ok::<_, UserErr>);

    Ok((StatusCode::OK, Body::from_stream(result_stream)))
}

/// Called by a relayer to initiate the signing process for a message
///
/// Takes an [EncryptedSignedMessage] containing a JSON serialized [RelayerSignatureRequest]
#[tracing::instrument(skip_all, fields(request_author))]
pub async fn sign_tx(
    State(app_state): State<AppState>,
    Json(encrypted_msg): Json<EncryptedSignedMessage>,
) -> Result<(StatusCode, Body), UserErr> {
    let (signer, x25519_secret) = get_signer_and_x25519_secret(&app_state.kv_store).await?;

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    let signed_message = encrypted_msg.decrypt(&x25519_secret, &[])?;

    let request_author = SubxtAccountId32(*signed_message.account_id().as_ref());
    tracing::Span::current().record("request_author", signed_message.account_id().to_string());
    let validators_query = entropy::storage().session().validators();

    let validators = query_chain(&api, &rpc, validators_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Error getting signers"))?;

    let validators_info = get_validators_info(&api, &rpc, validators).await?;

    validators_info
        .iter()
        .find(|validator| validator.tss_account == request_author)
        .ok_or_else(|| UserErr::NotRelayedFromValidator)?;

    let request_limit_query = entropy::storage().parameters().request_limit();
    let request_limit = query_chain(&api, &rpc, request_limit_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Failed to get request limit"))?;

    let relayer_sig_request: RelayerSignatureRequest =
        serde_json::from_slice(&signed_message.message.0)?;

    // check validator info > threshold
    let key_info_query = entropy::storage().parameters().signers_info();
    let threshold = query_chain(&api, &rpc, key_info_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Failed to get signers info"))?
        .threshold;

    if relayer_sig_request.validators_info.len() < threshold as usize {
        return Err(UserErr::TooFewSigners);
    }
    // validators are signers
    let signer_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(&api, &rpc, signer_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Get all validators error"))?;

    let validator_exists = {
        let mut found = true;

        for validator_info in &relayer_sig_request.validators_info {
            let stash_address_query = entropy::storage()
                .staking_extension()
                .threshold_to_stash(validator_info.tss_account.clone());

            let stash_address = query_chain(&api, &rpc, stash_address_query, None)
                .await?
                .ok_or_else(|| UserErr::ChainFetch("Stash Fetch Error"))?;

            // If the stash_address is found in signers, we can stop further checking
            if !signers.contains(&stash_address) {
                found = false;
                break;
            }
        }
        found
    };

    if !validator_exists {
        return Err(UserErr::IncorrectSigner);
    }

    let string_verifying_key =
        hex::encode(relayer_sig_request.user_signature_request.signature_verifying_key.clone());
    request_limit_check(&rpc, &app_state.kv_store, string_verifying_key.clone(), request_limit)
        .await?;

    let block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error Getting Block Number".to_string()))?
        .number;

    let (mut runtime, user_details, message) = pre_sign_checks(
        &api,
        &rpc,
        relayer_sig_request.user_signature_request.clone(),
        block_number,
        string_verifying_key,
    )
    .await?;

    let message_hash = compute_hash(
        &api,
        &rpc,
        &relayer_sig_request.user_signature_request.hash,
        &mut runtime,
        &user_details.programs_data.0,
        message.as_slice(),
    )
    .await?;

    let signing_session_id = SigningSessionInfo {
        signature_verifying_key: relayer_sig_request
            .user_signature_request
            .signature_verifying_key
            .clone(),
        message_hash,
        request_author,
    };

    let derivation_path = if let Some(path) = user_details.derivation_path {
        let decoded_path = String::decode(&mut path.as_ref())?;
        let path = bip32::DerivationPath::from_str(&decoded_path)?;

        Some(path)
    } else {
        None
    };

    let (mut response_tx, response_rx) = mpsc::channel(1);

    // Do the signing protocol in another task, so we can already respond
    tokio::spawn(async move {
        let signing_protocol_output = do_signing(
            &rpc,
            relayer_sig_request,
            &app_state,
            signing_session_id,
            request_limit,
            derivation_path,
        )
        .await
        .map(|signature| {
            (
                BASE64_STANDARD.encode(signature.to_rsv_bytes()),
                signer.signer().sign(&signature.to_rsv_bytes()),
            )
        })
        .map_err(|error| error.to_string());

        // This response chunk is sent later with the result of the signing protocol
        if response_tx.try_send(serde_json::to_string(&signing_protocol_output)).is_err() {
            tracing::warn!("Cannot send signing protocol output - connection is closed")
        };
    });

    // This indicates that the signing protocol is starting successfully
    Ok((StatusCode::OK, Body::from_stream(response_rx)))
}

/// HTTP POST endpoint called by the off-chain worker (Propagation pallet) during the network
/// jumpstart.
///
/// The HTTP request takes a Parity SCALE encoded [OcwMessageDkg] which indicates which validators
/// are in the validator group.
///
/// This will trigger the Distributed Key Generation (DKG) process.
#[tracing::instrument(skip_all, fields(block_number))]
pub async fn generate_network_key(
    State(app_state): State<AppState>,
    encoded_data: Bytes,
) -> Result<StatusCode, UserErr> {
    let data = OcwMessageDkg::decode(&mut encoded_data.as_ref())?;
    tracing::Span::current().record("block_number", data.block_number);

    if data.validators_info.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    let (signer, x25519_secret_key) = get_signer_and_x25519_secret(&app_state.kv_store).await?;

    let in_registration_group =
        check_in_registration_group(&data.validators_info, signer.account_id());

    if in_registration_group.is_err() {
        tracing::warn!(
            "The account {:?} is not in the registration group for block_number {:?}",
            signer.account_id(),
            data.block_number
        );

        return Ok(StatusCode::MISDIRECTED_REQUEST);
    }

    validate_jump_start(&data, &api, &rpc, &app_state.kv_store).await?;

    // Do the DKG protocol in another task, so we can already respond
    tokio::spawn(async move {
        if let Err(err) = setup_dkg(api, &rpc, signer, &x25519_secret_key, data, app_state).await {
            // TODO here we would check the error and if it relates to a misbehaving node,
            // use the slashing mechanism
            tracing::error!("User registration failed {:?}", err);
        }
    });

    Ok(StatusCode::OK)
}

/// Setup and execute DKG.
///
/// Called internally by the [generate_network_key] function.
#[tracing::instrument(
    skip_all,
    fields(data),
    level = tracing::Level::DEBUG
)]
async fn setup_dkg(
    api: OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: PairSigner<EntropyConfig, sr25519::Pair>,
    x25519_secret_key: &StaticSecret,
    data: OcwMessageDkg,
    app_state: AppState,
) -> Result<(), UserErr> {
    tracing::debug!("Preparing to execute DKG");
    let (key_share, aux_info) = do_dkg(
        &data.validators_info,
        &signer,
        x25519_secret_key,
        &app_state.listener_state,
        data.block_number,
    )
    .await?;

    let verifying_key = key_share.verifying_key().to_encoded_point(true).as_bytes().to_vec();

    let serialized_key_share = key_serialize(&(key_share, aux_info))
        .map_err(|_| UserErr::KvSerialize("Kv Serialize Error".to_string()))?;

    let reservation = app_state.kv_store.kv().reserve_key(hex::encode(NETWORK_PARENT_KEY)).await?;
    app_state.kv_store.kv().put(reservation, serialized_key_share.clone()).await?;

    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash".to_string()))?;

    let nonce_call = entropy::apis().account_nonce_api().account_nonce(signer.account_id().clone());
    let nonce = api.runtime_api().at(block_hash).call(nonce_call).await?;

    // TODO: Error handling really complex needs to be thought about.
    confirm_jump_start(&api, rpc, &signer, verifying_key, nonce).await?;
    Ok(())
}

/// Confirms that the network wide distributed key generation process has taken place.
pub async fn confirm_jump_start(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    verifying_key: Vec<u8>,
    nonce: u32,
) -> Result<(), UserErr> {
    // TODO error handling + return error
    // TODO fire and forget, or wait for in block maybe Ddos error
    // TODO: Understand this better, potentially use sign_and_submit_default
    // or other method under sign_and_*

    let jump_start_request = entropy::tx().registry().confirm_jump_start(
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec(verifying_key),
    );
    submit_transaction(api, rpc, signer, &jump_start_request, Some(nonce)).await?;

    Ok(())
}

/// Validates network jump start endpoint.
///
/// Checks the chain for validity of data and block number of data matches current block
async fn validate_jump_start(
    chain_data: &OcwMessageDkg,
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    kv_manager: &KvManager,
) -> Result<(), UserErr> {
    let last_block_number_recorded = kv_manager.kv().get(LATEST_BLOCK_NUMBER_NEW_USER).await?;
    if u32::from_be_bytes(
        last_block_number_recorded
            .try_into()
            .map_err(|_| UserErr::Conversion("Block number conversion"))?,
    ) >= chain_data.block_number
    {
        return Err(UserErr::RepeatedData);
    }

    let latest_block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Failed to get block number".to_string()))?
        .number;

    // we subtract 1 as the message info is coming from the previous block
    if latest_block_number.saturating_sub(1) != chain_data.block_number {
        return Err(UserErr::StaleData);
    }

    // Check that the on-chain selected validators match those from the HTTP request
    let verifying_data_query = entropy::storage().registry().jumpstart_dkg(chain_data.block_number);
    let verifying_data = query_chain(api, rpc, verifying_data_query, None).await?.unwrap();
    let verifying_data: Vec<_> = verifying_data.into_iter().map(|v| v.0).collect();
    if verifying_data != chain_data.validators_info {
        return Err(UserErr::InvalidData);
    }

    kv_manager.kv().delete(LATEST_BLOCK_NUMBER_NEW_USER).await?;
    let reservation = kv_manager.kv().reserve_key(LATEST_BLOCK_NUMBER_NEW_USER.to_string()).await?;
    kv_manager.kv().put(reservation, chain_data.block_number.to_be_bytes().to_vec()).await?;

    Ok(())
}

/// Check if a given key is present in the given key-value store
pub async fn check_for_key(account: &str, kv: &KvManager) -> Result<bool, UserErr> {
    let exists_result = kv.kv().exists(account).await?;
    Ok(exists_result)
}

/// Checks the request limit
pub async fn request_limit_check(
    rpc: &LegacyRpcMethods<EntropyConfig>,
    kv_store: &KvManager,
    verifying_key: String,
    request_limit: u32,
) -> Result<(), UserErr> {
    let key = request_limit_key(verifying_key);
    let block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Failed to get block number".to_string()))?
        .number;

    if kv_store.kv().exists(&key).await? {
        let serialized_request_amount = kv_store.kv().get(&key).await?;
        let request_info: RequestLimitStorage =
            RequestLimitStorage::decode(&mut serialized_request_amount.as_ref())?;
        if request_info.block_number == block_number && request_info.request_amount >= request_limit
        {
            return Err(UserErr::TooManyRequests);
        }
    }

    Ok(())
}

/// Increments or restarts request count if a new block has been created
pub async fn increment_or_wipe_request_limit(
    rpc: &LegacyRpcMethods<EntropyConfig>,
    kv_store: &KvManager,
    verifying_key: String,
    request_limit: u32,
) -> Result<(), UserErr> {
    let key = request_limit_key(verifying_key);
    let block_number = rpc
        .chain_get_header(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Failed to get block number".to_string()))?
        .number;

    if kv_store.kv().exists(&key).await? {
        let serialized_request_amount = kv_store.kv().get(&key).await?;
        let request_info: RequestLimitStorage =
            RequestLimitStorage::decode(&mut serialized_request_amount.as_ref())?;

        // Previous block wipe request amount to new block
        if request_info.block_number != block_number {
            kv_store.kv().delete(&key).await?;
            let reservation = kv_store.kv().reserve_key(key).await?;
            kv_store
                .kv()
                .put(reservation, RequestLimitStorage { block_number, request_amount: 1 }.encode())
                .await?;
            return Ok(());
        }

        // same block incrememnt request amount
        if request_info.request_amount <= request_limit {
            kv_store.kv().delete(&key).await?;
            let reservation = kv_store.kv().reserve_key(key).await?;
            kv_store
                .kv()
                .put(
                    reservation,
                    RequestLimitStorage {
                        block_number,
                        request_amount: request_info.request_amount + 1,
                    }
                    .encode(),
                )
                .await?;
        }
    } else {
        let reservation = kv_store.kv().reserve_key(key).await?;
        kv_store
            .kv()
            .put(reservation, RequestLimitStorage { block_number, request_amount: 1 }.encode())
            .await?;
    }

    Ok(())
}

/// Creates the key for a request limit check
pub fn request_limit_key(signing_address: String) -> String {
    format!("{REQUEST_KEY_HEADER}_{signing_address}")
}

pub fn check_hash_pointer_out_of_bounds(
    hashing_algorithm: &HashingAlgorithm,
    program_info_len: usize,
) -> Result<(), UserErr> {
    match hashing_algorithm {
        HashingAlgorithm::Custom(i) => {
            if i >= &program_info_len {
                return Err(UserErr::CustomHashOutOfBounds);
            }
            Ok(())
        },
        _ => Ok(()),
    }
}

pub async fn pre_sign_checks(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    user_sig_req: UserSignatureRequest,
    block_number: u32,
    string_verifying_key: String,
) -> Result<(Runtime, RegisteredInfo, Vec<u8>), UserErr> {
    check_stale(user_sig_req.block_number, block_number).await?;

    // Probably impossible but block signing from parent key anyways
    if string_verifying_key == hex::encode(NETWORK_PARENT_KEY) {
        return Err(UserErr::NoSigningFromParentKey);
    }

    let user_details =
        get_registered_details(api, rpc, user_sig_req.signature_verifying_key.clone()).await?;
    check_hash_pointer_out_of_bounds(&user_sig_req.hash, user_details.programs_data.0.len())?;

    let message = hex::decode(&user_sig_req.message)?;

    if user_details.programs_data.0.is_empty() {
        return Err(UserErr::NoProgramPointerDefined());
    }

    // Handle aux data padding, if it is not explicit by client for ease send through None, error
    // if incorrect length
    let auxilary_data_vec = if let Some(auxilary_data) = user_sig_req.clone().auxilary_data {
        if auxilary_data.len() < user_details.programs_data.0.len() {
            return Err(UserErr::MismatchAuxData);
        }
        auxilary_data
    } else {
        vec![None; user_details.programs_data.0.len()]
    };

    // gets fuel from chain
    let max_instructions_per_programs_query =
        entropy::storage().parameters().max_instructions_per_programs();
    let fuel = query_chain(api, rpc, max_instructions_per_programs_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Max instructions per program error"))?;

    let mut runtime = Runtime::new(ProgramConfig { fuel });

    for (i, program_data) in user_details.programs_data.0.iter().enumerate() {
        let program_info = get_program(api, rpc, &program_data.program_pointer).await?;
        let oracle_data = get_oracle_data(api, rpc, program_info.oracle_data_pointer).await?;
        let auxilary_data = auxilary_data_vec[i].as_ref().map(hex::decode).transpose()?;
        let signature_request = SignatureRequest { message: message.clone(), auxilary_data };
        runtime.evaluate(
            &program_info.bytecode,
            &signature_request,
            Some(&program_data.program_config),
            Some(&oracle_data),
        )?;
    }

    Ok((runtime, user_details, message))
}
