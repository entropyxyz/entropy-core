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

use std::{str::FromStr, sync::Arc, time::SystemTime};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::prelude::{Engine, BASE64_STANDARD};
use bip39::{Language, Mnemonic};
use blake2::{Blake2s256, Digest};
use entropy_kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    helpers::serialize as key_serialize,
    value::PartyInfo,
    KvManager,
};
use entropy_programs_runtime::{Config as ProgramConfig, Runtime, SignatureRequest};
use entropy_protocol::{KeyParams, PartyId, SigningSessionInfo, ValidatorInfo};
use entropy_shared::{HashingAlgorithm, OcwMessageDkg, X25519PublicKey};
use futures::{
    channel::mpsc,
    future::{join_all, FutureExt},
    Stream,
};
use num::{bigint::BigInt, FromPrimitive, Num, ToPrimitive};
use parity_scale_codec::{Decode, DecodeAll, Encode};
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    ext::sp_core::{crypto::Ss58Codec, sr25519, sr25519::Signature, Pair},
    tx::{PairSigner, Signer},
    utils::{AccountId32 as SubxtAccountId32, MultiAddress},
    Config, OnlineClient,
};
use synedrion::KeyShare;
use tracing::instrument;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use super::{ParsedUserInputPartyInfo, ProgramError, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_registry::pallet::RegisteringDetails},
        get_api, get_rpc, EntropyConfig,
    },
    helpers::{
        launch::LATEST_BLOCK_NUMBER_NEW_USER,
        signing::{do_signing, Hasher},
        substrate::{
            get_program, get_registered_details, get_stash_address, query_chain, submit_transaction,
        },
        user::{check_in_registration_group, compute_hash, do_dkg},
        validator::{get_signer, get_signer_and_x25519_secret},
    },
    signing_client::{ListenerState, ProtocolErr},
    validation::{check_stale, EncryptedSignedMessage},
    validator::api::check_forbidden_key,
    AppState, Configuration,
};

pub use entropy_client::user::UserSignatureRequest;
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

    let request_limit_query = entropy::storage().parameters().request_limit();
    let request_limit = query_chain(&api, &rpc, request_limit_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Failed to get request limit"))?;

    let mut user_sig_req: UserSignatureRequest = serde_json::from_slice(&signed_message.message.0)?;

    let string_verifying_key = hex::encode(user_sig_req.signature_verifying_key.clone());
    request_limit_check(&rpc, &app_state.kv_store, string_verifying_key.clone(), request_limit)
        .await?;

    check_stale(user_sig_req.timestamp)?;
    let user_details =
        get_registered_details(&api, &rpc, user_sig_req.signature_verifying_key.clone()).await?;
    check_hash_pointer_out_of_bounds(&user_sig_req.hash, user_details.programs_data.0.len())?;

    let message = hex::decode(&user_sig_req.message)?;

    if user_details.programs_data.0.is_empty() {
        return Err(UserErr::NoProgramPointerDefined());
    }
    // handle aux data padding, if it is not explicit by client for ease send through None, error if incorrect length
    let auxilary_data_vec;
    if let Some(auxilary_data) = user_sig_req.clone().auxilary_data {
        if auxilary_data.len() < user_details.programs_data.0.len() {
            return Err(UserErr::MismatchAuxData);
        } else {
            auxilary_data_vec = auxilary_data;
        }
    } else {
        auxilary_data_vec = vec![None; user_details.programs_data.0.len()];
    }
    // gets fuel from chain
    let max_instructions_per_programs_query =
        entropy::storage().parameters().max_instructions_per_programs();
    let fuel = query_chain(&api, &rpc, max_instructions_per_programs_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Max instructions per program error"))?;

    let mut runtime = Runtime::new(ProgramConfig { fuel });

    for (i, program_info) in user_details.programs_data.0.iter().enumerate() {
        let program = get_program(&api, &rpc, &program_info.program_pointer).await?;
        let auxilary_data = auxilary_data_vec[i].as_ref().map(hex::decode).transpose()?;
        let signature_request = SignatureRequest { message: message.clone(), auxilary_data };
        runtime.evaluate(&program, &signature_request, Some(&program_info.program_config), None)?;
    }

    let signers = get_signers_from_chain(&api, &rpc).await?;
    // // Use the validator info from chain as we can be sure it is in the correct order and the
    // // details are correct
    user_sig_req.validators_info = signers;

    let message_hash = compute_hash(
        &api,
        &rpc,
        &user_sig_req.hash,
        &mut runtime,
        &user_details.programs_data.0,
        message.as_slice(),
    )
    .await?;

    let signing_session_id = SigningSessionInfo {
        signature_verifying_key: user_sig_req.signature_verifying_key.clone(),
        message_hash,
        request_author,
    };

    let _has_key = check_for_key(&string_verifying_key, &app_state.kv_store).await?;

    let (mut response_tx, response_rx) = mpsc::channel(1);

    // Do the signing protocol in another task, so we can already respond
    tokio::spawn(async move {
        let signing_protocol_output =
            do_signing(&rpc, user_sig_req, &app_state, signing_session_id, request_limit)
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

/// HTTP POST endpoint called by the off-chain worker (propagation pallet) during user registration.
///
/// The HTTP request takes a Parity SCALE encoded [OcwMessageDkg] which indicates which validators
/// are in the validator group.
///
/// This will trigger the Distributed Key Generation (DKG) process.
#[tracing::instrument(skip_all, fields(block_number))]
pub async fn new_user(
    State(app_state): State<AppState>,
    encoded_data: Bytes,
) -> Result<StatusCode, UserErr> {
    let data = OcwMessageDkg::decode(&mut encoded_data.as_ref())?;
    tracing::Span::current().record("block_number", data.block_number);

    if data.sig_request_accounts.is_empty() {
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

    validate_new_user(&data, &api, &rpc, &app_state.kv_store).await?;

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
/// Called internally by the [new_user] function.
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

    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash".to_string()))?;
    let nonce_call = entropy::apis().account_nonce_api().account_nonce(signer.account_id().clone());
    let nonce = api.runtime_api().at(block_hash).call(nonce_call).await?;

    for (i, sig_request_account) in data.sig_request_accounts.into_iter().enumerate() {
        let address_slice: &[u8; 32] = &sig_request_account
            .clone()
            .try_into()
            .map_err(|_| UserErr::AddressConversionError("Invalid Length".to_string()))?;
        let sig_request_address = SubxtAccountId32(*address_slice);

        let (key_share, aux_info) = do_dkg(
            &data.validators_info,
            &signer,
            x25519_secret_key,
            &app_state.listener_state,
            sig_request_address.clone(),
            data.block_number,
        )
        .await?;
        let verifying_key = key_share.verifying_key().to_encoded_point(true).as_bytes().to_vec();
        let string_verifying_key = hex::encode(verifying_key.clone()).to_string();
        let serialized_key_share = key_serialize(&(key_share, aux_info))
            .map_err(|_| UserErr::KvSerialize("Kv Serialize Error".to_string()))?;

        let reservation = app_state.kv_store.kv().reserve_key(string_verifying_key.clone()).await?;
        app_state.kv_store.kv().put(reservation, serialized_key_share.clone()).await?;

        // TODO: Error handling really complex needs to be thought about.
        confirm_registered(
            &api,
            rpc,
            sig_request_address,
            &signer,
            verifying_key,
            nonce + i as u32,
        )
        .await?;
    }
    Ok(())
}

/// HTTP POST endpoint to recieve a keyshare from another threshold server in the same
/// signing subgroup.
///
/// Takes a [UserRegistrationInfo] wrapped in an [EncryptedSignedMessage].
#[tracing::instrument(skip_all, fields(signing_address))]
pub async fn receive_key(
    State(app_state): State<AppState>,
    Json(encrypted_message): Json<EncryptedSignedMessage>,
) -> Result<StatusCode, UserErr> {
    let (_signer, x25519_secret_key) = get_signer_and_x25519_secret(&app_state.kv_store).await?;
    let signed_message = encrypted_message.decrypt(&x25519_secret_key, &[])?;
    let signing_address = signed_message.account_id();
    tracing::Span::current().record("signing_address", signing_address.to_string());

    let user_registration_info: UserRegistrationInfo =
        serde_json::from_slice(&signed_message.message.0)?;

    check_forbidden_key(&user_registration_info.key).map_err(|_| UserErr::ForbiddenKey)?;

    // Check this is a well-formed keyshare
    let _: KeyShare<KeyParams, PartyId> =
        entropy_kvdb::kv_manager::helpers::deserialize(&user_registration_info.value)
            .ok_or_else(|| UserErr::InputValidation("Not a valid keyshare"))?;

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    let already_exists =
        app_state.kv_store.kv().exists(&user_registration_info.key.to_string()).await?;

    if user_registration_info.proactive_refresh {
        if !already_exists {
            return Err(UserErr::UserDoesNotExist);
        }
        // TODO validate that an active proactive refresh is happening
        app_state.kv_store.kv().delete(&user_registration_info.key.to_string()).await?;
    } else {
        let registering = is_registering(
            &api,
            &rpc,
            &user_registration_info.sig_request_address.ok_or_else(|| {
                UserErr::OptionUnwrapError("Failed to unwrap signature request account".to_string())
            })?,
        )
        .await?;

        if already_exists {
            if registering {
                // Delete key if user in registering phase
                app_state.kv_store.kv().delete(&user_registration_info.key.to_string()).await?;
            } else {
                return Err(UserErr::AlreadyRegistered);
            }
        } else if !registering {
            return Err(UserErr::NotRegistering("Provided account ID not from a registering user"));
        }
    }

    // TODO #652 now get the block number and check that the author of the message should be in the
    // current DKG or proactive refresh committee

    let reservation =
        app_state.kv_store.kv().reserve_key(user_registration_info.key.to_string()).await?;
    app_state.kv_store.kv().put(reservation, user_registration_info.value).await?;
    Ok(StatusCode::OK)
}

/// Returns details of a given registering user including key key visibility and X25519 public key.
#[tracing::instrument(
    skip_all,
    fields(who),
    level = tracing::Level::DEBUG
)]
pub async fn get_registering_user_details(
    api: &OnlineClient<EntropyConfig>,
    who: &<EntropyConfig as Config>::AccountId,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<RegisteringDetails, UserErr> {
    let registering_info_query = entropy::storage().registry().registering(who);
    let register_info = query_chain(api, rpc, registering_info_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Register Onchain first"))?;
    Ok(register_info)
}

/// Returns `true` if the given account is in a "registering" state.
pub async fn is_registering(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    who: &<EntropyConfig as Config>::AccountId,
) -> Result<bool, UserErr> {
    let registering_info_query = entropy::storage().registry().registering(who);
    let register_info = query_chain(api, rpc, registering_info_query, None).await?;

    Ok(register_info.is_some())
}

/// Confirms that a address has finished registering on chain.
pub async fn confirm_registered(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    who: SubxtAccountId32,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    verifying_key: Vec<u8>,
    nonce: u32,
) -> Result<(), UserErr> {
    // TODO error handling + return error
    // TODO fire and forget, or wait for in block maybe Ddos error
    // TODO: Understand this better, potentially use sign_and_submit_default
    // or other method under sign_and_*
    let registration_tx = entropy::tx().registry().confirm_register(
        who,
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec(verifying_key),
    );
    submit_transaction(api, rpc, signer, &registration_tx, Some(nonce)).await?;
    Ok(())
}

pub async fn get_signers_from_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<ValidatorInfo>, UserErr> {
    let all_validators_query = entropy::storage().session().validators();
    let all_validators = query_chain(api, rpc, all_validators_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Get all validators error"))?;
    let block_hash = rpc.chain_get_block_hash(None).await?;
    let mut handles = Vec::new();

    for validator in all_validators {
        let handle: tokio::task::JoinHandle<Result<ValidatorInfo, UserErr>> = tokio::task::spawn({
            let api = api.clone();
            let rpc = rpc.clone();
            async move {
                let threshold_address_query =
                    entropy::storage().staking_extension().threshold_servers(validator);
                let server_info = query_chain(&api, &rpc, threshold_address_query, block_hash)
                    .await?
                    .ok_or_else(|| UserErr::ChainFetch("Subgroup Fetch Error"))?;
                Ok(ValidatorInfo {
                    x25519_public_key: server_info.x25519_public_key,
                    ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
                    tss_account: server_info.tss_account,
                })
            }
        });
        handles.push(handle);
    }
    let mut all_signers: Vec<ValidatorInfo> = vec![];
    for handle in handles {
        all_signers.push(handle.await??);
    }

    Ok(all_signers)
}

/// Validates new user endpoint
/// Checks the chain for validity of data and block number of data matches current block
pub async fn validate_new_user(
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

    let mut hasher_chain_data = Blake2s256::new();
    hasher_chain_data.update(Some(chain_data.sig_request_accounts.clone()).encode());
    let chain_data_hash = hasher_chain_data.finalize();
    let mut hasher_verifying_data = Blake2s256::new();

    let verifying_data_query = entropy::storage().registry().dkg(chain_data.block_number);
    let verifying_data = query_chain(api, rpc, verifying_data_query, None).await?;
    hasher_verifying_data.update(verifying_data.encode());

    let verifying_data_hash = hasher_verifying_data.finalize();
    if verifying_data_hash != chain_data_hash {
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
