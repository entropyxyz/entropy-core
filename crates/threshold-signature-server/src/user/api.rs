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
    body::{Bytes, StreamBody},
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bip39::{Language, Mnemonic};
use blake2::{Blake2s256, Digest};
use entropy_kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    helpers::serialize as key_serialize,
    value::PartyInfo,
    KvManager,
};
use entropy_programs_runtime::{Config as ProgramConfig, Runtime, SignatureRequest};
use entropy_protocol::SigningSessionInfo;
use entropy_protocol::ValidatorInfo;
use entropy_shared::{
    types::KeyVisibility, HashingAlgorithm, OcwMessageDkg, X25519PublicKey,
    MAX_INSTRUCTIONS_PER_PROGRAM, SIGNING_PARTY_SIZE,
};
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
use tracing::instrument;
use zeroize::Zeroize;

use super::{ParsedUserInputPartyInfo, ProgramError, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_relayer::pallet::RegisteringDetails},
        get_api, get_rpc, EntropyConfig,
    },
    get_random_server_info,
    helpers::{
        launch::LATEST_BLOCK_NUMBER_NEW_USER,
        signing::{do_signing, Hasher},
        substrate::{
            get_program, get_registered_details, get_subgroup, query_chain,
            return_all_addresses_of_subgroup, submit_transaction,
        },
        user::{check_in_registration_group, compute_hash, do_dkg, send_key},
        validator::get_signer,
    },
    signing_client::{ListenerState, ProtocolErr},
    validation::{check_stale, SignedMessage},
    validator::api::get_and_store_values,
    AppState, Configuration,
};

/// Represents an unparsed, transaction request coming from the client.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct UserSignatureRequest {
    /// Hex-encoded raw data to be signed (eg. hex-encoded RLP-serialized Ethereum transaction)
    pub message: String,
    /// Hex-encoded auxilary data for program evaluation, will not be signed (eg. zero-knowledge proof, serialized struct, etc)
    pub auxilary_data: Option<Vec<Option<String>>>,
    /// Information from the validators in signing party
    pub validators_info: Vec<ValidatorInfo>,
    /// When the message was created and signed
    pub timestamp: SystemTime,
    /// Hashing algorithm to be used for signing
    pub hash: HashingAlgorithm,
    /// The associated signature request account. Only in public access mode may this differ from
    /// the account used to sign the request
    pub signature_request_account: SubxtAccountId32,
}

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
}

/// Called by a user to initiate the signing process for a message
///
/// Takes an encrypted [SignedMessage] containing a JSON serialized [UserSignatureRequest]
#[tracing::instrument(
    skip_all,
    fields(signing_address = %signed_msg.account_id())
)]
pub async fn sign_tx(
    State(app_state): State<AppState>,
    Json(signed_msg): Json<SignedMessage>,
) -> Result<(StatusCode, StreamBody<impl Stream<Item = Result<String, serde_json::Error>>>), UserErr>
{
    let signer = get_signer(&app_state.kv_store).await?;

    let request_author = SubxtAccountId32(*signed_msg.account_id().as_ref());

    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;

    let mut user_sig_req: UserSignatureRequest = serde_json::from_slice(&decrypted_message)?;
    check_stale(user_sig_req.timestamp)?;

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    let user_details =
        get_registered_details(&api, &rpc, &user_sig_req.signature_request_account).await?;

    if user_details.key_visibility.0 != KeyVisibility::Public
        && user_sig_req.signature_request_account != request_author
    {
        return Err(UserErr::AuthorizationError);
    }

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

    let mut runtime = Runtime::new(ProgramConfig { fuel: MAX_INSTRUCTIONS_PER_PROGRAM });

    for (i, program_info) in user_details.programs_data.0.iter().enumerate() {
        let program = get_program(&api, &rpc, &program_info.program_pointer).await?;
        let auxilary_data = auxilary_data_vec[i].as_ref().map(hex::decode).transpose()?;
        let signature_request = SignatureRequest { message: message.clone(), auxilary_data };
        runtime.evaluate(&program, &signature_request, Some(&program_info.program_config))?;
    }
    // We decided to do Keccak for subgroup selection for frontend compatability
    let message_hash_keccak =
        compute_hash(&api, &rpc, &HashingAlgorithm::Keccak, &mut runtime, &[], message.as_slice())
            .await?;
    let message_hash_keccak_hex = hex::encode(message_hash_keccak);

    let subgroup_signers =
        get_current_subgroup_signers(&api, &rpc, &message_hash_keccak_hex).await?;
    check_signing_group(&subgroup_signers, &user_sig_req.validators_info, signer.account_id())?;

    // Use the validator info from chain as we can be sure it is in the correct order and the
    // details are correct
    user_sig_req.validators_info = subgroup_signers;

    let message_hash = compute_hash(
        &api,
        &rpc,
        &user_sig_req.hash,
        &mut runtime,
        &user_details.programs_data.0,
        message.as_slice(),
    )
    .await?;
    let message_hash_hex = hex::encode(message_hash);

    let signing_session_id = SigningSessionInfo {
        account_id: user_sig_req.signature_request_account.clone(),
        message_hash,
        request_author,
    };

    let signature_request_account_ss58 =
        AccountId32::new(user_sig_req.signature_request_account.0).to_ss58check();
    let has_key = check_for_key(&signature_request_account_ss58, &app_state.kv_store).await?;
    if !has_key {
        recover_key(&api, &rpc, &app_state.kv_store, &signer, signature_request_account_ss58)
            .await?
    }

    let (mut response_tx, response_rx) = mpsc::channel(1);

    // Do the signing protocol in another task, so we can already respond
    tokio::spawn(async move {
        let signing_protocol_output = do_signing(
            user_sig_req,
            message_hash_hex,
            &app_state,
            signing_session_id,
            user_details.key_visibility.0,
        )
        .await
        .map(|signature| {
            (
                base64::encode(signature.to_rsv_bytes()),
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
    Ok((StatusCode::OK, StreamBody::new(response_rx)))
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
    let signer = get_signer(&app_state.kv_store).await?;
    check_in_registration_group(&data.validators_info, signer.account_id())?;
    validate_new_user(&data, &api, &rpc, &app_state.kv_store).await?;

    // Do the DKG protocol in another task, so we can already respond
    tokio::spawn(async move {
        if let Err(err) = setup_dkg(api, &rpc, signer, data, app_state).await {
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
    data: OcwMessageDkg,
    app_state: AppState,
) -> Result<(), UserErr> {
    tracing::debug!("Preparing to execute DKG");

    let (subgroup, stash_address) = get_subgroup(&api, rpc, &signer).await?;
    let my_subgroup = subgroup.ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    let mut addresses_in_subgroup =
        return_all_addresses_of_subgroup(&api, rpc, my_subgroup).await?;

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
        let user_details =
            get_registering_user_details(&api, &sig_request_address.clone(), rpc).await?;

        let key_share = do_dkg(
            &data.validators_info,
            &signer,
            &app_state.listener_state,
            sig_request_address.clone(),
            *user_details.key_visibility,
        )
        .await?;
        let serialized_key_share = key_serialize(&key_share)
            .map_err(|_| UserErr::KvSerialize("Kv Serialize Error".to_string()))?;

        if app_state.kv_store.kv().exists(&sig_request_address.to_string()).await? {
            app_state.kv_store.kv().delete(&sig_request_address.to_string()).await?;
        }
        let reservation =
            app_state.kv_store.kv().reserve_key(sig_request_address.to_string()).await?;
        app_state.kv_store.kv().put(reservation, serialized_key_share.clone()).await?;

        let user_registration_info = UserRegistrationInfo {
            key: sig_request_address.to_string(),
            value: serialized_key_share,
            proactive_refresh: false,
        };
        send_key(
            &api,
            rpc,
            &stash_address,
            &mut addresses_in_subgroup,
            user_registration_info,
            &signer,
        )
        .await?;

        // TODO: Error handling really complex needs to be thought about.
        confirm_registered(
            &api,
            rpc,
            sig_request_address,
            my_subgroup,
            &signer,
            key_share.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
            nonce + i as u32,
        )
        .await?;
    }
    Ok(())
}

/// HTTP POST endpoint to recieve a keyshare from another threshold server in the same
/// signing subgroup.
///
/// Takes a [UserRegistrationInfo] wrapped in a [SignedMessage].
#[tracing::instrument(
    skip_all,
    fields(signing_address = %signed_msg.account_id())
)]
pub async fn receive_key(
    State(app_state): State<AppState>,
    Json(signed_msg): Json<SignedMessage>,
) -> Result<StatusCode, UserErr> {
    let signing_address = signed_msg.account_id();
    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }
    let signer = get_signer(&app_state.kv_store).await?;
    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;

    let user_registration_info: UserRegistrationInfo = serde_json::from_slice(&decrypted_message)?;
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    let my_subgroup = get_subgroup(&api, &rpc, &signer)
        .await?
        .0
        .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    let addresses_in_subgroup = return_all_addresses_of_subgroup(&api, &rpc, my_subgroup).await?;

    let signing_address_converted = SubxtAccountId32::from_str(&signing_address.to_ss58check())
        .map_err(|_| UserErr::StringError("Account Conversion"))?;

    // check message is from the person sending the message (get stash key from threshold key)
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(signing_address_converted);
    let stash_address = query_chain(&api, &rpc, stash_address_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Stash Fetch Error"))?;

    if !addresses_in_subgroup.contains(&stash_address) {
        return Err(UserErr::NotInSubgroup);
    }

    if user_registration_info.proactive_refresh {
        // TODO validate that an active proactive refresh is happening
        app_state.kv_store.kv().delete(&user_registration_info.key.to_string()).await?;
    } else {
        // delete key if user in registering phase
        let exists_result =
            app_state.kv_store.kv().exists(&user_registration_info.key.to_string()).await?;
        if exists_result {
            let registration_details = is_registering(
                &api,
                &rpc,
                &SubxtAccountId32::from_str(&user_registration_info.key)
                    .map_err(|_| UserErr::StringError("Account Conversion"))?,
            )
            .await?;
            if registration_details {
                app_state.kv_store.kv().delete(&user_registration_info.key.to_string()).await?;
            } else {
                return Err(UserErr::AlreadyRegistered);
            }
        }
    }
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
    let registering_info_query = entropy::storage().relayer().registering(who);
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
    let registering_info_query = entropy::storage().relayer().registering(who);
    let register_info = query_chain(api, rpc, registering_info_query, None).await?;

    Ok(register_info.is_some())
}

/// Confirms that a address has finished registering on chain.
pub async fn confirm_registered(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    who: SubxtAccountId32,
    subgroup: u8,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    verifying_key: Vec<u8>,
    nonce: u32,
) -> Result<(), UserErr> {
    // TODO error handling + return error
    // TODO fire and forget, or wait for in block maybe Ddos error
    // TODO: Understand this better, potentially use sign_and_submit_default
    // or other method under sign_and_*
    let registration_tx = entropy::tx().relayer().confirm_register(
        who,
        subgroup,
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec(verifying_key),
    );
    submit_transaction(api, rpc, signer, &registration_tx, Some(nonce)).await?;
    Ok(())
}
/// Gets the current signing committee
/// The signing committee is composed as the validators at the index into each subgroup
/// Where the index is computed as the user's sighash as an integer modulo the number of subgroups
pub async fn get_current_subgroup_signers(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    sig_hash: &str,
) -> Result<Vec<ValidatorInfo>, UserErr> {
    let mut subgroup_signers = vec![];
    let number = Arc::new(BigInt::from_str_radix(sig_hash, 16)?);
    let block_hash = rpc.chain_get_block_hash(None).await?;

    let futures = (0..SIGNING_PARTY_SIZE)
        .map(|i| {
            let owned_number = Arc::clone(&number);
            async move {
                let subgroup_info_query =
                    entropy::storage().staking_extension().signing_groups(i as u8);
                let subgroup_info = query_chain(api, rpc, subgroup_info_query, block_hash)
                    .await?
                    .ok_or_else(|| UserErr::ChainFetch("Subgroup Fetch Error"))?;

                let index_of_signer_big = &*owned_number % subgroup_info.len();
                let index_of_signer =
                    index_of_signer_big.to_usize().ok_or(UserErr::Usize("Usize error"))?;

                let threshold_address_query = entropy::storage()
                    .staking_extension()
                    .threshold_servers(subgroup_info[index_of_signer].clone());
                let server_info = query_chain(api, rpc, threshold_address_query, block_hash)
                    .await?
                    .ok_or_else(|| UserErr::ChainFetch("Subgroup Fetch Error"))?;

                Ok::<_, UserErr>(ValidatorInfo {
                    x25519_public_key: server_info.x25519_public_key,
                    ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
                    tss_account: server_info.tss_account,
                })
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
    subgroup_signers: &[ValidatorInfo],
    validators_info: &Vec<ValidatorInfo>,
    my_id: &<EntropyConfig as Config>::AccountId,
) -> Result<(), UserErr> {
    let subgroup_signer_ids: Vec<SubxtAccountId32> =
        subgroup_signers.iter().map(|signer| signer.tss_account.clone()).collect();
    // Check that validators given by the user match those from get_current_subgroup_signers
    for validator in validators_info {
        if !subgroup_signer_ids.contains(&validator.tss_account) {
            return Err(UserErr::InvalidSigner("Invalid Signer in Signing group"));
        }
    }
    // Finally, check that we ourselves are in the signing group
    if !subgroup_signer_ids.contains(my_id) {
        return Err(UserErr::InvalidSigner(
            "Signing group is valid, but this threshold server is not in the group",
        ));
    }
    Ok(())
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

    let verifying_data_query = entropy::storage().relayer().dkg(chain_data.block_number);
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

pub async fn check_for_key(account: &str, kv: &KvManager) -> Result<bool, UserErr> {
    let exists_result = kv.kv().exists(account).await?;
    Ok(exists_result)
}

pub async fn recover_key(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    kv_store: &KvManager,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    signing_address: String,
) -> Result<(), UserErr> {
    let (my_subgroup, stash_address) = get_subgroup(api, rpc, signer).await?;
    let unwrapped_subgroup = my_subgroup.ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    let key_server_info = get_random_server_info(api, rpc, unwrapped_subgroup, stash_address)
        .await
        .map_err(|_| UserErr::ValidatorError("Error getting server".to_string()))?;
    let ip_address = String::from_utf8(key_server_info.endpoint)?;
    let recip_key = x25519_dalek::PublicKey::from(key_server_info.x25519_public_key);
    get_and_store_values(vec![signing_address], kv_store, ip_address, 1, false, &recip_key, signer)
        .await
        .map_err(|e| UserErr::ValidatorError(e.to_string()))?;
    Ok(())
}
