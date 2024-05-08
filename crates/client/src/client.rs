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

//! Simple client for Entropy.
//! Used in integration tests and for the test-cli
pub use crate::chain_api::{get_api, get_rpc};
pub use entropy_protocol::{sign_and_encrypt::EncryptedSignedMessage, KeyParams};
pub use entropy_shared::{KeyVisibility, SIGNING_PARTY_SIZE};
pub use synedrion::KeyShare;

use crate::{
    chain_api::{
        entropy::{
            self,
            runtime_types::{
                bounded_collections::bounded_vec::BoundedVec,
                pallet_programs::pallet::ProgramInfo,
                pallet_registry::pallet::{ProgramInstance, RegisteredInfo},
            },
        },
        EntropyConfig,
    },
    substrate::{query_chain, submit_transaction_with_pair, SubstrateError},
    user::{get_current_subgroup_signers, SubgroupGetError, UserSignatureRequest},
    Hasher,
};
use base64::prelude::{Engine, BASE64_STANDARD};
use entropy_protocol::{
    errors::UserRunningProtocolErr,
    user::{user_participates_in_dkg_protocol, user_participates_in_signing_protocol},
    RecoverableSignature, ValidatorInfo,
};
use entropy_shared::HashingAlgorithm;
use futures::{future, stream::StreamExt};
use sp_core::{sr25519, Pair};
use std::time::SystemTime;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    events::EventsClient,
    utils::{AccountId32 as SubxtAccountId32, Static, H256},
    Config, OnlineClient,
};
use synedrion::k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey};
use thiserror::Error;
use x25519_dalek::StaticSecret;

pub const VERIFYING_KEY_LENGTH: usize = entropy_shared::VERIFICATION_KEY_LENGTH as usize;

/// Register an account.
///
/// If successful, returns registration info including verfiying key.
///
/// If registering in private mode, a keyshare is also returned.
#[allow(clippy::type_complexity)]
#[tracing::instrument(
    skip_all,
    fields(
        signature_request_account = ?signature_request_keypair.public(),
        program_account,
        key_visibility,
    )
)]
pub async fn register(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signature_request_keypair: sr25519::Pair,
    program_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    programs_data: BoundedVec<ProgramInstance>,
    x25519_secret_key: Option<StaticSecret>,
) -> Result<(RegisteredInfo, Option<KeyShare<KeyParams>>), ClientError> {
    // Send register transaction
    put_register_request_on_chain(
        api,
        rpc,
        signature_request_keypair.clone(),
        program_account,
        key_visibility,
        programs_data,
    )
    .await?;

    // If registering with private key visibility, participate in the DKG protocol
    let keyshare_option = match key_visibility {
        KeyVisibility::Private(x25519_public_key) => {
            let x25519_secret_key = x25519_secret_key.ok_or(ClientError::PrivateMode)?;

            let x25519_public_key_check =
                x25519_dalek::PublicKey::from(&x25519_secret_key).to_bytes();
            if x25519_public_key_check != x25519_public_key {
                return Err(ClientError::PrivateMode);
            }

            let block_number =
                rpc.chain_get_header(None).await?.ok_or(ClientError::BlockNumber)?.number + 1;

            let validators_info = get_dkg_committee(api, rpc, block_number).await?;
            Some(
                user_participates_in_dkg_protocol(
                    validators_info,
                    &signature_request_keypair,
                    x25519_secret_key,
                    block_number,
                )
                .await?,
            )
        },
        _ => None,
    };

    let account_id: <EntropyConfig as Config>::AccountId =
        SubxtAccountId32(signature_request_keypair.public().0);

    for _ in 0..50 {
        let block_hash = rpc.chain_get_block_hash(None).await?;
        let events =
            EventsClient::new(api.clone()).at(block_hash.ok_or(ClientError::BlockHash)?).await?;
        let registered_event = events.find::<entropy::registry::events::AccountRegistered>();
        for event in registered_event.flatten() {
            if event.0 == account_id {
                let registered_query = entropy::storage().registry().registered(&event.1);
                let registered_status = query_chain(api, rpc, registered_query, block_hash).await?;
                if let Some(status) = registered_status {
                    // check if the event belongs to this user
                    return Ok((status, keyshare_option));
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    Err(ClientError::RegistrationTimeout)
}

/// Request to sign a message
#[tracing::instrument(
    skip_all,
    fields(
        user_account = ?user_keypair.public(),
        signature_verifying_key,
        message,
        private,
        auxilary_data,
    )
)]
pub async fn sign(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    user_keypair: sr25519::Pair,
    signature_verifying_key: [u8; VERIFYING_KEY_LENGTH],
    message: Vec<u8>,
    private: Option<(KeyShare<KeyParams>, StaticSecret)>,
    auxilary_data: Option<Vec<u8>>,
) -> Result<RecoverableSignature, ClientError> {
    let message_hash = Hasher::keccak(&message);
    let message_hash_hex = hex::encode(message_hash);
    let validators_info = get_current_subgroup_signers(api, rpc, &message_hash_hex).await?;
    tracing::debug!("Validators info {:?}", validators_info);

    let signature_request = UserSignatureRequest {
        message: hex::encode(message),
        auxilary_data: Some(vec![auxilary_data.map(hex::encode)]),
        validators_info: validators_info.clone(),
        timestamp: get_current_time(),
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key: signature_verifying_key.to_vec(),
    };

    let signature_request_vec = serde_json::to_vec(&signature_request)?;
    let validators_info_clone = validators_info.clone();
    let client = reqwest::Client::new();

    // Make http requests to TSS servers
    let submit_transaction_requests = validators_info
        .iter()
        .map(|validator_info| async {
            let encrypted_message = EncryptedSignedMessage::new(
                &user_keypair,
                signature_request_vec.clone(),
                &validator_info.x25519_public_key,
                &[],
            )?;
            let message_json = serde_json::to_string(&encrypted_message)?;

            let url = format!("http://{}/user/sign_tx", validator_info.ip_address);

            let res = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(message_json)
                .send()
                .await;
            Ok::<_, ClientError>(res)
        })
        .collect::<Vec<_>>();

    // If we have a keyshare, connect to TSS servers
    let results = if let Some((keyshare, x25519_secret_key)) = private {
        let (validator_results, _own_result) = future::join(
            future::try_join_all(submit_transaction_requests),
            user_participates_in_signing_protocol(
                &keyshare,
                validators_info_clone,
                &user_keypair,
                x25519_secret_key,
                message_hash,
            ),
        )
        .await;
        validator_results?
    } else {
        future::try_join_all(submit_transaction_requests).await?
    };

    // Get the first result
    if let Some(res) = results.into_iter().next() {
        let output = res?;
        if output.status() != 200 {
            return Err(ClientError::SigningFailed(output.text().await?));
        }

        let mut bytes_stream = output.bytes_stream();
        let chunk = bytes_stream.next().await.ok_or(ClientError::NoResponse)??;
        let signing_result: Result<(String, sr25519::Signature), String> =
            serde_json::from_slice(&chunk)?;
        let (signature_base64, signature_of_signature) =
            signing_result.map_err(ClientError::SigningFailed)?;
        tracing::debug!("Signature: {}", signature_base64);
        let mut decoded_sig = BASE64_STANDARD.decode(signature_base64)?;

        // Verify the response signature from the TSS client
        if !sr25519::Pair::verify(
            &signature_of_signature,
            &decoded_sig,
            &sr25519::Public(validators_info[0].tss_account.0),
        ) {
            return Err(ClientError::BadSignature);
        }

        let recovery_digit = decoded_sig.pop().ok_or(ClientError::NoRecoveryId)?;
        let signature = k256Signature::from_slice(&decoded_sig)?;
        let recovery_id =
            RecoveryId::from_byte(recovery_digit).ok_or(ClientError::BadRecoveryId)?;

        let verifying_key_of_signature =
            VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)?;
        tracing::debug!("Verifying Key {:?}", verifying_key_of_signature);

        return Ok(RecoverableSignature { signature, recovery_id });
    }
    Err(ClientError::NoResponse)
}

/// Store a program on chain and return it's hash
#[tracing::instrument(
    skip_all,
    fields(
        signature_request_account,
        deployer = ?deployer_pair.public(),
    )
)]
pub async fn store_program(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    deployer_pair: &sr25519::Pair,
    program: Vec<u8>,
    configuration_interface: Vec<u8>,
    auxiliary_data_interface: Vec<u8>,
    oracle_data_pointer: Vec<u8>,
) -> Result<<EntropyConfig as Config>::Hash, ClientError> {
    let update_program_tx = entropy::tx().programs().set_program(
        program,
        configuration_interface,
        auxiliary_data_interface,
        oracle_data_pointer,
    );
    let in_block =
        submit_transaction_with_pair(api, rpc, deployer_pair, &update_program_tx, None).await?;
    let result_event = in_block.find_first::<entropy::programs::events::ProgramCreated>()?;
    Ok(result_event.ok_or(ClientError::CannotConfirmProgramCreated)?.program_hash)
}

/// Update the program pointers associated with a given entropy account
pub async fn update_programs(
    entropy_api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    verifying_key: [u8; VERIFYING_KEY_LENGTH],
    deployer_pair: &sr25519::Pair,
    program_instance: BoundedVec<ProgramInstance>,
) -> Result<(), ClientError> {
    let update_pointer_tx = entropy::tx()
        .registry()
        .change_program_instance(BoundedVec(verifying_key.to_vec()), program_instance);
    submit_transaction_with_pair(entropy_api, rpc, deployer_pair, &update_pointer_tx, None).await?;
    Ok(())
}
/// Get info on all registered accounts
pub async fn get_accounts(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<([u8; VERIFYING_KEY_LENGTH], RegisteredInfo)>, ClientError> {
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or(ClientError::BlockHash)?;
    let storage_address = entropy::storage().registry().registered_iter();
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    let mut accounts = Vec::new();
    while let Some(Ok(kv)) = iter.next().await {
        let key: [u8; VERIFYING_KEY_LENGTH] =
            kv.key_bytes[kv.key_bytes.len() - VERIFYING_KEY_LENGTH..].try_into()?;
        accounts.push((key, kv.value))
    }
    Ok(accounts)
}

/// Get details of all stored programs
pub async fn get_programs(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<(H256, ProgramInfo<<EntropyConfig as Config>::AccountId>)>, ClientError> {
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or(ClientError::BlockHash)?;

    let storage_address = entropy::storage().programs().programs_iter();
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    let mut programs = Vec::new();
    while let Some(Ok(kv)) = iter.next().await {
        let hash: [u8; 32] = kv.key_bytes[kv.key_bytes.len() - 32..].try_into()?;
        programs.push((H256(hash), kv.value));
    }
    Ok(programs)
}

/// Submit a register transaction
pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signature_request_keypair: sr25519::Pair,
    deployer: SubxtAccountId32,
    key_visibility: KeyVisibility,
    program_instance: BoundedVec<ProgramInstance>,
) -> Result<(), ClientError> {
    let registering_tx =
        entropy::tx().registry().register(deployer, Static(key_visibility), program_instance);

    submit_transaction_with_pair(api, rpc, &signature_request_keypair, &registering_tx, None)
        .await?;
    Ok(())
}

/// Check that the verfiying key from a new signature matches that in the from the
/// on-chain registration info for a given account
pub async fn check_verifying_key(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    verifying_key: VerifyingKey,
) -> Result<(), ClientError> {
    let verifying_key_serialized = verifying_key.to_encoded_point(true).as_bytes().to_vec();

    // Get the verifying key associated with this account, if it exist return ok
    let registered_query =
        entropy::storage().registry().registered(BoundedVec(verifying_key_serialized));
    let query_registered_status = query_chain(api, rpc, registered_query, None).await;
    query_registered_status?.ok_or(ClientError::NotRegistered)?;
    Ok(())
}

/// Get the commitee of tss servers who will perform DKG for a given block number
async fn get_dkg_committee(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    block_number: u32,
) -> Result<Vec<ValidatorInfo>, ClientError> {
    let mut validators_info: Vec<ValidatorInfo> = vec![];

    for i in 0..SIGNING_PARTY_SIZE {
        let account_id = select_validator_from_subgroup(api, rpc, i as u8, block_number).await?;

        let threshold_address_query =
            entropy::storage().staking_extension().threshold_servers(account_id);
        let server_info = query_chain(api, rpc, threshold_address_query, None)
            .await?
            .ok_or(ClientError::StashFetch)?;
        let validator_info = ValidatorInfo {
            x25519_public_key: server_info.x25519_public_key,
            ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
            tss_account: server_info.tss_account,
        };
        validators_info.push(validator_info);
    }
    Ok(validators_info)
}

/// For a given subgroup ID, choose a validator using a block number, omitting validators who are
/// not synced
async fn select_validator_from_subgroup(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signing_group: u8,
    block_number: u32,
) -> Result<SubxtAccountId32, ClientError> {
    let subgroup_info_query = entropy::storage().staking_extension().signing_groups(signing_group);
    let mut subgroup_addresses = query_chain(api, rpc, subgroup_info_query, None)
        .await?
        .ok_or(ClientError::SubgroupFetch)?;

    let address = loop {
        if subgroup_addresses.is_empty() {
            return Err(ClientError::NoSyncedValidators);
        }
        let selection: u32 = block_number % subgroup_addresses.len() as u32;
        let address = &subgroup_addresses[selection as usize];
        let is_validator_syned_query =
            entropy::storage().staking_extension().is_validator_synced(address);
        let is_synced = query_chain(api, rpc, is_validator_syned_query, None)
            .await?
            .ok_or(ClientError::CannotQuerySynced)?;
        if !is_synced {
            subgroup_addresses.remove(selection as usize);
        } else {
            break address;
        }
    };
    Ok(address.clone())
}

#[cfg(feature = "full-client-wasm")]
fn get_current_time() -> SystemTime {
    use std::time::{Duration, UNIX_EPOCH};
    UNIX_EPOCH + Duration::from_secs(js_sys::Date::now() as u64)
}
#[cfg(not(feature = "full-client-wasm"))]
fn get_current_time() -> SystemTime {
    SystemTime::now()
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Substrate: {0}")]
    Substrate(#[from] SubstrateError),
    #[error("Error relating to private mode")]
    PrivateMode,
    #[error("Cannot get block number")]
    BlockNumber,
    #[error("Cannot get block hash")]
    BlockHash,
    #[error("Stash fetch")]
    StashFetch,
    #[error("UTF8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("User running protocol: {0}")]
    UserRunningProtocol(#[from] UserRunningProtocolErr),
    #[error("Subxt: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("Timed out waiting for register confirmation")]
    RegistrationTimeout,
    #[error("Cannot get subgroup: {0}")]
    SubgroupGet(#[from] SubgroupGetError),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] entropy_protocol::sign_and_encrypt::EncryptedSignedMessageErr),
    #[error("Http client: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Failed to get response from TSS Server")]
    NoResponse,
    #[error("Bad signature in response from TSS Server")]
    BadSignature,
    #[error("Base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("ECDSA: {0}")]
    Ecdsa(#[from] synedrion::ecdsa::Error),
    #[error("Cannot get recovery ID from signature")]
    NoRecoveryId,
    #[error("Cannot parse recovery ID from signature")]
    BadRecoveryId,
    #[error("Cannot parse chain query response: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("User not registered")]
    NotRegistered,
    #[error("No synced validators")]
    NoSyncedValidators,
    #[error("Cannot confirm program was created")]
    CannotConfirmProgramCreated,
    #[error("Subgroup fetch error")]
    SubgroupFetch,
    #[error("Cannot query whether validator is synced")]
    CannotQuerySynced,
}
