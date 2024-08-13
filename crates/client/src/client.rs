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
pub use crate::{
    chain_api::{get_api, get_rpc},
    errors::ClientError,
};
use anyhow::anyhow;
pub use entropy_protocol::{sign_and_encrypt::EncryptedSignedMessage, KeyParams};
use std::str::FromStr;
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
    client::entropy::staking_extension::events::{EndpointChanged, ThresholdAccountChanged},
    substrate::{query_chain, submit_transaction_with_pair},
    user::{get_signers_from_chain, UserSignatureRequest},
    Hasher,
};

use base64::prelude::{Engine, BASE64_STANDARD};
use entropy_protocol::RecoverableSignature;
use entropy_shared::HashingAlgorithm;
use futures::{future, stream::StreamExt};
use sp_core::{sr25519, Pair};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    events::EventsClient,
    utils::{AccountId32 as SubxtAccountId32, H256},
    Config, OnlineClient,
};
use synedrion::k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey};

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
    )
)]
pub async fn register(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signature_request_keypair: sr25519::Pair,
    program_account: SubxtAccountId32,
    programs_data: BoundedVec<ProgramInstance>,
    on_chain: bool,
) -> Result<Vec<([u8; VERIFYING_KEY_LENGTH], RegisteredInfo)>, ClientError> {
    // TODO (Nando): We hack the jumpstart for now. Ideally we already have this done by the point
    // somebody tries to register
    dbg!(jumpstart_network(api, rpc, signature_request_keypair.clone()).await);
    println!("Waiting for network jumpstart");
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    // Send register transaction
    let account_registration_events = if on_chain {
        dbg!(
            put_register_request_on_chain(
                api,
                rpc,
                signature_request_keypair.clone(),
                program_account,
                programs_data,
            )
            .await
        )?
    } else {
        dbg!(
            put_old_register_request_on_chain(
                api,
                rpc,
                signature_request_keypair.clone(),
                program_account,
                programs_data,
            )
            .await
        )?
    };

    let mut registration_info = vec![];
    for event in account_registration_events {
        let verifying_key = event.1 .0;
        let registered_info = get_registered_details(api, rpc, verifying_key.clone()).await?;

        registration_info.push((
            verifying_key.try_into().map_err(|_| ClientError::BadVerifyingKeyLength)?,
            registered_info,
        ))
    }

    Ok(registration_info)

    // let account_id: SubxtAccountId32 = signature_request_keypair.public().into();

    // for _ in 0..50 {
    //     let block_hash = rpc.chain_get_block_hash(None).await?;
    //     let events =
    //         EventsClient::new(api.clone()).at(block_hash.ok_or(ClientError::BlockHash)?).await?;
    //     let registered_event = events.find::<entropy::registry::events::AccountRegistered>();
    //     for event in registered_event.flatten() {
    //         // check if the event belongs to this user
    //         if event.0 == account_id {
    //             let registered_query = entropy::storage().registry().registered(&event.1);
    //             let registered_status = query_chain(api, rpc, registered_query, block_hash).await?;
    //             if let Some(status) = registered_status {
    //                 let verifying_key =
    //                     event.1 .0.try_into().map_err(|_| ClientError::BadVerifyingKeyLength)?;
    //                 return Ok((verifying_key, status));
    //             }
    //         }
    //     }
    //     std::thread::sleep(std::time::Duration::from_millis(1000));
    // }
    // Err(ClientError::RegistrationTimeout)
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
    auxilary_data: Option<Vec<u8>>,
) -> Result<RecoverableSignature, ClientError> {
    let message_hash = Hasher::keccak(&message);

    // TODO (Nando): So depending on the verifying key we'd need to change this flag
    // let user_details =
    //   get_registered_details(&api, &rpc, user_sig_req.signature_verifying_key.clone()).await?;
    //       if user_details.derivation_path.is_none() { ... }

    let validators_info = get_signers_from_chain(api, rpc, false).await?;

    tracing::debug!("Validators info {:?}", validators_info);
    let block_number = rpc.chain_get_header(None).await?.ok_or(ClientError::BlockNumber)?.number;
    let signature_request = UserSignatureRequest {
        message: hex::encode(message),
        auxilary_data: Some(vec![auxilary_data.map(hex::encode)]),
        validators_info: validators_info.clone(),
        block_number,
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key: signature_verifying_key.to_vec(),
    };

    let signature_request_vec = serde_json::to_vec(&signature_request)?;
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
    let results = future::try_join_all(submit_transaction_requests).await?;

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
    program_instances: BoundedVec<ProgramInstance>,
) -> Result<Vec<entropy::registry::events::AccountRegistered>, ClientError> {
    println!("on_chain");

    let registering_tx = entropy::tx().registry().register_on_chain(deployer, program_instances);
    let registered_events =
        submit_transaction_with_pair(api, rpc, &signature_request_keypair, &registering_tx, None)
            .await?;

    // Note: In the case of the new registration flow we can have many registration events for a
    // single signature request account.
    let registered_events: Vec<_> = registered_events
        .find::<entropy::registry::events::AccountRegistered>()
        .flatten()
        .filter(|event| event.0 == signature_request_keypair.public().into())
        .collect();

    Ok(registered_events)
}

/// Submit a register transaction
pub async fn put_old_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signature_request_keypair: sr25519::Pair,
    deployer: SubxtAccountId32,
    program_instances: BoundedVec<ProgramInstance>,
) -> Result<Vec<entropy::registry::events::AccountRegistered>, ClientError> {
    println!("off_chain");

    let registering_tx = entropy::tx().registry().register(deployer, program_instances);
    submit_transaction_with_pair(api, rpc, &signature_request_keypair, &registering_tx, None)
        .await?;

    let account_id: SubxtAccountId32 = signature_request_keypair.public().into();

    for _ in 0..50 {
        let block_hash = rpc.chain_get_block_hash(None).await?;
        let events =
            EventsClient::new(api.clone()).at(block_hash.ok_or(ClientError::BlockHash)?).await?;
        let registered_event = events.find::<entropy::registry::events::AccountRegistered>();
        for event in registered_event.flatten() {
            // check if the event belongs to this user
            if event.0 == account_id {
                return Ok(vec![event]);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    Err(ClientError::RegistrationTimeout)
}

/// Returns a registered user's key visibility
///
/// TODO (Nando): This was copied from `entropy-tss::helpers::substrate`
#[tracing::instrument(skip_all, fields(verifying_key))]
pub async fn get_registered_details(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    verifying_key: Vec<u8>,
) -> Result<RegisteredInfo, ClientError> {
    tracing::info!("Querying chain for registration info.");

    let registered_info_query =
        entropy::storage().registry().registered(BoundedVec(verifying_key.clone()));
    let registered_result = query_chain(api, rpc, registered_info_query, None).await?;

    let registration_info = if let Some(old_registration_info) = registered_result {
        tracing::debug!("Found user in old `Registered` struct.");

        old_registration_info
    } else {
        // We failed with the old registration path, let's try the new one
        tracing::warn!("Didn't find user in old `Registered` struct, trying new one.");

        let registered_info_query =
            entropy::storage().registry().registered_on_chain(BoundedVec(verifying_key));

        query_chain(api, rpc, registered_info_query, None).await?.expect("TODO")
        // .ok_or_else(|| UserErr::ChainFetch("Not Registering error: Register Onchain first"))?
    };

    Ok(registration_info)
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

/// Changes the endpoint of a validator
pub async fn change_endpoint(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    user_keypair: sr25519::Pair,
    new_endpoint: String,
) -> anyhow::Result<EndpointChanged> {
    let change_endpoint_tx = entropy::tx().staking_extension().change_endpoint(new_endpoint.into());
    let in_block =
        submit_transaction_with_pair(api, rpc, &user_keypair, &change_endpoint_tx, None).await?;
    let result_event = in_block
        .find_first::<entropy::staking_extension::events::EndpointChanged>()?
        .ok_or(anyhow!("Error with transaction"))?;
    Ok(result_event)
}

/// Changes the threshold account info of a validator
pub async fn change_threshold_accounts(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    user_keypair: sr25519::Pair,
    new_tss_account: String,
    new_x25519_public_key: String,
) -> anyhow::Result<ThresholdAccountChanged> {
    let tss_account = SubxtAccountId32::from_str(&new_tss_account)?;
    let change_threshold_accounts = entropy::tx().staking_extension().change_threshold_accounts(
        tss_account,
        hex::decode(new_x25519_public_key)?
            .try_into()
            .map_err(|_| anyhow!("X25519 pub key needs to be 32 bytes"))?,
    );
    let in_block =
        submit_transaction_with_pair(api, rpc, &user_keypair, &change_threshold_accounts, None)
            .await?;
    let result_event = in_block
        .find_first::<entropy::staking_extension::events::ThresholdAccountChanged>()?
        .ok_or(anyhow!("Error with transaction"))?;
    Ok(result_event)
}

/// Trigger a network wide distributed key generation (DKG) event.
///
/// Fails if the network has already been jumpstarted.
pub async fn jumpstart_network(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: sr25519::Pair,
) -> Result<(), ClientError> {
    // We split the implementation out into an inner function so that we can more easily pass a
    // single future to the `timeout`
    tokio::time::timeout(std::time::Duration::from_secs(45), jumpstart_inner(api, rpc, signer))
        .await
        .map_err(|_| ClientError::JumpstartTimeout)?
}

async fn jumpstart_inner(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: sr25519::Pair,
) -> Result<(), ClientError> {
    // In this case we don't care too much about the result because we're more interested in the
    // `FinishedNetworkJumpStart` event, which happens later on.
    let jump_start_request = entropy::tx().registry().jump_start_network();
    let _result =
        submit_transaction_with_pair(api, rpc, &signer, &jump_start_request, None).await?;

    let mut blocks_sub = api.blocks().subscribe_finalized().await?;

    while let Some(block) = blocks_sub.next().await {
        let block = block?;
        let events = block.events().await?;

        if events.has::<entropy::registry::events::FinishedNetworkJumpStart>()? {
            break;
        }
    }

    Ok(())
}
