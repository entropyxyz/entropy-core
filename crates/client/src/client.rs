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
    errors::{ClientError, SubstrateError},
};
pub use entropy_protocol::{sign_and_encrypt::EncryptedSignedMessage, KeyParams};
use parity_scale_codec::Decode;
use rand::Rng;
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
    substrate::{get_registered_details, query_chain, submit_transaction_with_pair},
    user::{
        self, get_all_signers_from_chain, get_validators_not_signer_for_relay, UserSignatureRequest,
    },
    Hasher,
};

use base64::prelude::{Engine, BASE64_STANDARD};
use entropy_protocol::RecoverableSignature;
use entropy_shared::HashingAlgorithm;
use futures::stream::StreamExt;
use sp_core::{
    sr25519::{self, Signature},
    Pair,
};
use subxt::{
    backend::legacy::LegacyRpcMethods,
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
) -> Result<([u8; VERIFYING_KEY_LENGTH], RegisteredInfo), ClientError> {
    let registration_event = put_register_request_on_chain(
        api,
        rpc,
        signature_request_keypair.clone(),
        program_account,
        programs_data,
    )
    .await?;

    let verifying_key = registration_event.1 .0;
    let registered_info = get_registered_details(api, rpc, verifying_key.clone()).await?;
    let verifying_key = verifying_key.try_into().map_err(|_| ClientError::BadVerifyingKeyLength)?;

    Ok((verifying_key, registered_info))
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

    let validators_info = get_validators_not_signer_for_relay(api, rpc).await?;
    if validators_info.is_empty() {
        return Err(ClientError::NoNonSigningValidators);
    }

    tracing::debug!("Validators info {:?}", validators_info);
    let block_number = rpc.chain_get_header(None).await?.ok_or(ClientError::BlockNumber)?.number;
    let signature_request = UserSignatureRequest {
        message: hex::encode(message),
        auxilary_data: Some(vec![auxilary_data.map(hex::encode)]),
        block_number,
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key: signature_verifying_key.to_vec(),
    };

    let signature_request_vec = serde_json::to_vec(&signature_request)?;
    let client = reqwest::Client::new();

    let mut rng = rand::thread_rng();
    let random_index = rng.gen_range(0..validators_info.len());
    let validator_info = &validators_info[random_index];

    // Make http request to TSS server
    let encrypted_message = EncryptedSignedMessage::new(
        &user_keypair,
        signature_request_vec.clone(),
        &validator_info.x25519_public_key,
        &[],
    )?;
    let message_json = serde_json::to_string(&encrypted_message)?;

    let url = format!("http://{}/user/relay_tx", validator_info.ip_address);

    let result = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(message_json)
        .send()
        .await?;

    let mut bytes_stream = result.bytes_stream();
    let chunk = bytes_stream.next().await.ok_or(ClientError::NoResponse)??;
    let signing_results: Vec<Result<(String, Signature), String>> = serde_json::from_slice(&chunk)?;
    // take only one of the responses randomly
    let mut rng = rand::thread_rng();
    let random_index = rng.gen_range(0..signing_results.len());
    let (signature_base64, signature_of_signature) =
        signing_results[random_index].clone().map_err(ClientError::SigningFailed)?;
    tracing::debug!("Signature: {}", signature_base64);
    let mut decoded_sig = BASE64_STANDARD.decode(signature_base64)?;

    // Verify the response signature from the TSS client
    let signers = get_all_signers_from_chain(api, rpc).await?;
    let mut sig_recovery_results = vec![];
    for signer_info in signers {
        let sig_recovery = <sr25519::Pair as Pair>::verify(
            &signature_of_signature,
            decoded_sig.clone(),
            &sr25519::Public(signer_info.tss_account.0),
        );
        sig_recovery_results.push(sig_recovery)
    }

    if !sig_recovery_results.contains(&true) {
        return Err(ClientError::BadSignature);
    }

    let recovery_digit = decoded_sig.pop().ok_or(ClientError::NoRecoveryId)?;
    let signature = k256Signature::from_slice(&decoded_sig)?;
    let recovery_id = RecoveryId::from_byte(recovery_digit).ok_or(ClientError::BadRecoveryId)?;

    let verifying_key_of_signature =
        VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)?;
    tracing::debug!("Verifying Key {:?}", verifying_key_of_signature);

    return Ok(RecoverableSignature { signature, recovery_id });
}

/// Store a program on chain and return it's hash
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    skip_all,
    fields(
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
    oracle_data_pointers: Vec<Vec<u8>>,
    version_number: u8,
) -> Result<<EntropyConfig as Config>::Hash, ClientError> {
    let set_program_tx = entropy::tx().programs().set_program(
        program,
        configuration_interface,
        auxiliary_data_interface,
        BoundedVec(oracle_data_pointers),
        version_number,
    );
    let in_block =
        submit_transaction_with_pair(api, rpc, deployer_pair, &set_program_tx, None).await?;
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

/// Removed a stored a program with a given hash
#[tracing::instrument(
    skip_all,
    fields(
        program_hash,
        deployer = ?deployer_pair.public(),
    )
)]
pub async fn remove_program(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    deployer_pair: &sr25519::Pair,
    program_hash: <EntropyConfig as Config>::Hash,
) -> Result<(), ClientError> {
    let remove_program_tx = entropy::tx().programs().remove_program(program_hash);
    let in_block =
        submit_transaction_with_pair(api, rpc, deployer_pair, &remove_program_tx, None).await?;

    let event = in_block
        .find_first::<entropy::programs::events::ProgramRemoved>()?
        .ok_or(ClientError::CannotConfirmProgramRemoved)?;

    if event.old_program_hash != program_hash {
        return Err(ClientError::CannotConfirmProgramRemoved);
    }
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
) -> Result<Vec<(H256, ProgramInfo)>, ClientError> {
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

/// Submits a transaction registering an account on-chain.
#[tracing::instrument(
    skip_all,
    fields(
        user_account = ?signature_request_keypair.public(),
    )
)]
pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signature_request_keypair: sr25519::Pair,
    deployer: SubxtAccountId32,
    program_instances: BoundedVec<ProgramInstance>,
) -> Result<entropy::registry::events::AccountRegistered, ClientError> {
    tracing::debug!("Registering an account using on-chain flow.");

    let registering_tx = entropy::tx().registry().register(deployer, program_instances);
    let registered_events =
        submit_transaction_with_pair(api, rpc, &signature_request_keypair, &registering_tx, None)
            .await?;

    // Note: In the case of the new registration flow we can have many registration events for a
    // single signature request account. We only care about the first one we find.
    let registered_event = registered_events
        .find::<entropy::registry::events::AccountRegistered>()
        .flatten()
        .find_map(|event| (event.0 == signature_request_keypair.public().0.into()).then_some(event))
        .ok_or(ClientError::NotRegistered);

    registered_event
}

/// Changes the endpoint of a validator, retrieving a TDX quote from the new endpoint internally
pub async fn get_quote_and_change_endpoint(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    validator_keypair: sr25519::Pair,
    new_endpoint: String,
) -> Result<EndpointChanged, ClientError> {
    let quote =
        reqwest::get(format!("http://{}/attest", new_endpoint)).await?.bytes().await?.to_vec();
    change_endpoint(api, rpc, validator_keypair, new_endpoint, quote).await
}

/// Changes the endpoint of a validator, with a TDX quote given as an argument
pub async fn change_endpoint(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    user_keypair: sr25519::Pair,
    new_endpoint: String,
    quote: Vec<u8>,
) -> Result<EndpointChanged, ClientError> {
    let change_endpoint_tx =
        entropy::tx().staking_extension().change_endpoint(new_endpoint.into(), quote);
    let in_block =
        submit_transaction_with_pair(api, rpc, &user_keypair, &change_endpoint_tx, None).await?;
    let result_event = in_block
        .find_first::<entropy::staking_extension::events::EndpointChanged>()?
        .ok_or(SubstrateError::NoEvent)?;
    Ok(result_event)
}

/// Changes the threshold account info of a validator
pub async fn change_threshold_accounts(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    user_keypair: sr25519::Pair,
    new_tss_account: SubxtAccountId32,
    new_x25519_public_key: [u8; 32],
    new_pck_certificate_chain: Vec<Vec<u8>>,
    quote: Vec<u8>,
) -> Result<ThresholdAccountChanged, ClientError> {
    let change_threshold_accounts = entropy::tx().staking_extension().change_threshold_accounts(
        new_tss_account,
        new_x25519_public_key,
        new_pck_certificate_chain,
        quote,
    );
    let in_block =
        submit_transaction_with_pair(api, rpc, &user_keypair, &change_threshold_accounts, None)
            .await?;
    let result_event = in_block
        .find_first::<entropy::staking_extension::events::ThresholdAccountChanged>()?
        .ok_or(SubstrateError::NoEvent)?;
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

/// An extrinsic to indicate to the chain that it should expect an attestation from the `signer` at
/// some point in the near future.
///
/// The returned `nonce` must be used when generating a `quote` for the chain.
///
/// This wraps [user::request_attestation] to convert the error to a [ClientError] consistant with
/// other functions in this module
#[tracing::instrument(
    skip_all,
    fields(
        attestee = ?attestee.public(),
    )
)]
pub async fn request_attestation(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    attestee: &sr25519::Pair,
) -> Result<[u8; 32], ClientError> {
    Ok(user::request_attestation(api, rpc, attestee).await?)
}

/// Get oracle data headings
/// This is useful for program developers to know what oracle data is available
pub async fn get_oracle_headings(
    api: &OnlineClient<EntropyConfig>,
    _rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<String>, ClientError> {
    let storage_address = entropy::storage().oracle().oracle_data_iter();
    let mut iter = api.storage().at_latest().await?.iter(storage_address).await?;
    let mut headings = Vec::new();
    while let Some(Ok(kv)) = iter.next().await {
        // Key is: storage_address || 128 bit hash || key
        let mut input = &kv.key_bytes[32 + 16 + 1..];
        let heading = String::decode(&mut input)?;
        headings.push(heading);
    }
    Ok(headings)
}

/// Retrieve a TDX quote using the currently configured endpoint associated with the given validator
/// ID
pub async fn get_tdx_quote(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    validator_stash: &SubxtAccountId32,
) -> Result<Vec<u8>, ClientError> {
    let query = entropy::storage().staking_extension().threshold_servers(validator_stash);
    let server_info = query_chain(&api, &rpc, query, None).await.unwrap().unwrap();

    let tss_endpoint = std::str::from_utf8(&server_info.endpoint)?.to_string();
    Ok(reqwest::get(format!("http://{}/attest", tss_endpoint)).await?.bytes().await?.to_vec())
}
