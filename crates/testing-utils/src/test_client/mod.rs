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

//! Simple test client
pub use crate::chain_api::{get_api, get_rpc};
pub use entropy_protocol::{sign_and_encrypt::EncryptedSignedMessage, KeyParams};
use entropy_shared::HashingAlgorithm;
pub use entropy_shared::{KeyVisibility, SIGNING_PARTY_SIZE};
pub use synedrion::KeyShare;

use std::time::SystemTime;

use anyhow::{anyhow, ensure};
use entropy_protocol::{
    user::{user_participates_in_dkg_protocol, user_participates_in_signing_protocol},
    RecoverableSignature, ValidatorInfo,
};
use entropy_tss::{
    chain_api::{
        entropy,
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::{
            pallet_programs::pallet::ProgramInfo,
            pallet_registry::pallet::{ProgramInstance, RegisteredInfo},
        },
        EntropyConfig,
    },
    common::{get_current_subgroup_signers, Hasher, UserSignatureRequest},
    helpers::substrate::{query_chain, submit_transaction},
};
use futures::future;
use parity_scale_codec::Decode;
use sp_core::{crypto::AccountId32, sr25519, Pair};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    events::EventsClient,
    tx::PairSigner,
    utils::{AccountId32 as SubxtAccountId32, Static, H256},
    Config, OnlineClient,
};
use synedrion::k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey};
use x25519_dalek::StaticSecret;

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
) -> anyhow::Result<(RegisteredInfo, Option<KeyShare<KeyParams>>)> {
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
        KeyVisibility::Private(_x25519_pk) => {
            let x25519_secret_key = x25519_secret_key
                .ok_or(anyhow!("In private mode, an x25519 secret key must be given"))?;
            // TODO ensure!(the public key matches that from key_visibility)

            let block_number = rpc
                .chain_get_header(None)
                .await?
                .ok_or(anyhow!("Cannot get current block number"))?
                .number
                + 1;

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

    let account_id32: AccountId32 = signature_request_keypair.public().into();
    let account_id: <EntropyConfig as Config>::AccountId = account_id32.into();

    for _ in 0..50 {
        let block_hash = rpc.chain_get_block_hash(None).await.unwrap();
        let events = EventsClient::new(api.clone()).at(block_hash.unwrap()).await.unwrap();
        let registered_event = events.find::<entropy::registry::events::AccountRegistered>();
        for event in registered_event.flatten() {
            if event.0 == account_id {
                let registered_query = entropy::storage().registry().registered(&event.1);
                let registered_status =
                    query_chain(api, rpc, registered_query, block_hash).await.unwrap();
                if registered_status.is_some() {
                    // check if the event belongs to this user
                    return Ok((registered_status.unwrap(), keyshare_option));
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    Err(anyhow!("Timed out waiting for register confirmation"))
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
    signature_verifying_key: Vec<u8>,
    message: Vec<u8>,
    private: Option<(KeyShare<KeyParams>, StaticSecret)>,
    auxilary_data: Option<Vec<u8>>,
) -> anyhow::Result<RecoverableSignature> {
    let message_hash = Hasher::keccak(&message);
    let message_hash_hex = hex::encode(message_hash);
    let validators_info = get_current_subgroup_signers(api, rpc, &message_hash_hex).await?;
    tracing::debug!("Validators info {:?}", validators_info);

    let signature_request = UserSignatureRequest {
        message: hex::encode(message),
        auxilary_data: Some(vec![auxilary_data.map(hex::encode)]),
        validators_info: validators_info.clone(),
        timestamp: SystemTime::now(),
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key,
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
            Ok::<_, anyhow::Error>(res)
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
        let mut output = res?;
        ensure!(output.status() == 200, "Signing failed: {}", output.text().await?);

        let chunk = output.chunk().await?.ok_or(anyhow!("No response"))?;
        let signing_result: Result<(String, sr25519::Signature), String> =
            serde_json::from_slice(&chunk)?;
        let (signature_base64, signature_of_signature) =
            signing_result.map_err(|err| anyhow!(err))?;
        tracing::debug!("Signature: {}", signature_base64);
        let mut decoded_sig = base64::decode(signature_base64)?;

        // Verify the response signature from the TSS client
        ensure!(
            sr25519::Pair::verify(
                &signature_of_signature,
                &decoded_sig,
                &sr25519::Public(validators_info[0].tss_account.0),
            ),
            "Failed to verify response from TSS server"
        );

        let recovery_digit = decoded_sig.pop().ok_or(anyhow!("Cannot get recovery digit"))?;
        let signature = k256Signature::from_slice(&decoded_sig)?;
        let recovery_id =
            RecoveryId::from_byte(recovery_digit).ok_or(anyhow!("Cannot create recovery id"))?;

        let verifying_key_of_signature =
            VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id)?;
        tracing::debug!("Verifying Key {:?}", verifying_key_of_signature);

        return Ok(RecoverableSignature { signature, recovery_id });
    }
    Err(anyhow!("Failed to get responses from TSS servers"))
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
) -> anyhow::Result<<EntropyConfig as Config>::Hash> {
    let update_program_tx = entropy::tx().programs().set_program(
        program,
        configuration_interface,
        auxiliary_data_interface,
    );
    let deployer = PairSigner::<EntropyConfig, sr25519::Pair>::new(deployer_pair.clone());

    let in_block = submit_transaction(api, rpc, &deployer, &update_program_tx, None).await?;
    let result_event = in_block.find_first::<entropy::programs::events::ProgramCreated>()?;
    Ok(result_event.ok_or(anyhow!("Error getting program created event"))?.program_hash)
}

/// Update the program pointers associated with a given entropy account
pub async fn update_programs(
    entropy_api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    verifying_key: Vec<u8>,
    deployer_pair: &sr25519::Pair,
    program_instance: BoundedVec<ProgramInstance>,
) -> anyhow::Result<()> {
    let update_pointer_tx = entropy::tx()
        .registry()
        .change_program_instance(BoundedVec(verifying_key), program_instance);
    let deployer = PairSigner::<EntropyConfig, sr25519::Pair>::new(deployer_pair.clone());
    submit_transaction(entropy_api, rpc, &deployer, &update_pointer_tx, None).await?;
    Ok(())
}
/// Get info on all registered accounts
pub async fn get_accounts(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> anyhow::Result<Vec<([u8; 32], RegisteredInfo)>> {
    let block_hash =
        rpc.chain_get_block_hash(None).await?.ok_or_else(|| anyhow!("Error getting block hash"))?;
    let keys = Vec::<()>::new();
    let storage_address = subxt::dynamic::storage("Registry", "Registered", keys);
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    let mut accounts = Vec::new();
    while let Some(Ok((storage_key, account))) = iter.next().await {
        let decoded = account.into_encoded();
        let registered_info = RegisteredInfo::decode(&mut decoded.as_ref())?;
        let key: [u8; 32] = storage_key[storage_key.len() - 32..].try_into()?;
        accounts.push((key, registered_info))
    }
    Ok(accounts)
}

/// Get details of all stored programs
pub async fn get_programs(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> anyhow::Result<Vec<(H256, ProgramInfo<<EntropyConfig as Config>::AccountId>)>> {
    let block_hash =
        rpc.chain_get_block_hash(None).await?.ok_or_else(|| anyhow!("Error getting block hash"))?;
    let keys = Vec::<()>::new();
    let storage_address = subxt::dynamic::storage("Programs", "Programs", keys);
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    let mut programs = Vec::new();
    while let Some(Ok((storage_key, program))) = iter.next().await {
        let decoded = program.into_encoded();
        let program_info: ProgramInfo<<EntropyConfig as Config>::AccountId> =
            ProgramInfo::decode(&mut decoded.as_ref())?;
        let hash: [u8; 32] = storage_key[storage_key.len() - 32..].try_into()?;
        programs.push((H256(hash), program_info));
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
) -> anyhow::Result<()> {
    let signature_request_pair_signer =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(signature_request_keypair);

    let registering_tx =
        entropy::tx().registry().register(deployer, Static(key_visibility), program_instance);

    submit_transaction(api, rpc, &signature_request_pair_signer, &registering_tx, None).await?;
    Ok(())
}

/// Check that the verfiying key from a new signature matches that in the from the
/// on-chain registration info for a given account
pub async fn check_verifying_key(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    verifying_key: VerifyingKey,
) -> anyhow::Result<()> {
    let verifying_key_serialized = verifying_key.to_encoded_point(true).as_bytes().to_vec();

    // Get the verifying key associated with this account, if it exist return ok
    let registered_query =
        entropy::storage().registry().registered(BoundedVec(verifying_key_serialized));
    let query_registered_status = query_chain(api, rpc, registered_query, None).await;
    query_registered_status?.ok_or(anyhow!("User not registered"))?;
    Ok(())
}

/// Get the commitee of tss servers who will perform DKG for a given block number
async fn get_dkg_committee(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    block_number: u32,
) -> anyhow::Result<Vec<ValidatorInfo>> {
    let mut validators_info: Vec<ValidatorInfo> = vec![];

    for i in 0..SIGNING_PARTY_SIZE {
        let account_id = select_validator_from_subgroup(api, rpc, i as u8, block_number).await?;

        let threshold_address_query =
            entropy::storage().staking_extension().threshold_servers(account_id);
        let server_info = query_chain(api, rpc, threshold_address_query, None)
            .await?
            .ok_or(anyhow!("Stash Fetch Error"))?;
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
) -> anyhow::Result<SubxtAccountId32> {
    let subgroup_info_query = entropy::storage().staking_extension().signing_groups(signing_group);
    let mut subgroup_addresses = query_chain(api, rpc, subgroup_info_query, None)
        .await?
        .ok_or(anyhow!("Subgroup Fetch Error"))?;

    let address = loop {
        ensure!(!subgroup_addresses.is_empty(), "No synced validators");
        let selection: u32 = block_number % subgroup_addresses.len() as u32;
        let address = &subgroup_addresses[selection as usize];
        let is_validator_syned_query =
            entropy::storage().staking_extension().is_validator_synced(address);
        let is_synced = query_chain(api, rpc, is_validator_syned_query, None)
            .await?
            .ok_or(anyhow!("Cannot query whether validator is synced"))?;
        if !is_synced {
            subgroup_addresses.remove(selection as usize);
        } else {
            break address;
        }
    };
    Ok(address.clone())
}
