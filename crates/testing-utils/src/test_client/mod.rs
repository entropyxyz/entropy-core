//! Simple test client
pub use crate::chain_api::{get_api, get_rpc};
pub use entropy_protocol::KeyParams;
pub use entropy_shared::{KeyVisibility, SIGNING_PARTY_SIZE};
pub use synedrion::KeyShare;
pub use x25519_chacha20poly1305::derive_static_secret;

use std::{
    thread,
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, ensure};
use entropy_protocol::{
    user::{user_participates_in_dkg_protocol, user_participates_in_signing_protocol},
    RecoverableSignature, ValidatorInfo,
};
use entropy_tss::{
    chain_api::{
        entropy, entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::pallet_relayer::pallet::RegisteredInfo, EntropyConfig,
    },
    common::{get_current_subgroup_signers, Hasher, UserSignatureRequest},
};
use futures::future;
use parity_scale_codec::Decode;
use sp_core::{crypto::AccountId32, sr25519, Bytes, Pair};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    tx::{PairSigner, Signer},
    utils::{AccountId32 as SubxtAccountId32, Static, H256},
    Config, OnlineClient,
};
use synedrion::k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey};
use x25519_chacha20poly1305::SignedMessage;

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
    program_hashes: BoundedVec<H256>,
) -> anyhow::Result<(RegisteredInfo, Option<KeyShare<KeyParams>>)> {
    // Check if user is already registered
    let account_id32: AccountId32 = signature_request_keypair.public().into();
    let account_id: <EntropyConfig as Config>::AccountId = account_id32.into();
    let registered_query = entropy::storage().relayer().registered(account_id);

    let query_registered_status = api.storage().at_latest().await?.fetch(&registered_query).await;
    if let Some(registered_status) = query_registered_status? {
        return Err(anyhow!("Already registered {:?}", registered_status));
    }

    // Send register transaction
    put_register_request_on_chain(
        api,
        signature_request_keypair.clone(),
        program_account,
        key_visibility,
        program_hashes,
    )
    .await?;

    // If registering with private key visibility, participate in the DKG protocol
    let keyshare_option = match key_visibility {
        KeyVisibility::Private(_x25519_pk) => {
            let block_number = rpc
                .chain_get_header(None)
                .await?
                .ok_or(anyhow!("Cannot get current block number"))?
                .number;

            let validators_info = get_dkg_committee(api, block_number + 1).await?;
            Some(
                user_participates_in_dkg_protocol(validators_info, &signature_request_keypair)
                    .await?,
            )
        },
        _ => None,
    };

    // Wait until user is confirmed as registered
    for _ in 0..50 {
        let query_registered_status =
            api.storage().at_latest().await?.fetch(&registered_query).await;
        if let Some(registered_status) = query_registered_status? {
            return Ok((registered_status, keyshare_option));
        }
        thread::sleep(Duration::from_millis(1000));
    }
    Err(anyhow!("Timed out waiting for register confirmation"))
}

/// Request to sign a message
#[tracing::instrument(
    skip_all,
    fields(
        signature_request_account = ?signature_request_keypair.public(),
        message,
        private,
        auxilary_data,
    )
)]
pub async fn sign(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signature_request_keypair: sr25519::Pair,
    message: Vec<u8>,
    private: Option<KeyShare<KeyParams>>,
    auxilary_data: Option<Vec<u8>>,
) -> anyhow::Result<RecoverableSignature> {
    let message_hash = Hasher::keccak(&message);
    let message_hash_hex = hex::encode(message_hash);
    let validators_info = get_current_subgroup_signers(api, rpc, &message_hash_hex).await?;
    tracing::debug!("Validators info {:?}", validators_info);

    let signature_request = UserSignatureRequest {
        message: hex::encode(message),
        auxilary_data: auxilary_data.map(hex::encode),
        validators_info: validators_info.clone(),
        timestamp: SystemTime::now(),
    };

    let signature_request_vec = serde_json::to_vec(&signature_request)?;
    let validators_info_clone = validators_info.clone();
    let client = reqwest::Client::new();

    // Make http requests to TSS servers
    let submit_transaction_requests = validators_info
        .iter()
        .map(|validator_info| async {
            let validator_public_key: x25519_dalek::PublicKey =
                validator_info.x25519_public_key.into();
            let signed_message = SignedMessage::new(
                &signature_request_keypair,
                &Bytes(signature_request_vec.clone()),
                &validator_public_key,
            )?;
            let signed_message_json = signed_message.to_json()?;

            let url = format!("http://{}/user/sign_tx", validator_info.ip_address);

            let res = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(signed_message_json)
                .send()
                .await;
            Ok::<_, anyhow::Error>(res)
        })
        .collect::<Vec<_>>();

    // If we have a keyshare, connect to TSS servers
    let results = if let Some(keyshare) = private {
        let (validator_results, _own_result) = future::join(
            future::try_join_all(submit_transaction_requests),
            user_participates_in_signing_protocol(
                &keyshare,
                validators_info_clone,
                &signature_request_keypair,
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

/// Set or update the program associated with a given entropy account
#[tracing::instrument(
    skip_all,
    fields(
        signature_request_account,
        program_modification_account = ?program_modification_keypair.public(),
    )
)]
pub async fn update_program(
    api: &OnlineClient<EntropyConfig>,
    program_modification_keypair: &sr25519::Pair,
    program: Vec<u8>,
) -> anyhow::Result<<EntropyConfig as Config>::Hash> {
    let update_program_tx = entropy::tx().programs().set_program(program);
    let program_modification_account =
        PairSigner::<EntropyConfig, sr25519::Pair>::new(program_modification_keypair.clone());

    let in_block = api
        .tx()
        .sign_and_submit_then_watch_default(&update_program_tx, &program_modification_account)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;

    let result_event = in_block.find_first::<entropy::programs::events::ProgramCreated>()?;
    Ok(result_event.ok_or(anyhow!("Error getting program created event"))?.program_hash)
}

/// Set or update pointer with a given entropy account
pub async fn update_pointer(
    entropy_api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signature_request_account: &sr25519::Pair,
    pointer_modification_account: &sr25519::Pair,
    program_hashes: BoundedVec<<EntropyConfig as Config>::Hash>,
) -> anyhow::Result<()> {
    let block_hash =
        rpc.chain_get_block_hash(None).await?.ok_or_else(|| anyhow!("Error getting block hash"))?;

    let update_pointer_tx = entropy::tx()
        .relayer()
        .change_program_pointer(signature_request_account.public().into(), program_hashes);

    let account_id32: AccountId32 = pointer_modification_account.public().into();
    let account_id: <EntropyConfig as Config>::AccountId = account_id32.into();

    let nonce_call = entropy::apis().account_nonce_api().account_nonce(account_id.clone());
    let nonce = entropy_api.runtime_api().at(block_hash).call(nonce_call).await?;

    let pointer_modification_account =
        PairSigner::<EntropyConfig, sr25519::Pair>::new(pointer_modification_account.clone());

    let partial_tx = entropy_api
        .tx()
        .create_partial_signed_with_nonce(&update_pointer_tx, nonce.into(), Default::default())
        .unwrap();
    let signer_payload = partial_tx.signer_payload();
    let signature = pointer_modification_account.sign(&signer_payload);

    let tx = partial_tx.sign_with_address_and_signature(&account_id.into(), &signature);

    tx.submit_and_watch().await?.wait_for_in_block().await?.wait_for_success().await?;
    Ok(())
}
/// Get info on all registered accounts
pub async fn get_accounts(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> anyhow::Result<Vec<(SubxtAccountId32, RegisteredInfo)>> {
    let block_hash =
        rpc.chain_get_block_hash(None).await?.ok_or_else(|| anyhow!("Error getting block hash"))?;
    let keys = Vec::<()>::new();
    let storage_address = subxt::dynamic::storage("Relayer", "Registered", keys);
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    let mut accounts = Vec::new();
    while let Some(Ok((storage_key, account))) = iter.next().await {
        let decoded = account.into_encoded();
        let registered_info = RegisteredInfo::decode(&mut decoded.as_ref())?;
        let key: [u8; 32] = storage_key[storage_key.len() - 32..].try_into()?;
        accounts.push((SubxtAccountId32(key), registered_info))
    }
    Ok(accounts)
}

/// Submit a register transaction
pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    signature_request_keypair: sr25519::Pair,
    program_modification_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    program_hashes: BoundedVec<H256>,
) -> anyhow::Result<()> {
    let signature_request_pair_signer =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(signature_request_keypair);

    let registering_tx = entropy::tx().relayer().register(
        program_modification_account,
        Static(key_visibility),
        program_hashes,
    );

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &signature_request_pair_signer)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}

/// Check that the verfiying key from a new signature matches that in the from the
/// on-chain registration info for a given account
pub async fn check_verifying_key(
    api: &OnlineClient<EntropyConfig>,
    public_key: sr25519::Public,
    verifying_key: VerifyingKey,
) -> anyhow::Result<()> {
    let verifying_key_serialized = verifying_key.to_encoded_point(true).as_bytes().to_vec();

    // Get the verifying key associated with this account
    let registered_status = {
        let account_id32: AccountId32 = public_key.into();
        let account_id: <EntropyConfig as Config>::AccountId = account_id32.into();
        let registered_query = entropy::storage().relayer().registered(account_id);
        let query_registered_status =
            api.storage().at_latest().await?.fetch(&registered_query).await;
        query_registered_status?.ok_or(anyhow!("User not registered"))?
    };

    Ok(ensure!(registered_status.verifying_key.0 == verifying_key_serialized))
}

/// Get the commitee of tss servers who will perform DKG for a given block number
async fn get_dkg_committee(
    api: &OnlineClient<EntropyConfig>,
    block_number: u32,
) -> anyhow::Result<Vec<ValidatorInfo>> {
    let mut validators_info: Vec<ValidatorInfo> = vec![];

    for i in 0..SIGNING_PARTY_SIZE {
        let account_id = select_validator_from_subgroup(api, i as u8, block_number).await?;

        let threshold_address_query =
            entropy::storage().staking_extension().threshold_servers(account_id);
        let server_info = api
            .storage()
            .at_latest()
            .await?
            .fetch(&threshold_address_query)
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
    signing_group: u8,
    block_number: u32,
) -> anyhow::Result<SubxtAccountId32> {
    let subgroup_info_query = entropy::storage().staking_extension().signing_groups(signing_group);
    let mut subgroup_addresses = api
        .storage()
        .at_latest()
        .await?
        .fetch(&subgroup_info_query)
        .await?
        .ok_or(anyhow!("Subgroup Fetch Error"))?;

    let address = loop {
        ensure!(!subgroup_addresses.is_empty(), "No synced validators");
        let selection: u32 = block_number % subgroup_addresses.len() as u32;
        let address = &subgroup_addresses[selection as usize];
        let is_validator_syned_query =
            entropy::storage().staking_extension().is_validator_synced(address);
        let is_synced = api
            .storage()
            .at_latest()
            .await?
            .fetch(&is_validator_syned_query)
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
