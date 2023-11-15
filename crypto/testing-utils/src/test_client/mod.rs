mod common;
use std::{
    str::FromStr,
    thread,
    time::{Duration, SystemTime},
};

pub use crate::chain_api::{get_api, get_rpc};
use anyhow::{anyhow, ensure};
pub use common::derive_static_secret;
use common::{get_current_subgroup_signers, Hasher, UserSignatureRequest};
use entropy_protocol::{
    user::{user_participates_in_dkg_protocol, user_participates_in_signing_protocol},
    KeyParams, RecoverableSignature, ValidatorInfo,
};
pub use entropy_shared::{KeyVisibility, SIGNING_PARTY_SIZE};
use futures::future::try_join_all;
use log::info;
use parity_scale_codec::Decode;
use sp_core::{
    crypto::{AccountId32, Ss58Codec},
    sr25519, Pair,
};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    tx::PairSigner,
    utils::{AccountId32 as SubxtAccountId32, Static},
    Config, OnlineClient,
};
use subxt_signer::SecretUri;
use synedrion::{
    k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey},
    KeyShare,
};
use x25519_chacha20poly1305::SignedMessage;

use crate::chain_api::{
    entropy, entropy::runtime_types::pallet_relayer::pallet::RegisteredInfo, *,
};

/// Register an account
pub async fn register(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    sig_req_seed_string: String,
    constraint_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    initial_program: Vec<u8>,
) -> anyhow::Result<(RegisteredInfo, Option<KeyShare<KeyParams>>)> {
    let sig_req_seed = SeedString::new(sig_req_seed_string);
    let sig_req_keypair: sr25519::Pair = sig_req_seed.clone().try_into()?;
    let sig_req_subxt_keypair: subxt_signer::sr25519::Keypair = sig_req_seed.try_into()?;
    info!("Signature request account: {}", hex::encode(sig_req_keypair.public().0));

    // Check if user is already registered
    let account_id32: AccountId32 = sig_req_keypair.public().into();
    let account_id: <EntropyConfig as Config>::AccountId = account_id32.into();
    let registered_query = entropy::storage().relayer().registered(account_id);

    let query_registered_status = api.storage().at_latest().await?.fetch(&registered_query).await;
    if let Some(registered_status) = query_registered_status? {
        return Err(anyhow!("Already registered {:?}", registered_status));
    }

    // Send register transaction
    put_register_request_on_chain(
        api,
        sig_req_keypair.clone(),
        constraint_account,
        key_visibility,
        initial_program,
    )
    .await?;

    // If registering with private key visibility, participate in the DKG protocol
    let keyshare_option = match key_visibility {
        KeyVisibility::Private(_x25519_pk) => {
            let x25519_secret = derive_static_secret(&sig_req_keypair);

            let block_number = rpc
                .chain_get_header(None)
                .await?
                .ok_or(anyhow!("Cannot get current block number"))?
                .number;

            let validators_info = get_dkg_committee(api, block_number).await?;
            Some(
                user_participates_in_dkg_protocol(
                    validators_info,
                    &sig_req_subxt_keypair,
                    &x25519_secret,
                )
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
pub async fn sign(
    api: &OnlineClient<EntropyConfig>,
    sig_req_seed_string: String,
    message: Vec<u8>,
    private: Option<KeyShare<KeyParams>>,
    auxilary_data: Option<Vec<u8>>,
) -> anyhow::Result<RecoverableSignature> {
    let sig_req_seed = SeedString::new(sig_req_seed_string);
    let sig_req_keypair: sr25519::Pair = sig_req_seed.clone().try_into()?;
    let sig_req_subxt_keypair: subxt_signer::sr25519::Keypair = sig_req_seed.clone().try_into()?;
    info!("Signature request account: {}", hex::encode(sig_req_keypair.public().0));

    let message_hash = Hasher::keccak(&message);
    let message_hash_hex = hex::encode(message_hash);
    let validators_info = get_current_subgroup_signers(api, &message_hash_hex).await?;
    info!("Validators info {:?}", validators_info);

    let generic_msg = UserSignatureRequest {
        message: hex::encode(message),
        auxilary_data: auxilary_data.map(|data| hex::encode(data)),
        validators_info: validators_info.clone(),
        timestamp: SystemTime::now(),
    };

    let user_transaction_request_vec = serde_json::to_vec(&generic_msg)?;
    let validators_info_clone = validators_info.clone();

    use sp_core_6::Pair;
    let (keypair_sp_core_6, _) =
        sp_core_6::sr25519::Pair::from_string_with_seed(&sig_req_seed.0, None)
            .map_err(|_| anyhow!("Could not create sr25519 keypair"))?;

    // Make http requests to tss servers
    let submit_transaction_requests = validators_info
        .iter()
        .map(|validator_info| async {
            let validator_public_key: x25519_dalek::PublicKey =
                validator_info.x25519_public_key.into();
            let signed_message = SignedMessage::new(
                &keypair_sp_core_6,
                &sp_core_6::Bytes(user_transaction_request_vec.clone()),
                &validator_public_key,
            )?;
            let signed_message_json = signed_message.to_json()?;

            let url = format!("http://{}/user/sign_tx", validator_info.ip_address);

            let client = reqwest::Client::new();
            let res = client
                .post(url)
                .header("Content-Type", "application/json")
                .body(signed_message_json)
                .send()
                .await;
            Ok::<_, anyhow::Error>(res)
        })
        .collect::<Vec<_>>();

    // If we have a keyshare, connect to tss servers
    let results = if let Some(keyshare) = private {
        let x25519_secret = derive_static_secret(&sig_req_keypair);

        let sig_uid = {
            let account_id32: AccountId32 = sig_req_keypair.public().into();
            let account_id_ss58 = account_id32.to_ss58check();
            format!("{account_id_ss58}_{message_hash_hex}")
        };
        let (validator_results, _own_result) = futures::future::join(
            try_join_all(submit_transaction_requests),
            user_participates_in_signing_protocol(
                &keyshare,
                &sig_uid,
                validators_info_clone,
                &sig_req_subxt_keypair,
                message_hash,
                &x25519_secret,
            ),
        )
        .await;
        validator_results?
    } else {
        try_join_all(submit_transaction_requests).await?
    };

    // Get the first result
    if let Some(res) = results.into_iter().next() {
        let mut output = res?;
        if output.status() != 200 {
            return Err(anyhow!("Signing failed: {}", output.text().await?));
        }

        let chunk = output.chunk().await?.ok_or(anyhow!("No response"))?;
        let signing_result: Result<(String, sr25519::Signature), String> =
            serde_json::from_slice(&chunk).unwrap();
        let (signature_base64, _signature_of_signature) =
            signing_result.map_err(|err| anyhow!(err))?;
        info!("Signature: {}", signature_base64);

        let mut decoded_sig = base64::decode(signature_base64)?;
        let recovery_digit = decoded_sig.pop().ok_or(anyhow!("Cannot get recovery digit"))?;
        let signature = k256Signature::from_slice(&decoded_sig)?;
        let recovery_id =
            RecoveryId::from_byte(recovery_digit).ok_or(anyhow!("Cannot create recovery id"))?;
        let recovery_key_from_sig =
            VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id).unwrap();
        info!("Verifying Key {:?}", recovery_key_from_sig);

        return Ok(RecoverableSignature { signature, recovery_id });
    }
    Err(anyhow!("No results to return"))
}

/// Update a program
pub async fn update_program(
    api: &OnlineClient<EntropyConfig>,
    sig_req_account: SubxtAccountId32,
    program_seed_string: String,
    program: Vec<u8>,
) -> anyhow::Result<()> {
    let program_seed = SeedString::new(program_seed_string);
    let program_keypair: sr25519::Pair = program_seed.try_into()?;

    let update_program_tx = entropy::tx().programs().update_program(sig_req_account, program);

    let program_modification_account =
        PairSigner::<EntropyConfig, sr25519::Pair>::new(program_keypair.clone());

    api.tx()
        .sign_and_submit_then_watch_default(&update_program_tx, &program_modification_account)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}

/// Get info on all registered accounts
pub async fn get_accounts(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> anyhow::Result<Vec<(Vec<u8>, RegisteredInfo)>> {
    let block_hash =
        rpc.chain_get_block_hash(None).await?.ok_or_else(|| anyhow!("Error getting block hash"))?;
    let keys = Vec::<()>::new();
    let storage_address = subxt::dynamic::storage("Relayer", "Registered", keys);
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    let mut accounts = Vec::new();
    while let Some(Ok((storage_key, account))) = iter.next().await {
        let decoded = account.into_encoded();
        let registered_info = RegisteredInfo::decode(&mut decoded.as_ref())?;
        let key = storage_key[storage_key.len() - 32..].to_vec();
        accounts.push((key, registered_info))
    }
    Ok(accounts)
}

// TODO this is not tested
/// Fund a given account with sudo
pub async fn fund_account(
    api: &OnlineClient<EntropyConfig>,
    root_keypair: sr25519::Pair,
    account_to_fund: AccountId32,
    amount: u128,
) -> anyhow::Result<()> {
    let root_account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(root_keypair);
    let sudo_tx = entropy::tx().balances().force_set_balance(account_to_fund.into(), amount);
    api.tx()
        .sign_and_submit_then_watch_default(&sudo_tx, &root_account)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}

// Submit a register transaction
async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keypair: sr25519::Pair,
    constraint_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    initial_program: Vec<u8>,
) -> anyhow::Result<()> {
    let sig_req_account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keypair);

    let registering_tx = entropy::tx().relayer().register(
        constraint_account,
        Static(key_visibility),
        initial_program,
    );

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &sig_req_account)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}

/// A string from which to generate a sr25519 keypair for test accounts
#[derive(Clone)]
struct SeedString(String);

impl SeedString {
    fn new(seed_string: String) -> Self {
        Self(if seed_string.starts_with("//") { seed_string } else { format!("//{}", seed_string) })
    }

    // fn seed(&self) -> anyhow::Result<[u8; 32]> {
    //     let (_, seed_option) = sr25519::Pair::from_string_with_seed(&seed_string.0, None)?;
    //     Ok(seed_option.ok_or(anyhow!("Could not get seed"))?)
    // }
}

impl TryFrom<SeedString> for sr25519::Pair {
    type Error = anyhow::Error;

    fn try_from(seed_string: SeedString) -> Result<Self, Self::Error> {
        let (keypair, _) = sr25519::Pair::from_string_with_seed(&seed_string.0, None)?;
        Ok(keypair)
    }
}

impl TryFrom<SeedString> for subxt_signer::sr25519::Keypair {
    type Error = anyhow::Error;

    fn try_from(seed_string: SeedString) -> Result<Self, Self::Error> {
        let uri = SecretUri::from_str(&seed_string.0)?;
        let keypair = subxt_signer::sr25519::Keypair::from_uri(&uri)?;
        Ok(keypair)
    }
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
