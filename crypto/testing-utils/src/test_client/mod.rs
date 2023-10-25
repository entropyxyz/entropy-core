mod common;
use std::{str::FromStr, time::SystemTime};

use anyhow::{anyhow, ensure};
pub use common::derive_static_secret;
use common::{get_current_subgroup_signers, Hasher, UserTransactionRequest};
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
    tx::PairSigner,
    utils::{AccountId32 as SubxtAccountId32, Static},
    Config, OnlineClient,
};
use subxt_signer::SecretUri;
use synedrion::{
    k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey},
    KeyShare,
};
use x25519_chacha20poly1305::encrypt_and_sign;

pub use crate::chain_api::entropy::runtime_types::entropy_shared::constraints::Constraints;
use crate::chain_api::{
    entropy, entropy::runtime_types::pallet_relayer::pallet::RegisteredInfo, *,
};

/// Get the Entropy api
pub async fn get_api(ws_url: String) -> anyhow::Result<OnlineClient<EntropyConfig>> {
    Ok(OnlineClient::<EntropyConfig>::from_url(ws_url.clone()).await?)
}

/// Register an account
pub async fn register(
    api: &OnlineClient<EntropyConfig>,
    sig_req_seed_string: String,
    constraint_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    initial_program: Option<Constraints>,
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
            let block_number = api
                .rpc()
                .block(None)
                .await?
                .ok_or(anyhow!("Cannot get current block number"))?
                .block
                .header
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
    for _ in 0..20 {
        let query_registered_status =
            api.storage().at_latest().await?.fetch(&registered_query).await;
        if let Some(registered_status) = query_registered_status? {
            return Ok((registered_status, keyshare_option));
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    Err(anyhow!("Timed out waiting for register confirmation"))
}

/// Request to sign a message
pub async fn sign(
    api: &OnlineClient<EntropyConfig>,
    sig_req_seed_string: String,
    message: Vec<u8>,
    private: Option<KeyShare<KeyParams>>,
) -> anyhow::Result<RecoverableSignature> {
    let sig_req_seed = SeedString::new(sig_req_seed_string);
    let sig_req_keypair: sr25519::Pair = sig_req_seed.clone().try_into()?;
    let sig_req_subxt_keypair: subxt_signer::sr25519::Keypair = sig_req_seed.try_into()?;
    info!("Signature request account: {}", hex::encode(sig_req_keypair.public().0));

    let message_hash = Hasher::keccak(&message);
    let message_hash_hex = hex::encode(message_hash);
    let validators_info = get_current_subgroup_signers(api, &message_hash_hex).await?;
    info!("Validators info {:?}", validators_info);

    let generic_msg = UserTransactionRequest {
        transaction_request: hex::encode(message),
        validators_info: validators_info.clone(),
        timestamp: SystemTime::now(),
    };

    let user_transaction_request_vec = serde_json::to_vec(&generic_msg)?;
    let validators_info_clone = validators_info.clone();

    // Make http requests to tss servers
    let submit_transaction_requests = validators_info
        .iter()
        .map(|validator_info| async {
            let signed_message_json = encrypt_and_sign(
                sig_req_keypair.to_raw_vec(),
                user_transaction_request_vec.clone(),
                validator_info.x25519_public_key.to_vec(),
            )
            .map_err(|js_err| {
                anyhow!(js_err
                    .as_string()
                    .unwrap_or("encrypt_and_sign gives bad JS error".to_string()))
            })?;
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

    let update_program_tx =
        entropy::tx().constraints().update_v2_constraints(sig_req_account, program);

    let constraint_modification_account =
        PairSigner::<EntropyConfig, sr25519::Pair>::new(program_keypair.clone());

    api.tx()
        .sign_and_submit_then_watch_default(&update_program_tx, &constraint_modification_account)
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
) -> anyhow::Result<Vec<(Vec<u8>, RegisteredInfo)>> {
    let storage_address = subxt::dynamic::storage_root("Relayer", "Registered");
    let batch_size = 100;
    let mut iter =
        api.storage().at_latest().await?.iter(storage_address, batch_size as u32).await?;
    let mut accounts = Vec::new();
    while let Some((storage_key, account)) = iter.next().await? {
        let decoded = account.into_encoded();
        let registered_info = RegisteredInfo::decode(&mut decoded.as_ref())?;
        let key = storage_key.0[storage_key.0.len() - 32..].to_vec();
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

// pub async fn transfer_balance() {
// let pair = sp_core::sr25519::Pair::from_string(&mnemonic_phrase_A, None).unwrap();
// let account_A = PairSigner::new(pair);
//
// let balance_transfer_tx = entropy::tx().balances().transfer(account_B, 10_000);
//
//     let events = api
//         .tx()
//         .sign_and_submit_then_watch_default(&balance_transfer_tx, &account_A)
//         .await?
//         .wait_for_finalized_success()
//         .await?;
// }

// Submit a register transaction
async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keypair: sr25519::Pair,
    constraint_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    initial_program: Option<Constraints>,
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
            ip_address: std::str::from_utf8(&server_info.endpoint)?.parse()?,
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
