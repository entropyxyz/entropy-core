mod validation;
use std::{sync::Arc, time::SystemTime};

use anyhow::anyhow;
use entropy_protocol::ValidatorInfo;
use entropy_shared::SIGNING_PARTY_SIZE;
use futures::future::{join_all, try_join_all};
use num::{bigint::BigInt, Num, ToPrimitive};
use serde::{Deserialize, Serialize};
use sp_core::{crypto::AccountId32, sr25519, Bytes, Pair};
use subxt::{tx::PairSigner, utils::AccountId32 as SubxtAccountId32, Config, OnlineClient};
use synedrion::k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey};
use validation::SignedMessage;
use x25519_dalek::PublicKey;

pub use crate::chain_api::entropy::runtime_types::entropy_shared::{
    constraints::Constraints, types::KeyVisibility,
};
use crate::chain_api::{entropy::runtime_types::pallet_relayer::pallet::RegisteredInfo, *};

/// Get the Entropy api
pub async fn get_api(ws_url: String) -> anyhow::Result<OnlineClient<EntropyConfig>> {
    Ok(OnlineClient::<EntropyConfig>::from_url(ws_url.clone()).await?)
}

/// Register an account
pub async fn register(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keypair: sr25519::Pair,
    constraint_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    initial_program: Option<Constraints>,
) -> anyhow::Result<RegisteredInfo> {
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

    // Wait until user is confirmed as registered
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let query_registered_status =
            api.storage().at_latest().await?.fetch(&registered_query).await;
        if let Some(registered_status) = query_registered_status? {
            return Ok(registered_status);
        }
    }
    Err(anyhow!("Timed out waiting for register confirmation"))
}

/// Request to sign a message
pub async fn sign(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keypair: sr25519::Pair,
    message: Vec<u8>,
) -> anyhow::Result<()> {
    let message_hash = Hasher::keccak(&message);
    let message_hash_hex = hex::encode(message_hash);
    let validators_info = get_current_subgroup_signers(api, &message_hash_hex).await?;
    println!("Validators info {:?}", validators_info);
    let generic_msg = UserTransactionRequest {
        transaction_request: hex::encode(message),
        validators_info: validators_info.clone(),
        timestamp: SystemTime::now(),
    };

    let user_transaction_request_vec = serde_json::to_vec(&generic_msg)?;

    let submit_transaction_requests = validators_info
        .iter()
        .map(|validator_info| async {
            let server_public_key = PublicKey::from(validator_info.x25519_public_key);
            let signed_message = SignedMessage::new(
                &sig_req_keypair.clone(),
                &Bytes(user_transaction_request_vec.clone()),
                &server_public_key,
            )
            .unwrap();
            let url = format!("http://{}/user/sign_tx", validator_info.ip_address.to_string());

            let mock_client = reqwest::Client::new();
            let res = mock_client
                .post(url)
                .header("Content-Type", "application/json")
                .body(serde_json::to_string(&signed_message).unwrap())
                .send()
                .await;
            println!("sent a request");
            Ok::<_, anyhow::Error>(res)
        })
        .collect::<Vec<_>>();

    let results = try_join_all(submit_transaction_requests).await?;
    println!("Got all results");

    for res in results {
        let mut output = res?;
        if output.status() != 200 {
            println!("output {}", output.text().await?);
            return Err(anyhow!("Signing failed"));
        }

        let chunk = output.chunk().await?.ok_or(anyhow!("No response"))?;
        let signing_result: Result<(String, sr25519::Signature), String> =
            serde_json::from_slice(&chunk).unwrap();
        let (signature_base64, _signature_of_signature) =
            signing_result.map_err(|err| anyhow!(err))?;
        println!("Signature: {}", signature_base64);
        let mut decoded_sig = base64::decode(signature_base64)?;
        let recovery_digit = decoded_sig.pop().ok_or(anyhow!("Cannot get recovery digit"))?;
        let signature = k256Signature::from_slice(&decoded_sig)?;
        let recover_id =
            RecoveryId::from_byte(recovery_digit).ok_or(anyhow!("Cannot create recovery id"))?;
        let recovery_key_from_sig =
            VerifyingKey::recover_from_prehash(&message_hash, &signature, recover_id).unwrap();
        println!("Verifying Key {:?}", recovery_key_from_sig);
        // let mnemonic = if i == 0 { DEFAULT_MNEMONIC } else { DEFAULT_BOB_MNEMONIC };
        // let sk = <sr25519::Pair as Pair>::from_string(mnemonic, None).unwrap();
        // let sig_recovery = <sr25519::Pair as Pair>::verify(
        //     &signing_result.clone().unwrap().1,
        //     base64::decode(signing_result.unwrap().0).unwrap(),
        //     &sr25519::Public(sk.public().0),
        // );
        // assert!(sig_recovery);
    }
    Ok(())
}

/// Update a program
pub async fn update_program(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keypair: sr25519::Pair,
    program_keypair: sr25519::Pair,
    program: Vec<u8>,
) -> anyhow::Result<()> {
    let update_program_tx = entropy::tx()
        .constraints()
        .update_v2_constraints(SubxtAccountId32::from(sig_req_keypair.public()), program);

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

async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keypair: sr25519::Pair,
    constraint_account: SubxtAccountId32,
    key_visibility: KeyVisibility,
    initial_program: Option<Constraints>,
) -> anyhow::Result<()> {
    let sig_req_account = PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keypair);

    let registering_tx =
        entropy::tx().relayer().register(constraint_account, key_visibility, initial_program);

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &sig_req_account)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UserTransactionRequest {
    /// Hex-encoded raw data to be signed (eg. RLP-serialized Ethereum transaction)
    pub transaction_request: String,
    /// Information from the validators in signing party
    pub validators_info: Vec<ValidatorInfo>,
    /// When the message was created and signed
    pub timestamp: SystemTime,
}

/// Gets the current signing committee
/// The signing committee is composed as the validators at the index into each subgroup
/// Where the index is computed as the user's sighash as an integer modulo the number of subgroups
pub async fn get_current_subgroup_signers(
    api: &OnlineClient<EntropyConfig>,
    sig_hash: &str,
) -> anyhow::Result<Vec<ValidatorInfo>> {
    let mut subgroup_signers = vec![];
    let number = Arc::new(BigInt::from_str_radix(sig_hash, 16)?);
    let futures = (0..SIGNING_PARTY_SIZE)
        .map(|i| {
            let owned_number = Arc::clone(&number);
            async move {
                let subgroup_info_query =
                    entropy::storage().staking_extension().signing_groups(i as u8);
                let subgroup_info = api
                    .storage()
                    .at_latest()
                    .await?
                    .fetch(&subgroup_info_query)
                    .await?
                    .ok_or(anyhow!("Subgroup Fetch Error"))?;

                let index_of_signer_big = &*owned_number % subgroup_info.len();
                let index_of_signer =
                    index_of_signer_big.to_usize().ok_or(anyhow!("Usize error"))?;

                let threshold_address_query = entropy::storage()
                    .staking_extension()
                    .threshold_servers(subgroup_info[index_of_signer].clone());
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
                Ok::<_, anyhow::Error>(validator_info)
            }
        })
        .collect::<Vec<_>>();
    let results = join_all(futures).await;
    for result in results.into_iter() {
        subgroup_signers.push(result?);
    }
    Ok(subgroup_signers)
}

/// Produces a specific hash on a given message
pub struct Hasher;

impl Hasher {
    /// Produces the Keccak256 hash on a given message.
    ///
    /// In practice, if `data` is an RLP-serialized Ethereum transaction, this should produce the
    /// corrosponding .
    pub fn keccak(data: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};

        let mut keccak = Keccak256::new();
        keccak.update(data);
        keccak.finalize().into()
    }
}

// pub fn seed_from_string(input: String) -> [u8; 32] {
//     let mut buffer: [u8; 32] = [0; 32];
//     let mut hasher = Blake2s256::new();
//     hasher.update(input.as_bytes());
//     let hash = hasher.finalize().to_vec();
//     buffer.copy_from_slice(&hash);
//     buffer
// }

// let sudo_tx = entropy::tx().balances().force_set_balance(account_id32.into(), 9);
// api.tx().sudo().sign_and_submit_then_watch_default();
