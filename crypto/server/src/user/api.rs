use bip39::{Language, Mnemonic};
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KvManager,
};
use log::info;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use sp_core::{sr25519, Pair};
use substrate_common::SIGNING_PARTY_SIZE;
use subxt::{sp_runtime::AccountId32, DefaultConfig, PairSigner};
use tracing::instrument;
use zeroize::Zeroize;

use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{entropy, get_api, EntropyRuntime},
    message::SignedMessage,
    signing_client::SignerState,
    Configuration,
};

/// Add a new Keyshare to this node's set of known Keyshares. Store in kvdb.
#[post("/new", format = "json", data = "<msg>")]
pub async fn new_user(
    msg: Json<SignedMessage>,
    state: &State<KvManager>,
    config: &State<Configuration>,
) -> Result<Status, UserErr> {
    let api = get_api(&config.endpoint).await.unwrap();

    // Verifies the message contains a valid sr25519 signature from the sender.
    let signed_msg: SignedMessage = msg.into_inner();
    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }

    let signer = get_signer(state).await.unwrap();
    // Checks if the user has registered onchain first.
    let key = signed_msg.account_id();
    let is_registering = is_registering(&api, &key).await.unwrap();
    if !is_registering {
        return Err(UserErr::NotRegistering("Register Onchain first"));
    }

    println!("Updating threshold key for: {}", key.to_string());

    // store new user data in kvdb
    let reservation = state.kv().reserve_key(key.to_string()).await?;
    let decrypted_message = signed_msg.decrypt(signer.signer());
    match decrypted_message {
        Ok(v) => {
            state.kv().put(reservation, v).await?;
            let subgroup = get_subgroup(&api, &signer).await.unwrap().unwrap();
            // TODO: Error handling really complex needs to be thought about.
            confirm_registered(&api, key, subgroup, &signer).await.unwrap();
        },
        Err(v) => {
            return Err(UserErr::Parse("failed decrypting message"));
        },
    }
    Ok(Status::Ok)
}

pub async fn is_registering(api: &EntropyRuntime, who: &AccountId32) -> Result<bool, UserErr> {
    let is_registering = api.storage().relayer().registering(who, None).await.unwrap();
    if is_registering.is_none() {
        return Err(UserErr::NotRegistering("Register Onchain first"));
    }
    Ok(is_registering.unwrap().is_registering)
}

// Returns PairSigner for this nodes threshold server.
// The PairSigner is stored as an encrypted mnemonic in the kvdb and
// is used for PKE and to submit extrensics on chain.
pub async fn get_signer(
    kv: &KvManager,
) -> Result<subxt::PairSigner<DefaultConfig, sr25519::Pair>, KvError> {
    let exists = kv.kv().exists("MNEMONIC").await?;
    let raw_m = kv.kv().get("MNEMONIC").await?;
    match core::str::from_utf8(&raw_m) {
        Ok(s) => match Mnemonic::from_phrase(s, Language::English) {
            Ok(m) => match <sr25519::Pair as Pair>::from_phrase(m.phrase(), None) {
                Ok(p) => Ok(PairSigner::<DefaultConfig, sr25519::Pair>::new(p.0)),
                Err(e) => Err(KvError::GetErr(InnerKvError::LogicalErr("SENSITIVE".to_owned()))),
            },
            Err(e) => Err(KvError::GetErr(InnerKvError::LogicalErr(e.to_string()))),
        },
        Err(e) => Err(KvError::GetErr(InnerKvError::LogicalErr(e.to_string()))),
    }
}

pub async fn get_subgroup(
    api: &EntropyRuntime,
    signer: &subxt::PairSigner<DefaultConfig, sr25519::Pair>,
) -> Result<Option<u8>, subxt::Error<entropy::DispatchError>> {
    let mut subgroup: Option<u8> = None;
    let address = signer.account_id();
    for i in 0..SIGNING_PARTY_SIZE {
        let signing_group_addresses =
            api.storage().staking_extension().signing_groups(&(i as u8), None).await?.unwrap();
        if signing_group_addresses.contains(address) {
            subgroup = Some(i as u8);
            break;
        }
    }
    Ok(subgroup)
}

pub async fn confirm_registered(
    api: &EntropyRuntime,
    who: AccountId32,
    subgroup: u8,
    signer: &subxt::PairSigner<DefaultConfig, sr25519::Pair>,
) -> Result<(), subxt::Error<entropy::DispatchError>> {
    // TODO error handling + return error
    // TODO fire and forget, or wait for in block maybe Ddos error
    let _ = api.tx().relayer()
        .confirm_register(who, subgroup)
        // TODO: Understand this better, potentially use sign_and_submit_default
        // or other method under sign_and_*
        .sign_and_submit_then_watch_default(signer).await?
        .wait_for_in_block().await?
        .wait_for_success().await?;
    Ok(())
}
