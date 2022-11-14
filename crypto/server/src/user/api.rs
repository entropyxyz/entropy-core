use bip39::{Language, Mnemonic};
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KvManager,
};
use log::info;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use substrate_common::SIGNING_PARTY_SIZE;
use subxt::{
    ext::{
        sp_core::{sr25519, Pair},
        sp_runtime::AccountId32,
    },
    tx::PairSigner,
    OnlineClient,
};
use tracing::instrument;
use zeroize::Zeroize;

use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
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
    let api = get_api(&config.endpoint).await?;
    println!("USER/NEW");
    // Verifies the message contains a valid sr25519 signature from the sender.
    let signed_msg: SignedMessage = msg.into_inner();
    if !signed_msg.verify() {
        println!("INVALID SIGNATURE");
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }

    let signer = get_signer(state).await?;
    // Checks if the user has registered onchain first.
    let key = signed_msg.account_id();
    let is_registering = is_registering(&api, &key).await?;
    if !is_registering {
        println!("REGISTER ONCHAIN FIRST");
        return Err(UserErr::NotRegistering("Register Onchain first"));
    }

    let decrypted_message = signed_msg.decrypt(signer.signer());
    match decrypted_message {
        Ok(v) => {
            // store new user data in kvdb
            let subgroup = get_subgroup(&api, &signer)
                .await?
                .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
            let reservation = state.kv().reserve_key(key.to_string()).await?;
            state.kv().put(reservation, v).await?;
            // TODO: Error handling really complex needs to be thought about.
            confirm_registered(&api, key, subgroup, &signer).await?;
        },
        Err(v) => {
            println!("FAILED TO DECRYPT");
            return Err(UserErr::Parse("failed decrypting message"));
        },
    }
    Ok(Status::Ok)
}

pub async fn is_registering(
    api: &OnlineClient<EntropyConfig>,
    who: &AccountId32,
) -> Result<bool, UserErr> {
    let is_registering_query = entropy::storage().relayer().registering(who);
    let is_registering = api.storage().fetch(&is_registering_query, None).await.unwrap();
    Ok(is_registering
        .ok_or_else(|| UserErr::NotRegistering("Register Onchain first"))?
        .is_registering)
}

// Returns PairSigner for this nodes threshold server.
// The PairSigner is stored as an encrypted mnemonic in the kvdb and
// is used for PKE and to submit extrensics on chain.
pub async fn get_signer(
    kv: &KvManager,
) -> Result<PairSigner<EntropyConfig, sr25519::Pair>, KvError> {
    let exists = kv.kv().exists("MNEMONIC").await?;
    let raw_m = kv.kv().get("MNEMONIC").await?;
    match core::str::from_utf8(&raw_m) {
        Ok(s) => match Mnemonic::from_phrase(s, Language::English) {
            Ok(m) => match <sr25519::Pair as Pair>::from_phrase(m.phrase(), None) {
                Ok(p) => Ok(PairSigner::<EntropyConfig, sr25519::Pair>::new(p.0)),
                Err(e) => Err(KvError::GetErr(InnerKvError::LogicalErr("SENSITIVE".to_owned()))),
            },
            Err(e) => Err(KvError::GetErr(InnerKvError::LogicalErr(e.to_string()))),
        },
        Err(e) => Err(KvError::GetErr(InnerKvError::LogicalErr(e.to_string()))),
    }
}

pub async fn get_subgroup(
    api: &OnlineClient<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<Option<u8>, UserErr> {
    let mut subgroup: Option<u8> = None;
    let threshold_address = signer.account_id();
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(threshold_address);
    let stash_address = api
        .storage()
        .fetch(&stash_address_query, None)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Stash Fetch Error"))?;
    // TODO: stash keys are broken up into subgroups....need to get stash key here from threshold
    for i in 0..SIGNING_PARTY_SIZE {
        let signing_group_addresses_query =
            entropy::storage().staking_extension().signing_groups(i as u8);
        let signing_group_addresses = api
            .storage()
            .fetch(&signing_group_addresses_query, None)
            .await?
            .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
        if signing_group_addresses.contains(&stash_address) {
            subgroup = Some(i as u8);
            break;
        }
    }
    Ok(subgroup)
}

pub async fn confirm_registered(
    api: &OnlineClient<EntropyConfig>,
    who: AccountId32,
    subgroup: u8,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(), subxt::error::Error> {
    // TODO error handling + return error
    // TODO fire and forget, or wait for in block maybe Ddos error
    // TODO: Understand this better, potentially use sign_and_submit_default
    // or other method under sign_and_*
    let registration_tx = entropy::tx().relayer().confirm_register(who, subgroup);
    let _ = api
        .tx()
        .sign_and_submit_then_watch_default(&registration_tx, signer)
        .await?
        .wait_for_in_block()
        .await?
        .wait_for_success()
        .await?;
    Ok(())
}
