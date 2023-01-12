use bip39::{Language, Mnemonic};
use entropy_constraints::tx::evm::EVM;
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KvManager,
};
use log::info;
use rocket::{
    http::Status,
    response::stream::EventStream,
    serde::json::{to_string, Json},
    Shutdown, State,
};
use serde::{Deserialize, Serialize};
use serde_derive::{Deserialize as DeserializeDerive, Serialize as SerializeDerive};
use substrate_common::{
    types::{ACLConstraint, Architecture, BasicTransaction, ACL},
    SIGNING_PARTY_SIZE,
};
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EVMUserTx {
    tx: BasicTransaction<EVM>,
    hash: String,
}

/// TODO: Add block based removal for unsigned transactions in the KVDB.
/// https://github.com/entropyxyz/entropy-core/issues/248
/// Maps a tx hash -> unsigned transaction in the kvdb.
#[post("/tx", format = "json", data = "<tx>")]
pub async fn store_tx(
    tx: Json<EVMUserTx>,
    state: &State<KvManager>,
    config: &State<Configuration>,
) -> Result<Status, UserErr> {
    // TODO: the type used for transactions in the constraints lib
    // does not contain all the fields of an actual ETH transaction
    // so we don't have a way to validate the hash.
    if tx.hash.len() != 64 {
        return Err(UserErr::Parse("hash.len() != 64"));
    }
    let val = serde_json::to_string(&tx.clone().0)?.into_bytes();
    let reservation = state.kv().reserve_key(tx.hash.clone()).await?;
    state.kv().put(reservation, val).await?;
    Ok(Status::Ok)
}
/// Add a new Keyshare to this node's set of known Keyshares. Store in kvdb.
#[post("/new", format = "json", data = "<msg>")]
pub async fn new_user(
    msg: Json<SignedMessage>,
    state: &State<KvManager>,
    config: &State<Configuration>,
) -> Result<Status, UserErr> {
    let api = get_api(&config.endpoint).await?;
    // Verifies the message contains a valid sr25519 signature from the sender.
    let signed_msg: SignedMessage = msg.into_inner();
    if !signed_msg.verify() {
        return Err(UserErr::InvalidSignature("Invalid signature."));
    }

    let signer = get_signer(state).await?;
    // Checks if the user has registered onchain first.
    let key = signed_msg.account_id();
    let is_registering = register_info(&api, &key, true).await?;
    let is_swapping = register_info(&api, &key, false).await?;

    let decrypted_message = signed_msg.decrypt(signer.signer());
    match decrypted_message {
        Ok(v) => {
            // store new user data in kvdb or deletes and replaces it if swapping
            let subgroup = get_subgroup(&api, &signer)
                .await?
                .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
            if is_swapping {
                state.kv().delete(&key.to_string()).await?;
            }
            let reservation = state.kv().reserve_key(key.to_string()).await?;
            state.kv().put(reservation, v).await?;
            // TODO: Error handling really complex needs to be thought about.
            confirm_registered(&api, key, subgroup, &signer).await?;
        },
        Err(v) => {
            return Err(UserErr::Parse("failed decrypting message"));
        },
    }
    Ok(Status::Ok)
}

pub async fn register_info(
    api: &OnlineClient<EntropyConfig>,
    who: &AccountId32,
    registering: bool,
) -> Result<bool, UserErr> {
    let registering_info_query = entropy::storage().relayer().registering(who);
    let register_info = api.storage().fetch(&registering_info_query, None).await?;
    if registering {
        return Ok(register_info
            .ok_or_else(|| UserErr::NotRegistering("Register Onchain first"))?
            .is_registering);
    }
    Ok(register_info
        .ok_or_else(|| UserErr::NotRegistering("Declare swap Onchain first"))?
        .is_swapping)
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
