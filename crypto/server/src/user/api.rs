use bip39::{Language, Mnemonic};
use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{
    types::{Acl, AclKind, Arch},
    SIGNING_PARTY_SIZE,
};
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
    helpers::validator::{get_signer, get_subgroup},
    message::SignedMessage,
    signing_client::SignerState,
    Configuration,
};

/// Represents an unparsed, transaction request coming from the client.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct GenericTransactionRequest {
    /// 'eth', etc.
    pub arch: String,
    /// ETH: RLP encoded transaction request
    pub transaction_request: String,
}

/// TODO: Add block based removal for unsigned transactions in the KVDB.
/// https://github.com/entropyxyz/entropy-core/issues/248
/// Maps a tx hash -> unsigned transaction in the kvdb.
#[post("/tx", format = "json", data = "<generic_tx_req>")]
pub async fn store_tx(
    generic_tx_req: Json<GenericTransactionRequest>,
    state: &State<KvManager>,
) -> Result<Status, UserErr> {
    match generic_tx_req.arch.as_str() {
        "evm" => {
            let parsed_tx = <Evm as Architecture>::TransactionRequest::parse(
                generic_tx_req.transaction_request.clone(),
            )?;
            let sighash = parsed_tx.sighash();

            // Map the sighash to the serialize transaction request
            match state.kv().reserve_key(sighash.to_string()).await {
                Ok(reservation) => {
                    state
                        .kv()
                        .put(reservation, generic_tx_req.transaction_request.clone().into())
                        .await?;
                },
                // If the key is already reserved, then we can assume the transaction is already
                // stored.
                Err(_) => return Ok(Status::Ok),
            }
        },
        _ => {
            return Err(UserErr::Parse("Unknown \"arch\". Must be one of: [\"evm\"]"));
        },
    }
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
    let is_swapping = register_info(&api, &key).await?;

    let decrypted_message =
        signed_msg.decrypt(signer.signer()).map_err(|e| UserErr::Decryption(e.to_string()))?;
    // store new user data in kvdb or deletes and replaces it if swapping
    let subgroup = get_subgroup(&api, &signer)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    if is_swapping {
        state.kv().delete(&key.to_string()).await?;
    }
    let reservation = state.kv().reserve_key(key.to_string()).await?;
    state.kv().put(reservation, decrypted_message).await?;
    // TODO: Error handling really complex needs to be thought about.
    confirm_registered(&api, key, subgroup, &signer).await?;
    Ok(Status::Ok)
}
/// Returns wether an account is registering or swapping. If it is not, it returns error
pub async fn register_info(
    api: &OnlineClient<EntropyConfig>,
    who: &AccountId32,
) -> Result<bool, UserErr> {
    let registering_info_query = entropy::storage().relayer().registering(who);
    let register_info = api
        .storage()
        .fetch(&registering_info_query, None)
        .await?
        .ok_or_else(|| UserErr::NotRegistering("Register Onchain first"))?;
    if !register_info.is_swapping && !register_info.is_registering {
        return Err(UserErr::NotRegistering("Declare swap Onchain first"));
    }

    Ok(register_info.is_swapping)
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
