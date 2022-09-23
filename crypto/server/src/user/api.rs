use bip39::{Language, Mnemonic};
use kvdb::kv_manager::{error::KvError, value::PartyInfo, KvManager};
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use sp_core::{sr25519, Pair};
use subxt::{sp_runtime::AccountId32, DefaultConfig, PairSigner};
use tracing::instrument;

use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{entropy, get_api, EntropyRuntime},
    signing_client::SignerState,
    Configuration,
};

/// Add a new Keyshare to this node's set of known Keyshares. Store in kvdb.
#[instrument(skip(state))]
#[post("/new", format = "json", data = "<user_input>")]
pub async fn new_user(
    user_input: Json<UserInputPartyInfo>,
    state: &State<KvManager>,
    config: &State<Configuration>,
) -> Result<Status, UserErr> {
    let api = get_api(&config.endpoint).await.unwrap();
    // ToDo: validate is owner of key address
    // ToDo: JA make sure signed so other key does&n't override own key
    // try parsing the input and validate the result
    let parsed_user_input: ParsedUserInputPartyInfo = user_input.into_inner().try_into()?;
    let (key, value) = (parsed_user_input.key.clone(), parsed_user_input.value.clone());
    let is_registering = is_registering(&api, &key).await.unwrap();
    if !is_registering {
        return Err(UserErr::NotRegistering("Register Onchain first"));
    }
    //   let party_info: PartyInfo = parsed_user_input.clone().try_into()?;

    // store new user data in kvdb
    let reservation = state.kv().reserve_key(key.to_string()).await?;
    state.kv().put(reservation, value).await?;

    let signer = get_signer(state).await.unwrap();

    // TODO: Error handling really complex needs to be thought about.
    confirm_registered(&api, key, &signer).await.unwrap();

    Ok(Status::Ok)
}

pub async fn is_registering(
    api: &EntropyRuntime,
    who: &AccountId32,
) -> Result<bool, subxt::Error<entropy::DispatchError>> {
    let is_registering = api.storage().relayer().registering(who, None).await?.unwrap();
    Ok(is_registering)
}

// TODO: Error handling
async fn get_signer(
    kv: &KvManager,
) -> Result<subxt::PairSigner<DefaultConfig, sr25519::Pair>, KvError> {
    let exists = kv.kv().exists("MNEMONIC").await.unwrap();
    let raw_m = kv.kv().get("MNEMONIC").await.unwrap();
    let str_m = core::str::from_utf8(&raw_m).unwrap();
    let m = Mnemonic::from_phrase(str_m, Language::English).unwrap();
    let p = <sr25519::Pair as Pair>::from_phrase(m.phrase(), None).unwrap();

    Ok(PairSigner::<DefaultConfig, sr25519::Pair>::new(p.0))
}

pub async fn confirm_registered(
    api: &EntropyRuntime,
    who: AccountId32,
    signer: &subxt::PairSigner<DefaultConfig, sr25519::Pair>,
) -> Result<(), subxt::Error<entropy::DispatchError>> {
    // TODO error handling + return error
    let _ = api.tx().relayer()
        .confirm_register(who)
        // TODO: Understand this better, potentially use sign_and_submit_default
        // or other method under sign_and_*
        .sign_and_submit_then_watch_default(signer).await?
        .wait_for_in_block().await?
        .wait_for_success().await?;
    Ok(())
}
