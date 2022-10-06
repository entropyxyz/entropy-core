use std::str;

use bip39::{Language, Mnemonic};
use kvdb::kv_manager::{
    error::{InnerKvError, KvError},
    value::PartyInfo,
    KvManager,
};
use log::info;
use rocket::{http::Status, response::stream::EventStream, serde::json::Json, Shutdown, State};
use sp_core::{sr25519, Pair};
use subxt::{sp_runtime::AccountId32, DefaultConfig, PairSigner};
use tracing::instrument;

use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{entropy, get_api, EntropyRuntime},
    message::SignedMessage,
    signing_client::SignerState,
    Configuration,
};

#[get("/dh")]
pub async fn get_dh(state: &State<KvManager>, config: &State<Configuration>) -> String {
    let dh_public = state.kv().get("DH_PUBLIC").await.unwrap();
    hex::encode(&dh_public)
}
