use std::str;

use bip39::{Language, Mnemonic};
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
use sp_core::{sr25519, Pair};
use subxt::{ext::sp_runtime::AccountId32, tx::PairSigner};
use tracing::instrument;

use super::{ParsedUserInputPartyInfo, UserErr, UserInputPartyInfo};
use crate::{
    chain_api::{entropy, get_api},
    message::SignedMessage,
    signing_client::SignerState,
    Configuration,
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UnsafeQuery {
    pub key: String,
    pub value: String,
}

impl UnsafeQuery {
    pub fn new(key: String, value: String) -> Self { UnsafeQuery { key, value } }

    pub fn to_json(&self) -> String { to_string(self).unwrap() }
}

#[post("/get", format = "json", data = "<key>")]
pub async fn get(
    key: Json<UnsafeQuery>,
    state: &State<KvManager>,
    config: &State<Configuration>,
) -> Vec<u8> {
    state.kv().get(&key.key.to_owned()).await.unwrap()
}

#[post("/put", format = "json", data = "<key>")]
pub async fn put(
    key: Json<UnsafeQuery>,
    state: &State<KvManager>,
    config: &State<Configuration>,
) -> Status {
    match state.kv().exists(&key.key.to_owned()).await {
        Err(v) => {
            warn!("{}", v);
            Status::InternalServerError
        },
        Ok(v) => {
            if v {
                state.kv().delete(&key.key.to_owned()).await.unwrap();
            }
            match state.kv().reserve_key(key.key.clone()).await {
                Ok(v) => {
                    state.kv().put(v, key.value.as_bytes().to_vec()).await.unwrap();
                    Status::Ok
                },
                Err(v) => {
                    warn!("{}", v);
                    Status::InternalServerError
                },
            }
        },
    }
}

#[post("/delete", format = "json", data = "<key>")]
pub async fn delete(
    key: Json<UnsafeQuery>,
    state: &State<KvManager>,
    config: &State<Configuration>,
) -> Status {
    state.kv().delete(&key.key.to_owned()).await.unwrap();
    Status::Ok
}

#[get("/remove_keys")]
pub async fn remove_keys(state: &State<KvManager>, config: &State<Configuration>) -> Status {
    state.kv().delete("DH_PUBLIC").await.unwrap();
    state.kv().delete("MNEMONIC").await.unwrap();
    state.kv().delete("SHARED_SECRET").await.unwrap();
    Status::Ok
}
