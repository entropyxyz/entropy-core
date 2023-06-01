use std::str;

use kvdb::kv_manager::KvManager;
#[cfg(test)]
use rocket::serde::json::to_string;
use rocket::{http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
/// [UNSAFE - DO NOT USE IN PRODUCTION]
/// UnsafeQuery's are used to modify
/// the state of the KVDB, for development
/// purposes only.
pub struct UnsafeQuery {
    pub key: String,
    pub value: String,
}

#[cfg(test)]
/// Struct representing the query type
impl UnsafeQuery {
    pub fn new(key: String, value: String) -> Self { UnsafeQuery { key, value } }

    pub fn to_json(&self) -> String { to_string(self).unwrap() }
}

#[post("/get", format = "json", data = "<key>")]
/// Gets a value from the encrypted KVDB.
/// NOTE: for development purposes only.
pub async fn get(key: Json<UnsafeQuery>, state: &State<KvManager>) -> String {
    hex::encode(state.kv().get(&key.key.to_owned()).await.unwrap())
}

#[post("/put", format = "json", data = "<key>")]
/// Updates a value in the encrypted kvdb
/// NOTE: for development purposes only.
pub async fn put(key: Json<UnsafeQuery>, state: &State<KvManager>) -> Status {
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

/// [UNSAFE] Deletes any key from the KVDB.
#[post("/delete", format = "json", data = "<key>")]
pub async fn delete(key: Json<UnsafeQuery>, state: &State<KvManager>) -> Status {
    state.kv().delete(&key.key.to_owned()).await.unwrap();
    Status::Ok
}

/// [UNSAFE] Removes all keys from the KVDB.
#[get("/remove_keys")]
pub async fn remove_keys(state: &State<KvManager>) -> Status {
    state.kv().delete("DH_PUBLIC").await.unwrap();
    state.kv().delete("MNEMONIC").await.unwrap();
    state.kv().delete("SHARED_SECRET").await.unwrap();
    Status::Ok
}
