use std::str;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::to_string;

use crate::AppState;

#[derive(Debug, Deserialize, Serialize, Clone)]
/// \[UNSAFE - DO NOT USE IN PRODUCTION\]
/// UnsafeQuery's are used to modify
/// the state of the KVDB, for development
/// purposes only.
pub struct UnsafeQuery {
    pub key: String,
    pub value: Vec<u8>,
}

/// Struct representing the query type
impl UnsafeQuery {
    pub fn new(key: String, value: Vec<u8>) -> Self {
        UnsafeQuery { key, value }
    }

    pub fn to_json(&self) -> String {
        to_string(self).unwrap()
    }
}

/// Gets a value from the encrypted KVDB.
/// NOTE: for development purposes only.
pub async fn unsafe_get(
    State(app_state): State<AppState>,
    Json(key): Json<UnsafeQuery>,
) -> Vec<u8> {
    app_state.kv_store.kv().get(&key.key.to_owned()).await.unwrap()
}

/// Updates a value in the encrypted kvdb
/// NOTE: for development purposes only.
pub async fn put(State(app_state): State<AppState>, Json(key): Json<UnsafeQuery>) -> StatusCode {
    match app_state.kv_store.kv().exists(&key.key.to_owned()).await {
        Err(v) => {
            tracing::warn!("{}", v);
            StatusCode::INTERNAL_SERVER_ERROR
        },
        Ok(v) => {
            if v {
                app_state.kv_store.kv().delete(&key.key.to_owned()).await.unwrap();
            }
            match app_state.kv_store.kv().reserve_key(key.key.clone()).await {
                Ok(v) => {
                    app_state.kv_store.kv().put(v, key.value).await.unwrap();
                    StatusCode::OK
                },
                Err(v) => {
                    tracing::warn!("{}", v);
                    StatusCode::INTERNAL_SERVER_ERROR
                },
            }
        },
    }
}

/// \[UNSAFE\] Deletes any key from the KVDB.
pub async fn delete(State(app_state): State<AppState>, Json(key): Json<UnsafeQuery>) -> StatusCode {
    app_state.kv_store.kv().delete(&key.key.to_owned()).await.unwrap();
    StatusCode::OK
}

/// \[UNSAFE\] Removes all keys from the KVDB.
pub async fn remove_keys(State(app_state): State<AppState>) -> StatusCode {
    app_state.kv_store.kv().delete("DH_PUBLIC").await.unwrap();
    app_state.kv_store.kv().delete("MNEMONIC").await.unwrap();
    app_state.kv_store.kv().delete("SHARED_SECRET").await.unwrap();
    StatusCode::OK
}
