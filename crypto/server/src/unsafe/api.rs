use std::str;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::to_string;

use crate::AppState;

/// Used to modify the state of the KVDB directly.
///
/// # Note
///
/// This should only be used for development purposes.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UnsafeQuery {
    pub key: String,
    pub value: Vec<u8>,
}

/// Struct representing the query type
#[cfg(test)]
impl UnsafeQuery {
    pub fn new(key: String, value: Vec<u8>) -> Self {
        UnsafeQuery { key, value }
    }

    pub fn to_json(&self) -> String {
        to_string(self).unwrap()
    }
}

/// Read a value from the encrypted KVDB.
///
/// # Note
///
/// This should only be used for development purposes.
#[tracing::instrument(name = "Reading key from KVDB", skip(app_state))]
pub async fn unsafe_get(
    State(app_state): State<AppState>,
    Json(key): Json<UnsafeQuery>,
) -> Vec<u8> {
    let value = app_state.kv_store.kv().get(&key.key.to_owned()).await;
    match value {
        Ok(v) => {
            tracing::debug!("Read value: {:?} from KVDB", &v);
            v
        },
        Err(_) => {
            tracing::error!("Failed to get value from KVDB");
            panic!("Failed to get value from KVDB")
        },
    }
}

/// Updates a value in the encrypted KVDB.
///
/// # Note
///
/// This should only be used for development purposes.
#[tracing::instrument(name = "Updating key from KVDB", skip(app_state))]
pub async fn put(State(app_state): State<AppState>, Json(key): Json<UnsafeQuery>) -> StatusCode {
    match app_state.kv_store.kv().exists(&key.key.to_owned()).await {
        Ok(v) => {
            if v {
                tracing::debug!("Deleting existing key from KVDB");
                app_state.kv_store.kv().delete(&key.key.to_owned()).await.unwrap();
            }

            match app_state.kv_store.kv().reserve_key(key.key.clone()).await {
                Ok(v) => {
                    app_state.kv_store.kv().put(v, key.value).await.unwrap();
                    tracing::debug!("Succesfully wrote key to KVDB");
                    StatusCode::OK
                },
                Err(v) => {
                    tracing::warn!("Unable to reserve key {:?} from KVDB", v);
                    StatusCode::INTERNAL_SERVER_ERROR
                },
            }
        },
        Err(_) => {
            tracing::warn!("The provided key does not exist in the KVDB");
            StatusCode::INTERNAL_SERVER_ERROR
        },
    }
}

/// Deletes any key from the KVDB.
///
/// # Note
///
/// This should only be used for development purposes.
#[tracing::instrument(name = "Deleting key from KVDB", skip(app_state))]
pub async fn delete(State(app_state): State<AppState>, Json(key): Json<UnsafeQuery>) -> StatusCode {
    app_state.kv_store.kv().delete(&key.key.to_owned()).await.unwrap();

    tracing::debug!("Succesfully removed key from KVDB");
    StatusCode::OK
}

/// Removes all keys from the KVDB.
///
/// # Note
///
/// This should only be used for development purposes.
#[tracing::instrument(name = "Removing all keys from KVDB", skip(app_state))]
pub async fn remove_keys(State(app_state): State<AppState>) -> StatusCode {
    app_state.kv_store.kv().delete("DH_PUBLIC").await.unwrap();
    app_state.kv_store.kv().delete("MNEMONIC").await.unwrap();
    app_state.kv_store.kv().delete("SHARED_SECRET").await.unwrap();

    tracing::debug!("Succesfully removed all keys from KVDB");
    StatusCode::OK
}
