// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Public API for kvstore operations
//! Errors are mapped to [crate::kv_manager::error::KvError]

use std::{fmt::Debug, path::PathBuf};

use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::{mpsc, oneshot};

use super::{
    error::{InnerKvError, KvError::*, KvResult},
    sled_bindings::{handle_delete, handle_exists, handle_get, handle_put, handle_reserve},
    types::{
        Command::{self, *},
        KeyReservation, DEFAULT_KV_NAME, DEFAULT_KV_PATH,
    },
};
use crate::encrypted_sled::{self, Password};

#[derive(Clone)]
pub struct Kv<V> {
    sender: mpsc::UnboundedSender<Command<V>>,
}

// database functionality using the "actor" pattern (Kv is the "handle"): https://ryhl.io/blog/actors-with-tokio/
// see also https://tokio.rs/tokio/tutorial/channels
impl<V: 'static> Kv<V>
where
    V: Debug + Send + Sync + Serialize + DeserializeOwned,
{
    /// Creates a new kv service. Returns [InitErr] on failure.
    /// the path of the kvstore is `root_path` + "/kvstore/" + `kv_name`
    pub fn new(root_path: PathBuf, password: Password) -> KvResult<Self> {
        let kv_path = root_path.join(DEFAULT_KV_PATH).join(DEFAULT_KV_NAME);
        // use to_string_lossy() instead of to_str() to avoid handling Option<&str>
        let kv_path = kv_path.to_string_lossy().to_string();
        Self::with_db_name(kv_path, password)
    }

    /// Creates a kvstore at `full_db_name` and spawns a new kv_manager. Returns [InitErr] on
    /// failure. `full_db_name` is the name of the path of the kvstrore + its name
    /// Example: ~/entropy/kvstore/database_1
    pub fn with_db_name(full_db_name: String, password: Password) -> KvResult<Self> {
        let (sender, rx) = mpsc::unbounded_channel();

        // get kv store from db name before entering the kv_cmd_handler because
        // it's more convenient to return an error from outside of a tokio::span
        let kv = get_kv_store(&full_db_name, password)?;

        tokio::spawn(kv_cmd_handler(rx, kv));
        Ok(Self { sender })
    }

    /// Reserves a key in the kvstore with [super::types::DEFAULT_RESERV] value.
    /// Returns [ReserveErr] or [SendErr] on failure.
    pub async fn reserve_key(&self, key: String) -> KvResult<KeyReservation> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(ReserveKey { key, resp: resp_tx })
            .map_err(|err| SendErr(err.to_string()))?;
        resp_rx.await?.map_err(ReserveErr)
    }

    /// Unreserves an existing reservation
    pub async fn unreserve_key(&self, reservation: KeyReservation) {
        let _ = self.sender.send(UnreserveKey { reservation });
    }

    /// Puts a new value given a [super::types::KeyReservation]
    /// Returns [PutErr] or [SendErr] on failure.
    pub async fn put(&self, reservation: KeyReservation, value: V) -> KvResult<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Put { reservation, value, resp: resp_tx })
            .map_err(|e| SendErr(e.to_string()))?;
        resp_rx.await?.map_err(PutErr)
    }

    /// Gets a value given a key
    /// Returns [GetErr] or [SendErr] on failure.
    pub async fn get(&self, key: &str) -> KvResult<V> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Get { key: key.to_string(), resp: resp_tx })
            .map_err(|e| SendErr(e.to_string()))?;
        resp_rx.await?.map_err(GetErr)
    }

    /// Deletes an unreserved key
    /// Returns [DeleteErr] or [SendErr] on failure.
    pub async fn delete(&self, key: &str) -> KvResult<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Delete { key: key.to_string(), resp: resp_tx })
            .map_err(|e| SendErr(e.to_string()))?;
        resp_rx.await?.map_err(DeleteErr)
    }

    /// Checks if a key exists in the kvstore
    /// Returns [ExistsErr] or [SendErr] on failure.
    pub async fn exists(&self, key: &str) -> KvResult<bool> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.sender
            .send(Exists { key: key.to_string(), resp: resp_tx })
            .map_err(|e| SendErr(e.to_string()))?;
        resp_rx.await?.map_err(ExistsErr)
    }
}

/// Returns the db with name `db_name`, or creates a new if such DB does not exist
/// Returns [sled::Error] on failure.
/// Default path DB path is the executable's directory; The caller can specify a
/// full path followed by the name of the DB
/// Usage:
///  let my_db = get_kv_store(&"my_current_dir_db")?;
///  let my_db = get_kv_store(&"/tmp/my_tmp_bd")?;
#[tracing::instrument(skip_all, fields(db_name))]
pub fn get_kv_store(
    db_name: &str,
    password: Password,
) -> encrypted_sled::Result<encrypted_sled::Db> {
    // create/open DB
    tracing::debug!("Decrypting KV store");
    let kv = encrypted_sled::Db::open(db_name, password)?;

    // log whether the DB was newly created or not
    if kv.was_recovered() {
        tracing::debug!("Found exisiting database");
    } else {
        tracing::debug!("No existing database found, creating a new one.");
    }
    Ok(kv)
}

// private handler function to process commands as per the "actor" pattern (see above)
async fn kv_cmd_handler<V: 'static>(
    mut rx: mpsc::UnboundedReceiver<Command<V>>,
    kv: encrypted_sled::Db,
) where
    V: Debug + Serialize + DeserializeOwned,
{
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ReserveKey { key, resp } => {
                handle_response(handle_reserve(&kv, key), resp);
            },
            UnreserveKey { reservation } => {
                let kv_resp = kv.remove(reservation.key);
                match kv_resp {
                    Ok(_) => {},
                    Err(err) => tracing::warn!("Failed to remove key from database: {}", err),
                }
            },
            Put { reservation, value, resp } => {
                handle_response(handle_put(&kv, reservation, value), resp);
            },
            Get { key, resp } => {
                handle_response(handle_get(&kv, key), resp);
            },
            Exists { key, resp } => {
                handle_response(handle_exists(&kv, &key), resp);
            },
            Delete { key, resp } => {
                handle_response(handle_delete(&kv, key), resp);
            },
        }
    }
}

fn handle_response<T>(
    kv_resp: Result<T, InnerKvError>,
    resp: oneshot::Sender<Result<T, InnerKvError>>,
) where
    T: Debug,
{
    match kv_resp {
        Ok(_) => {
            let response = resp.send(kv_resp);
            match response {
                Ok(_) => {},
                Err(err) => tracing::warn!("Receiver to dropped with: {:?}", err),
            }
        },
        Err(err) => tracing::error!("Failed to handle database query with: {:?}", err),
    }
}
