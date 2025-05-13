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

//! Shared App State for TSS server.
use crate::{
    chain_api::{get_api, get_rpc, EntropyConfig},
    launch::Configuration,
    signing_client::ListenerState,
};
use entropy_kvdb::kv_manager::{helpers::serialize as key_serialize, KvManager};
use entropy_protocol::KeyShareWithAuxInfo;
use entropy_shared::{X25519PublicKey, NETWORK_PARENT_KEY, NEXT_NETWORK_PARENT_KEY};
use serde::{Deserialize, Serialize};
use sp_core::{crypto::AccountId32, sr25519, Pair};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};
use subxt::{
    backend::legacy::LegacyRpcMethods, tx::PairSigner, utils::AccountId32 as SubxtAccountId32,
    OnlineClient,
};
use thiserror::Error;
use x25519_dalek::StaticSecret;

/// Represents the state relating to the prerequisite checks
#[derive(Clone, PartialEq, Eq)]
pub enum TssState {
    /// Initial state where no connection to chain node has been made
    NoChainConnection,
    /// Connection is made to the chain node but the account may not be yet funded
    ReadOnlyChainConnection,
    /// Fully ready and able to participate in the protocols
    Ready,
}

impl TssState {
    fn new() -> Self {
        TssState::NoChainConnection
    }

    fn is_ready(&self) -> bool {
        self == &TssState::Ready
    }

    fn can_read_from_chain(&self) -> bool {
        self != &TssState::NoChainConnection
    }
}

/// Fields related to blocknumbers being stored in cache
#[derive(Debug, Deserialize, Serialize)]
pub enum BlockNumberFields {
    LatestBlock,
    NewUser,
    Reshare,
    Attest,
    ProactiveRefresh,
}

/// Blocknumbers being stored in cache
#[derive(Default, Clone)]
pub struct BlockNumbers {
    pub latest_block: Arc<RwLock<u32>>,
    pub new_user: Arc<RwLock<u32>>,
    pub reshare: Arc<RwLock<u32>>,
    pub attest: Arc<RwLock<u32>>,
    pub proactive_refresh: Arc<RwLock<u32>>,
}

/// In-memory store of application state
#[derive(Clone)]
pub struct Cache {
    /// Tracks incoming protocol connections with other TSS nodes
    pub listener_state: ListenerState,
    /// Tracks the state of prerequisite checks
    pub tss_state: Arc<RwLock<TssState>>,
    /// Storage for request limit
    pub request_limit: Arc<RwLock<HashMap<String, u32>>>,
    /// Storage for encryption key backups for other TSS nodes
    /// Maps TSS account id to encryption key
    pub encryption_key_backup_provider: Arc<RwLock<HashMap<AccountId32, [u8; 32]>>>,
    /// Storage for quote nonces for other TSS nodes wanting to make encryption key backups
    /// Maps response x25519 public key to quote nonce
    pub attestation_nonces: Arc<RwLock<HashMap<X25519PublicKey, [u8; 32]>>>,
    /// Collection of block numbers to store
    pub block_numbers: Arc<BlockNumbers>,
    /// The network keyshare, if we have one
    network_key_share: Arc<RwLock<Option<KeyShareWithAuxInfo>>>,
    /// The next network keyshare, stored during reshare confirmation
    next_network_key_share: Arc<RwLock<Option<KeyShareWithAuxInfo>>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl Cache {
    /// Setup new Cache
    pub fn new(
        network_key_share: Option<KeyShareWithAuxInfo>,
        next_network_key_share: Option<KeyShareWithAuxInfo>,
    ) -> Self {
        Self {
            listener_state: ListenerState::default(),
            tss_state: Arc::new(RwLock::new(TssState::new())),
            request_limit: Default::default(),
            encryption_key_backup_provider: Default::default(),
            attestation_nonces: Default::default(),
            block_numbers: Default::default(),
            network_key_share: Arc::new(RwLock::new(network_key_share)),
            next_network_key_share: Arc::new(RwLock::new(next_network_key_share)),
        }
    }
    /// Returns true if all prerequisite checks have passed.
    /// Is is not possible to participate in the protocols before this is true.
    /// 'Ready' means:
    ///  - Communication has been established with the chain node
    ///  - The TSS account is funded
    ///  - The TSS account is registered with the staking extension pallet
    pub fn is_ready(&self) -> bool {
        match self.tss_state.read() {
            Ok(state) => state.is_ready(),
            _ => false,
        }
    }

    /// Returns true if we are able to make chain queries
    pub fn can_read_from_chain(&self) -> bool {
        match self.tss_state.read() {
            Ok(state) => state.can_read_from_chain(),
            _ => false,
        }
    }

    /// Mark the node as able to make chain queries. This is called once during prerequisite checks
    pub fn connected_to_chain_node(&self) -> Result<(), AppStateError> {
        let mut tss_state =
            self.tss_state.write().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        if *tss_state == TssState::NoChainConnection {
            *tss_state = TssState::ReadOnlyChainConnection;
        }
        Ok(())
    }

    /// Mark the node as ready. This is called once when the prerequisite checks have passed.
    pub fn make_ready(&self) -> Result<(), AppStateError> {
        let mut tss_state =
            self.tss_state.write().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        *tss_state = TssState::Ready;
        Ok(())
    }

    /// Write to request limit
    pub fn write_to_request_limit(&self, key: String, value: u32) -> Result<(), AppStateError> {
        self.clear_poisioned_request_limit();
        let mut request_limit =
            self.request_limit.write().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        request_limit.insert(key, value);
        Ok(())
    }

    /// Check if key exists in request limit
    pub fn exists_in_request_limit(&self, key: &String) -> Result<bool, AppStateError> {
        self.clear_poisioned_request_limit();
        let request_limit =
            self.request_limit.read().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        Ok(request_limit.contains_key(key))
    }

    /// Remove key from request limt
    pub fn remove_from_request_limit(&self, key: &String) -> Result<(), AppStateError> {
        self.clear_poisioned_request_limit();
        let mut request_limit =
            self.request_limit.write().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        request_limit.remove(key);
        Ok(())
    }

    /// Reads from request_limit will error if no value, call exists_in_request_limit to check
    pub fn read_from_request_limit(&self, key: &String) -> Result<Option<u32>, AppStateError> {
        self.clear_poisioned_request_limit();
        let request_limit =
            self.request_limit.read().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        Ok(request_limit.get(key).cloned())
    }

    /// Clears the request_limit mapping
    pub fn clear_request_limit(&self) -> Result<(), AppStateError> {
        self.clear_poisioned_request_limit();
        let mut request_limit =
            self.request_limit.write().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        request_limit.clear();
        Ok(())
    }

    /// Clears a poisioned lock from request limit
    pub fn clear_poisioned_request_limit(&self) {
        if self.request_limit.is_poisoned() {
            self.request_limit.clear_poison()
        }
    }

    /// Reads and writes the given block number to the `block_number` cache.
    /// Maintains lock for both operations
    pub fn read_write_to_block_numbers(
        &self,
        key: BlockNumberFields,
        value: u32,
    ) -> Result<u32, AppStateError> {
        let block_number_target = self.get_block_number_target(&key);
        self.clear_poisioned_block_numbers(&block_number_target);
        let mut block_number =
            block_number_target.write().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        let current_number = *block_number;
        *block_number = value;
        Ok(current_number)
    }

    /// Write the given block number to the `block_number` cache.
    pub fn write_to_block_numbers(
        &self,
        key: BlockNumberFields,
        value: u32,
    ) -> Result<(), AppStateError> {
        let block_number_target = self.get_block_number_target(&key);
        self.clear_poisioned_block_numbers(&block_number_target);
        let mut block_number =
            block_number_target.write().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        *block_number = value;
        Ok(())
    }

    /// Returns the number of requests handled so far at the given block number.
    pub fn read_from_block_numbers(&self, key: &BlockNumberFields) -> Result<u32, AppStateError> {
        let block_number_target = self.get_block_number_target(key);
        self.clear_poisioned_block_numbers(&block_number_target);
        let block_number =
            block_number_target.read().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        Ok(*block_number)
    }

    /// Clears a poisioned lock from request limit
    pub fn clear_poisioned_block_numbers(&self, lock: &Arc<RwLock<u32>>) {
        if lock.is_poisoned() {
            lock.clear_poison()
        }
    }

    /// Gets block number field in block numbers
    pub fn get_block_number_target(&self, key: &BlockNumberFields) -> Arc<RwLock<u32>> {
        match key {
            BlockNumberFields::LatestBlock => self.block_numbers.latest_block.clone(),
            BlockNumberFields::NewUser => self.block_numbers.new_user.clone(),
            BlockNumberFields::Reshare => self.block_numbers.reshare.clone(),
            BlockNumberFields::Attest => self.block_numbers.attest.clone(),
            BlockNumberFields::ProactiveRefresh => self.block_numbers.proactive_refresh.clone(),
        }
    }

    /// Gets the list of peers who haven't yet subscribed to us for this particular session.
    pub fn unsubscribed_peers(
        &self,
        session_id: &entropy_protocol::SessionId,
    ) -> Result<Vec<subxt::utils::AccountId32>, AppStateError> {
        self.listener_state.unsubscribed_peers(session_id).map_err(|_| {
            AppStateError::SessionError(format!(
                "Unable to get unsubscribed peers for `SessionId` {:?}",
                session_id,
            ))
        })
    }

    fn read_network_key_share(&self) -> Result<Option<KeyShareWithAuxInfo>, AppStateError> {
        let key_share =
            self.network_key_share.read().map_err(|e| AppStateError::PosionError(e.to_string()))?;
        Ok(key_share.clone())
    }

    fn write_network_key_share(
        &self,
        updated_key_share: Option<KeyShareWithAuxInfo>,
    ) -> Result<(), AppStateError> {
        let mut key_share = self
            .network_key_share
            .write()
            .map_err(|e| AppStateError::PosionError(e.to_string()))?;
        *key_share = updated_key_share;
        Ok(())
    }

    fn read_next_network_key_share(&self) -> Result<Option<KeyShareWithAuxInfo>, AppStateError> {
        let key_share = self
            .next_network_key_share
            .read()
            .map_err(|e| AppStateError::PosionError(e.to_string()))?;
        Ok(key_share.clone())
    }

    fn write_next_network_key_share(
        &self,
        updated_key_share: Option<KeyShareWithAuxInfo>,
    ) -> Result<(), AppStateError> {
        let mut key_share = self
            .next_network_key_share
            .write()
            .map_err(|e| AppStateError::PosionError(e.to_string()))?;
        *key_share = updated_key_share;
        Ok(())
    }
}

/// Application state struct which is cloned and made available to every axum HTTP route handler function
#[derive(Clone)]
pub struct AppState {
    /// Keypair for TSS account
    pub pair: sr25519::Pair,
    /// Secret encryption key
    pub x25519_secret: StaticSecret,
    /// Configuation containing the chain endpoint
    pub configuration: Configuration,
    /// Key-value store
    kv_store: KvManager,
    /// Global cache for TSS server
    pub cache: Cache,
}

impl AppState {
    /// Setup AppState with given secret keys
    pub async fn new(
        configuration: Configuration,
        kv_store: KvManager,
        pair: sr25519::Pair,
        x25519_secret: StaticSecret,
    ) -> Self {
        // Read the network keyshare from the kv_store on startup - this is the only point at which
        // we use it as a source of truth, as it is vulnerable to rollback attacks
        let network_key_share: Option<KeyShareWithAuxInfo> = if let Ok(key_share_bytes) =
            kv_store.kv().get(&hex::encode(NETWORK_PARENT_KEY)).await
        {
            entropy_kvdb::kv_manager::helpers::deserialize(&key_share_bytes)
        } else {
            None
        };

        let next_network_key_share: Option<KeyShareWithAuxInfo> = if let Ok(next_key_share_bytes) =
            kv_store.kv().get(&hex::encode(NEXT_NETWORK_PARENT_KEY)).await
        {
            entropy_kvdb::kv_manager::helpers::deserialize(&next_key_share_bytes)
        } else {
            None
        };

        let cache = Cache::new(network_key_share, next_network_key_share);

        Self { pair, x25519_secret, configuration, kv_store, cache }
    }

    /// Convenience function to get chain api and rpc
    pub async fn get_api_rpc(
        &self,
    ) -> Result<(OnlineClient<EntropyConfig>, LegacyRpcMethods<EntropyConfig>), AppStateError> {
        Ok((
            get_api(&self.configuration.endpoint).await?,
            get_rpc(&self.configuration.endpoint).await?,
        ))
    }

    /// Get a [PairSigner] for submitting extrinsics with subxt
    pub fn signer(&self) -> PairSigner<EntropyConfig, sr25519::Pair> {
        PairSigner::<EntropyConfig, sr25519::Pair>::new(self.pair.clone())
    }

    /// Get the [AccountId32]
    pub fn account_id(&self) -> AccountId32 {
        AccountId32::new(self.pair.public().0)
    }

    /// Get the subxt account ID
    pub fn subxt_account_id(&self) -> SubxtAccountId32 {
        SubxtAccountId32(self.pair.public().0)
    }

    /// Get the x25519 public key
    pub fn x25519_public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.x25519_secret).to_bytes()
    }

    pub fn network_key_share(&self) -> Result<Option<KeyShareWithAuxInfo>, AppStateError> {
        self.cache.read_network_key_share()
    }

    pub fn next_network_key_share(&self) -> Result<Option<KeyShareWithAuxInfo>, AppStateError> {
        self.cache.read_next_network_key_share()
    }

    pub async fn update_network_key_share(
        &self,
        updated_key_share: Option<KeyShareWithAuxInfo>,
    ) -> Result<(), AppStateError> {
        self.cache.write_network_key_share(updated_key_share.clone())?;

        // Write to on-disk store for backup
        self.kv_store.kv().delete(&hex::encode(NETWORK_PARENT_KEY)).await.unwrap();
        if let Some(key_share_with_aux_info) = updated_key_share {
            let serialized_key_share = key_serialize(&key_share_with_aux_info).unwrap();

            let reservation =
                self.kv_store.kv().reserve_key(hex::encode(NETWORK_PARENT_KEY)).await.unwrap();
            self.kv_store.kv().put(reservation, serialized_key_share.clone()).await.unwrap();
        }
        Ok(())
    }

    pub async fn update_next_network_key_share(
        &self,
        updated_key_share: Option<KeyShareWithAuxInfo>,
    ) -> Result<(), AppStateError> {
        self.cache.write_next_network_key_share(updated_key_share.clone())?;

        // Write to on-disk store for backup
        self.kv_store.kv().delete(&hex::encode(NEXT_NETWORK_PARENT_KEY)).await.unwrap();
        if let Some(key_share_with_aux_info) = updated_key_share {
            let serialized_key_share = key_serialize(&key_share_with_aux_info).unwrap();

            let reservation =
                self.kv_store.kv().reserve_key(hex::encode(NEXT_NETWORK_PARENT_KEY)).await.unwrap();
            self.kv_store.kv().put(reservation, serialized_key_share.clone()).await.unwrap();
        }
        Ok(())
    }

    pub async fn rotate_key_share(&self) -> Result<(), AppStateError> {
        let next_key_share = self.cache.read_next_network_key_share()?;
        if next_key_share.is_none() {
            panic!("No next keyshare to rotate");
        }
        self.update_network_key_share(next_key_share).await?;
        self.update_next_network_key_share(None).await?;
        Ok(())
    }

    pub fn storage_path(&self) -> PathBuf {
        self.kv_store.storage_path().to_path_buf()
    }
}

/// Errors related to app state.
#[derive(Error, Debug)]
pub enum AppStateError {
    #[error("Posion Mutex error: {0}")]
    PosionError(String),
    #[error("Session Error: {0}")]
    SessionError(String),
    #[error("Subxt: {0}")]
    Subxt(#[from] subxt::Error),
}
