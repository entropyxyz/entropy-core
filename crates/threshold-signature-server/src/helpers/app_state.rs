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
use anyhow::anyhow;
use entropy_kvdb::kv_manager::KvManager;
use entropy_shared::X25519PublicKey;
use sp_core::{crypto::AccountId32, sr25519, Pair};
use std::{
    collections::HashMap,
    sync::{Arc, PoisonError, RwLock},
};
use subxt::{
    backend::legacy::LegacyRpcMethods, tx::PairSigner, utils::AccountId32 as SubxtAccountId32,
    OnlineClient,
};
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
    pub block_numbers: Arc<RwLock<HashMap<String, u32>>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    /// Setup new Cache
    pub fn new() -> Self {
        Self {
            listener_state: ListenerState::default(),
            tss_state: Arc::new(RwLock::new(TssState::new())),
            request_limit: Default::default(),
            encryption_key_backup_provider: Default::default(),
            attestation_nonces: Default::default(),
            block_numbers: Default::default(),
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
    pub fn connected_to_chain_node(
        &self,
    ) -> Result<(), PoisonError<std::sync::RwLockWriteGuard<'_, TssState>>> {
        let mut tss_state = self.tss_state.write()?;
        if *tss_state == TssState::NoChainConnection {
            *tss_state = TssState::ReadOnlyChainConnection;
        }
        Ok(())
    }

    /// Mark the node as ready. This is called once when the prerequisite checks have passed.
    pub fn make_ready(&self) -> Result<(), PoisonError<std::sync::RwLockWriteGuard<'_, TssState>>> {
        let mut tss_state = self.tss_state.write()?;
        *tss_state = TssState::Ready;
        Ok(())
    }

    /// Write to request limit
    pub fn write_to_request_limit(&self, key: String, value: u32) -> anyhow::Result<()> {
        self.clear_poisioned_request_limit();
        let mut request_limit = self
            .request_limit
            .write()
            .map_err(|_| anyhow!("Error getting write write_to_request_limit lock"))?;
        request_limit.insert(key, value);
        Ok(())
    }

    /// Check if key exists in request limit
    pub fn exists_in_request_limit(&self, key: &String) -> anyhow::Result<bool> {
        self.clear_poisioned_request_limit();
        let request_limit = self
            .request_limit
            .read()
            .map_err(|_| anyhow!("Error getting read exists_in_request_limit lock"))?;
        Ok(request_limit.contains_key(key))
    }

    /// Remove key from request limt
    pub fn remove_from_request_limit(&self, key: &String) -> anyhow::Result<()> {
        self.clear_poisioned_request_limit();
        let mut request_limit = self
            .request_limit
            .write()
            .map_err(|_| anyhow!("Error getting write remove_from_request_limit lock"))?;
        request_limit.remove(key);
        Ok(())
    }

    /// Reads from request_limit will error if no value, call exists_in_request_limit to check
    pub fn read_from_request_limit(&self, key: &String) -> anyhow::Result<Option<u32>> {
        self.clear_poisioned_request_limit();
        let request_limit = self
            .request_limit
            .read()
            .map_err(|_| anyhow!("Error getting read read_from_request_limit lock"))?;
        Ok(request_limit.get(key).cloned())
    }

    /// Clears the request_limit mapping
    pub fn clear_request_limit(&self) -> anyhow::Result<()> {
        self.clear_poisioned_request_limit();
        let mut request_limit = self
            .request_limit
            .write()
            .map_err(|_| anyhow!("Error getting read read_from_request_limit lock"))?;
        request_limit.clear();
        Ok(())
    }

    /// Clears a poisioned lock from request limit
    pub fn clear_poisioned_request_limit(&self) {
        if self.request_limit.is_poisoned() {
            self.request_limit.clear_poison()
        }
    }

    /// Write the given block number to the `block_number` cache.
    pub fn write_to_block_numbers(&self, key: String, value: u32) -> anyhow::Result<()> {
        self.clear_poisioned_block_numbers();
        let mut block_numbers = self
            .block_numbers
            .write()
            .map_err(|_| anyhow!("Error getting write write_to_block_numbers lock"))?;
        block_numbers.insert(key, value);
        Ok(())
    }

    /// Check if the given block number exists in the cache.
    pub fn exists_in_block_numbers(&self, key: &String) -> anyhow::Result<bool> {
        self.clear_poisioned_block_numbers();
        let block_numbers = self
            .block_numbers
            .read()
            .map_err(|_| anyhow!("Error getting read exists_in_block_numbers lock"))?;
        Ok(block_numbers.contains_key(key))
    }

    /// Returns the number of requests handled so far at the given block number.
    pub fn read_from_block_numbers(&self, key: &String) -> anyhow::Result<Option<u32>> {
        self.clear_poisioned_block_numbers();
        let block_numbers = self
            .block_numbers
            .read()
            .map_err(|_| anyhow!("Error getting read read_from_block_numbers lock"))?;
        Ok(block_numbers.get(key).cloned())
    }

    /// Clears a poisioned lock from request limit
    pub fn clear_poisioned_block_numbers(&self) {
        if self.block_numbers.is_poisoned() {
            self.block_numbers.clear_poison()
        }
    }
    /// Gets the list of peers who haven't yet subscribed to us for this particular session.
    pub fn unsubscribed_peers(
        &self,
        session_id: &entropy_protocol::SessionId,
    ) -> Result<Vec<subxt::utils::AccountId32>, crate::signing_client::ProtocolErr> {
        self.listener_state.unsubscribed_peers(session_id).map_err(|_| {
            crate::signing_client::ProtocolErr::SessionError(format!(
                "Unable to get unsubscribed peers for `SessionId` {:?}",
                session_id,
            ))
        })
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
    pub kv_store: KvManager,
    /// Global cache for TSS server
    pub cache: Cache,
}

impl AppState {
    /// Setup AppState with given secret keys
    pub fn new(
        configuration: Configuration,
        kv_store: KvManager,
        pair: sr25519::Pair,
        x25519_secret: StaticSecret,
    ) -> Self {
        Self { pair, x25519_secret, configuration, kv_store, cache: Cache::default() }
    }
    /// Convenience function to get chain api and rpc
    pub async fn get_api_rpc(
        &self,
    ) -> Result<(OnlineClient<EntropyConfig>, LegacyRpcMethods<EntropyConfig>), subxt::Error> {
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
}
