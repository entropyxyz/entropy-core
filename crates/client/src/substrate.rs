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
//! For interacting with the substrate chain node
use crate::chain_api::entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use crate::chain_api::entropy::runtime_types::pallet_registry::pallet::RegisteredInfo;
use crate::chain_api::{entropy, EntropyConfig};

use entropy_shared::MORTALITY_BLOCKS;
use sp_core::{sr25519, Pair};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    blocks::ExtrinsicEvents,
    config::DefaultExtrinsicParamsBuilder as Params,
    tx::{Payload, Signer, TxStatus},
    utils::{AccountId32, MultiSignature, H256},
    Config, OnlineClient,
};
use subxt_core::{storage::address::Address, utils::Yes};

pub use crate::errors::SubstrateError;

/// Send a transaction to the Entropy chain
///
/// Optionally takes a nonce, otherwise it grabs the latest nonce from the chain
///
pub async fn submit_transaction<Call: Payload, S: Signer<EntropyConfig>>(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: &S,
    call: &Call,
    nonce_option: Option<u32>,
) -> Result<ExtrinsicEvents<EntropyConfig>, SubstrateError> {
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or(SubstrateError::BlockHash)?;

    let nonce = if let Some(nonce) = nonce_option {
        nonce
    } else {
        let nonce_call =
            entropy::apis().account_nonce_api().account_nonce(signer.account_id().clone());
        api.runtime_api().at(block_hash).call(nonce_call).await?
    };

    let tx_params = Params::new().mortal(MORTALITY_BLOCKS).nonce(nonce.into()).build();
    let mut tx = api.tx().create_signed(call, signer, tx_params).await?.submit_and_watch().await?;

    while let Some(status) = tx.next().await {
        match status? {
            TxStatus::InBestBlock(tx_in_block) | TxStatus::InFinalizedBlock(tx_in_block) => {
                return Ok(tx_in_block.wait_for_success().await?);
            },
            TxStatus::Error { message }
            | TxStatus::Invalid { message }
            | TxStatus::Dropped { message } => {
                // Handle any errors:
                return Err(SubstrateError::BadEvent(message));
            },
            // Continue otherwise:
            _ => continue,
        };
    }
    Err(SubstrateError::NoEvent)
}

/// Convenience function to send a transaction to the Entropy chain giving a sr25519::Pair to sign with
pub async fn submit_transaction_with_pair<Call: Payload>(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    pair: &sr25519::Pair,
    call: &Call,
    nonce_option: Option<u32>,
) -> Result<ExtrinsicEvents<EntropyConfig>, SubstrateError> {
    let signer = PairSigner::new(pair.clone());
    submit_transaction(api, rpc, &signer, call, nonce_option).await
}

/// Gets data from the Entropy chain
///
/// Optionally takes a block hash, otherwise the latest block hash from the chain is used
pub async fn query_chain<Addr>(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    storage_call: Addr,
    block_hash_option: Option<H256>,
) -> Result<Option<Addr::Target>, SubstrateError>
where
    Addr: Address<IsFetchable = Yes>,
{
    let block_hash = if let Some(block_hash) = block_hash_option {
        block_hash
    } else {
        rpc.chain_get_block_hash(None).await?.ok_or(SubstrateError::BlockHash)?
    };

    let result = api.storage().at(block_hash).fetch(&storage_call).await?;

    Ok(result)
}

/// Returns a registered user's key visibility
#[tracing::instrument(skip_all, fields(verifying_key))]
pub async fn get_registered_details(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    verifying_key: Vec<u8>,
) -> Result<RegisteredInfo, SubstrateError> {
    tracing::info!("Querying chain for registration info.");

    let registered_info_query = entropy::storage().registry().registered(BoundedVec(verifying_key));

    let registration_info = query_chain(api, rpc, registered_info_query, None)
        .await?
        .ok_or_else(|| SubstrateError::NotRegistered)?;

    Ok(registration_info)
}

/// A wrapper around [sr25519::Pair] which implements [Signer]
/// This is needed because on wasm we cannot use the generic `subxt::tx::PairSigner`
#[derive(Clone)]
pub struct PairSigner {
    account_id: <EntropyConfig as Config>::AccountId,
    pair: sr25519::Pair,
}

impl PairSigner {
    /// Creates a new [`PairSigner`] from an [`sr25519::Pair`].
    pub fn new(pair: sr25519::Pair) -> Self {
        Self { account_id: AccountId32(pair.public().0), pair }
    }
    /// Returns the [`sp_core::sr25519::Pair`] implementation used to construct this.
    pub fn signer(&self) -> &sr25519::Pair {
        &self.pair
    }

    /// Return the account ID.
    pub fn account_id(&self) -> &AccountId32 {
        &self.account_id
    }
}

impl Signer<EntropyConfig> for PairSigner {
    fn account_id(&self) -> <EntropyConfig as Config>::AccountId {
        self.account_id.clone()
    }

    fn sign(&self, signer_payload: &[u8]) -> <EntropyConfig as Config>::Signature {
        MultiSignature::Sr25519(self.pair.sign(signer_payload).0)
    }
}
