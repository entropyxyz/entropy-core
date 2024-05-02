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
use crate::chain_api::EntropyConfig;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    storage::address::{StorageAddress, Yes},
    utils::H256,
    OnlineClient,
};
use thiserror::Error;

#[cfg(feature = "native")]
pub use submit::submit_transaction;

/// Currently not available on wasm due to needing subxt::tx::PairSigner
#[cfg(feature = "native")]
mod submit {
    use super::SubstrateError;
    use crate::chain_api::{entropy, EntropyConfig};
    use entropy_shared::MORTALITY_BLOCKS;
    use sp_core::sr25519;
    use subxt::{
        backend::legacy::LegacyRpcMethods,
        blocks::ExtrinsicEvents,
        config::PolkadotExtrinsicParamsBuilder as Params,
        tx::{PairSigner, TxPayload, TxStatus},
        OnlineClient,
    };

    /// Send a transaction to the Entropy chain
    ///
    /// Optionally takes a nonce, otherwise it grabs the latest nonce from the chain
    ///
    pub async fn submit_transaction<Call: TxPayload>(
        api: &OnlineClient<EntropyConfig>,
        rpc: &LegacyRpcMethods<EntropyConfig>,
        signer: &PairSigner<EntropyConfig, sr25519::Pair>,
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

        let latest_block = api.blocks().at_latest().await?;
        let tx_params = Params::new()
            .mortal(latest_block.header(), MORTALITY_BLOCKS)
            .nonce(nonce.into())
            .build();
        let mut tx =
            api.tx().create_signed(call, signer, tx_params).await?.submit_and_watch().await?;

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
}

/// Gets data from the Entropy chain
///
/// Optionally takes a block hash, otherwise the latest block hash from the chain is used
pub async fn query_chain<Address>(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    storage_call: Address,
    block_hash_option: Option<H256>,
) -> Result<Option<Address::Target>, SubstrateError>
where
    Address: StorageAddress<IsFetchable = Yes>,
{
    let block_hash = if let Some(block_hash) = block_hash_option {
        block_hash
    } else {
        rpc.chain_get_block_hash(None).await?.ok_or(SubstrateError::BlockHash)?
    };

    let result = api.storage().at(block_hash).fetch(&storage_call).await?;

    Ok(result)
}

/// Error relating to submitting an extrinsic or querying the chain
#[derive(Debug, Error)]
pub enum SubstrateError {
    #[error("Cannot get block hash")]
    BlockHash,
    #[error("No event following extrinsic submission")]
    NoEvent,
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Could not sumbit transaction {0}")]
    BadEvent(String),
}
