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
use crate::chain_api::{entropy, EntropyConfig};
use entropy_shared::MORTALITY_BLOCKS;
use sp_core::{sr25519, Pair};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    blocks::ExtrinsicEvents,
    config::PolkadotExtrinsicParamsBuilder as Params,
    storage::address::{StorageAddress, Yes},
    tx::{Signer, TxPayload, TxStatus},
    utils::{AccountId32, MultiSignature, H256},
    Config, OnlineClient,
};

pub use crate::errors::SubstrateError;

/// Send a transaction to the Entropy chain
///
/// Optionally takes a nonce, otherwise it grabs the latest nonce from the chain
///
pub async fn submit_transaction<Call: TxPayload, S: Signer<EntropyConfig>>(
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

    let latest_block = api.blocks().at_latest().await?;
    let tx_params =
        Params::new().mortal(latest_block.header(), MORTALITY_BLOCKS).nonce(nonce.into()).build();
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
pub async fn submit_transaction_with_pair<Call: TxPayload>(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    pair: &sr25519::Pair,
    call: &Call,
    nonce_option: Option<u32>,
) -> Result<ExtrinsicEvents<EntropyConfig>, SubstrateError> {
    let signer = Sr25519Signer::new(pair.clone());
    submit_transaction(api, rpc, &signer, call, nonce_option).await
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

/// A wrapper around [sr25519::Pair] which implements [Signer]
/// This is needed because on wasm we cannot use the generic `subxt::tx::PairSigner`
#[derive(Clone)]
struct Sr25519Signer {
    account_id: <EntropyConfig as Config>::AccountId,
    pair: sr25519::Pair,
}

impl Sr25519Signer {
    /// Creates a new [`Sr25519Signer`] from an [`sr25519::Pair`].
    pub fn new(pair: sr25519::Pair) -> Self {
        Self { account_id: AccountId32(pair.public().0), pair }
    }
}

impl Signer<EntropyConfig> for Sr25519Signer {
    fn account_id(&self) -> <EntropyConfig as Config>::AccountId {
        self.account_id.clone()
    }

    fn address(&self) -> <EntropyConfig as Config>::Address {
        self.account_id.clone().into()
    }

    fn sign(&self, signer_payload: &[u8]) -> <EntropyConfig as Config>::Signature {
        MultiSignature::Sr25519(self.pair.sign(signer_payload).0)
    }
}
