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

//! Helpers for Ethereum transactions over Entropy
pub use entropy_protocol::{
    sign_and_encrypt::{derive_static_secret, SignedMessage},
    KeyParams,
};
pub use entropy_shared::{KeyVisibility, SIGNING_PARTY_SIZE};
pub use ethers::core::types::U256;
pub use synedrion::{k256::ecdsa::VerifyingKey, KeyShare};

use anyhow::{anyhow, ensure};
use entropy_protocol::RecoverableSignature;
use entropy_tss::common::Hasher;
use ethers::{
    core::{
        abi::ethabi::ethereum_types::H160,
        types::{Transaction, TransactionRequest},
        utils::{
            public_key_to_address,
            rlp::{Decodable, Rlp},
        },
    },
    providers::{Http, Middleware, Provider},
    types::{RecoveryMessage, TransactionReceipt, H256},
};

/// Convert a k256 Signature and RecoveryId to an ethers Signature
pub fn recoverable_signature_to_ethers_signature(
    recoverable_signature: RecoverableSignature,
    _chain_id: U256,
) -> ethers::core::types::Signature {
    let recovery_id_u64: u64 = recoverable_signature.recovery_id.to_byte().into();
    // let v = chain_id.as_u64() * 2 + (recovery_id_u64 + 35);
    let v: u64 = 27 + recovery_id_u64;
    let r = U256::from_big_endian(&recoverable_signature.signature.r().to_bytes());
    let s = U256::from_big_endian(&recoverable_signature.signature.s().to_bytes());

    ethers::core::types::Signature { r, s, v }
}

/// A helper for submitting Ethereum transactions for testing
pub struct TestEthereumTransaction {
    pub transaction_request: TransactionRequest,
    pub provider: Provider<Http>,
    pub from: H160,
}

impl TestEthereumTransaction {
    pub async fn new(
        provider_url: &str,
        verifying_key: VerifyingKey,
        to: H160,
        value: U256,
        nonce: U256,
    ) -> anyhow::Result<Self> {
        let from = public_key_to_address(&verifying_key);

        let provider = Provider::<Http>::try_from(provider_url)?;
        let chain_id = provider.get_chainid().await?.as_u64();

        Ok(Self {
            provider,
            transaction_request: TransactionRequest::new()
                .from(from)
                .to(to)
                .value(value)
                .gas_price(2000000000)
                .gas(60000)
                .chain_id(chain_id)
                .nonce(nonce)
                .data(b"Signed on Entropy"),
            from,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.transaction_request.rlp_unsigned().to_vec()
    }

    pub async fn submit_eth_transaction(
        &self,
        recoverable_signature: RecoverableSignature,
    ) -> anyhow::Result<Option<TransactionReceipt>> {
        let chain_id = self.provider.get_chainid().await?;
        println!("Chain ID {:?}", chain_id.as_u64());
        let ethers_signature =
            recoverable_signature_to_ethers_signature(recoverable_signature, chain_id);

        println!("Tx: {:?}", self.transaction_request);
        // Check the signature
        let recovered_eth_address = ethers_signature
            .recover(RecoveryMessage::Hash(H256(Hasher::keccak(&self.serialize()))))?;
        println!("Recoverd {:?}", recovered_eth_address);
        ensure!(recovered_eth_address == self.from, anyhow!("Cannot verify signature"));

        let signed_transaction_bytes = self.transaction_request.rlp_signed(&ethers_signature);
        let rlp = Rlp::new(&signed_transaction_bytes);
        let transaction = Transaction::decode(&rlp)?;

        // Verify the signed Transaction
        let recovered_eth_address = transaction.recover_from().unwrap();
        ensure!(recovered_eth_address == self.from, anyhow!("Cannot verify signature"));

        println!("{:?}", transaction);
        println!("transaction: 0x{}", hex::encode(transaction.rlp()));

        let receipt = self
            .provider
            .send_raw_transaction(transaction.rlp())
            .await?
            .log_msg("Transaction pending")
            .await?;
        Ok(receipt)
    }
}
