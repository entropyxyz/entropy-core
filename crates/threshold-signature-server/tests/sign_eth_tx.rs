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

use entropy_client::{
    chain_api::{
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance, get_api, get_rpc,
    },
    client as test_client, Hasher,
};
use entropy_kvdb::clean_tests;
use entropy_protocol::{decode_verifying_key, RecoverableSignature};
use entropy_shared::EVE_VERIFYING_KEY;
use entropy_testing_utils::{
    constants::{AUXILARY_DATA_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE},
    spawn_testing_validators,
    substrate_context::test_context_stationary,
};
use ethers_core::{
    abi::ethabi::ethereum_types::{H160, H256},
    types::{RecoveryMessage, Transaction, TransactionRequest, U256},
    utils::{
        public_key_to_address,
        rlp::{Decodable, Rlp},
    },
};
use serial_test::serial;
use sp_keyring::AccountKeyring;
use synedrion::k256::ecdsa::VerifyingKey;

const GOERLI_CHAIN_ID: u64 = 5;

#[tokio::test]
#[serial]
async fn integration_test_sign_eth_tx() {
    clean_tests();
    let pre_registered_user = AccountKeyring::Eve;

    let (_validator_ips, _validator_ids) = spawn_testing_validators().await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_pointer = test_client::store_program(
        &api,
        &rpc,
        &pre_registered_user.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    test_client::update_programs(
        &api,
        &rpc,
        EVE_VERIFYING_KEY,
        &pre_registered_user.pair(),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();

    // Get the public key to use in the 'from' field
    let verifying_key = decode_verifying_key(&EVE_VERIFYING_KEY).unwrap();

    let transaction_request = create_unsigned_eth_tx(verifying_key);

    let message = transaction_request.rlp_unsigned().to_vec();

    let message_hash = Hasher::keccak(&message);

    let recoverable_signature = test_client::sign(
        &api,
        &rpc,
        pre_registered_user.pair(),
        EVE_VERIFYING_KEY,
        message,
        Some(AUXILARY_DATA_SHOULD_SUCCEED.to_vec()),
    )
    .await
    .unwrap();

    let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
        &message_hash,
        &recoverable_signature.signature,
        recoverable_signature.recovery_id,
    )
    .unwrap();
    assert_eq!(verifying_key, recovery_key_from_sig);

    let ethers_signature = recoverable_signature_to_ethers_signature(recoverable_signature);

    // Check the signature
    let recovered_eth_address =
        ethers_signature.recover(RecoveryMessage::Hash(H256(message_hash))).unwrap();
    assert_eq!(recovered_eth_address, public_key_to_address(&verifying_key));

    let signed_transaction_bytes = transaction_request.rlp_signed(&ethers_signature);
    let rlp = Rlp::new(&signed_transaction_bytes);
    let transaction = Transaction::decode(&rlp).unwrap();

    // To be sure that the message we are verifying, matches the message that we signed, convert
    // Transaction back into transaction request
    let back_into_transaction_request: TransactionRequest = (&transaction).into();
    // Check that the hashes match
    assert_eq!(message_hash, Hasher::keccak(&back_into_transaction_request.rlp()));

    // Verify the signed Transaction
    let recovered_eth_address = transaction.recover_from().unwrap();
    assert_eq!(recovered_eth_address, public_key_to_address(&verifying_key));
}

/// Convert a k256 Signature and RecoveryId to an ethers Signature
fn recoverable_signature_to_ethers_signature(
    recoverable_signature: RecoverableSignature,
) -> ethers_core::types::Signature {
    let recovery_id_u64: u64 = recoverable_signature.recovery_id.to_byte().into();
    let v: u64 = 27 + recovery_id_u64;
    let r = U256::from_big_endian(&recoverable_signature.signature.r().to_bytes());
    let s = U256::from_big_endian(&recoverable_signature.signature.s().to_bytes());

    ethers_core::types::Signature { r, s, v }
}

/// Create a mock Ethereum transaction request
fn create_unsigned_eth_tx(verifying_key: VerifyingKey) -> TransactionRequest {
    let from = public_key_to_address(&verifying_key);
    let to = H160::zero();
    TransactionRequest::pay(to, 1000).from(from).chain_id(GOERLI_CHAIN_ID)
}
