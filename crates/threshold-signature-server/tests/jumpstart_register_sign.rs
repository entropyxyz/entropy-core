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
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance,
    },
    client as test_client, Hasher,
};
use entropy_kvdb::clean_tests;
use entropy_testing_utils::{
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE,
    },
    helpers::spawn_tss_nodes_and_start_chain,
    ChainSpecType,
};
use entropy_tss::helpers::tests::{do_jump_start, initialize_test_logger};
use k256::ecdsa::VerifyingKey;
use serial_test::serial;
use sp_core::Pair;
use sp_keyring::sr25519::Keyring;
use subxt::utils::AccountId32;

// FIXME (#1119): This fails intermittently and needs to be addressed. For now we ignore it since
// it's producing false negatives on our CI runs.
#[ignore]
#[tokio::test]
#[serial]
async fn integration_test_register_sign() {
    initialize_test_logger().await;
    clean_tests();

    let spawn_results = spawn_tss_nodes_and_start_chain(ChainSpecType::Integration).await;

    // First jumpstart the network
    do_jump_start(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        Keyring::Alice.pair(),
    )
    .await;

    // Now register an account
    let account_owner = Keyring::Ferdie.pair();
    let signature_request_author = Keyring::One;

    // Store a program
    let program_pointer = test_client::store_program(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &account_owner,
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    // Register, using that program
    let (verifying_key, _registered_info) = test_client::register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        account_owner.clone(),
        AccountId32(account_owner.public().0),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();

    // Sign a message
    let recoverable_signature = test_client::sign(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        signature_request_author.pair(),
        verifying_key,
        PREIMAGE_SHOULD_SUCCEED.to_vec(),
        Some(AUXILARY_DATA_SHOULD_SUCCEED.to_vec()),
    )
    .await
    .unwrap();

    // Check the signature
    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
        &message_should_succeed_hash,
        &recoverable_signature.signature,
        recoverable_signature.recovery_id,
    )
    .unwrap();
    assert_eq!(
        verifying_key.to_vec(),
        recovery_key_from_sig.to_encoded_point(true).to_bytes().to_vec()
    );
}
