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
        EntropyConfig,
    },
    client as test_client, Hasher,
};
use entropy_kvdb::clean_tests;
use entropy_testing_utils::{
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE,
    },
    jump_start_network, spawn_testing_validators, test_node_process_testing_state,
};
use serial_test::serial;
use sp_core::{sr25519, Pair};
use sp_keyring::AccountKeyring;
use subxt::{tx::PairSigner, utils::AccountId32};
use synedrion::k256::ecdsa::VerifyingKey;

#[tokio::test]
#[serial]
async fn integration_test_register_and_sign() {
    clean_tests();
    let account_owner = AccountKeyring::Ferdie.pair();
    let signature_request_author = AccountKeyring::One;

    let add_parent_key = true;
    let (_validator_ips, _validator_ids) = spawn_testing_validators(add_parent_key).await;

    let force_authoring = true;
    let substrate_context = test_node_process_testing_state(force_authoring).await;
    let api = get_api(&substrate_context.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.ws_url).await.unwrap();

    // Jumpstart the network
    let alice = AccountKeyring::Alice;
    let signer = PairSigner::<EntropyConfig, sr25519::Pair>::new(alice.clone().into());
    jump_start_network(&api, &rpc, &signer).await;

    // Store a program
    let program_pointer = test_client::store_program(
        &api,
        &rpc,
        &account_owner,
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    // Register, using that program
    let register_on_chain = true;
    let (verifying_key, _registered_info) = test_client::register(
        &api,
        &rpc,
        account_owner.clone(),
        AccountId32(account_owner.public().0),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
        register_on_chain,
    )
    .await
    .unwrap();

    // Sign a message
    let recoverable_signature = test_client::sign(
        &api,
        &rpc,
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
