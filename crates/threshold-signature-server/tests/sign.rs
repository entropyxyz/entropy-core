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

use entropy_kvdb::clean_tests;
use entropy_testing_utils::{
    chain_api::{
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::pallet_relayer::pallet::ProgramInstance,
    },
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE,
    },
    substrate_context::test_context_stationary,
    test_client,
    tss_server_process::spawn_testing_validators,
};
use serial_test::serial;
use sp_core::crypto::Ss58Codec;
use sp_keyring::AccountKeyring;
use subxt::utils::AccountId32 as SubxtAccountId32;
use synedrion::k256::ecdsa::VerifyingKey;

use entropy_tss::{
    chain_api::{get_api, get_rpc},
    common::Hasher,
};

#[tokio::test]
#[serial]
async fn integration_test_sign() {
    clean_tests();
    let pre_registered_user = AccountKeyring::Ferdie;
    let eve = AccountKeyring::Eve;

    let signing_address = pre_registered_user.to_account_id().to_ss58check();
    let (_validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), false).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_pointer = test_client::store_program(
        &api,
        &eve.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
    )
    .await
    .unwrap();

    test_client::update_programs(
        &api,
        &rpc,
        &pre_registered_user.pair(),
        &pre_registered_user.pair(),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();

    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);

    let recoverable_signature = test_client::sign(
        &api,
        &rpc,
        pre_registered_user.pair(),
        None,
        PREIMAGE_SHOULD_SUCCEED.to_vec(),
        None,
        Some(AUXILARY_DATA_SHOULD_SUCCEED.to_vec()),
    )
    .await
    .unwrap();

    let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
        &message_should_succeed_hash,
        &recoverable_signature.signature,
        recoverable_signature.recovery_id,
    )
    .unwrap();
    assert_eq!(keyshare_option.clone().unwrap().verifying_key(), recovery_key_from_sig);
}

#[tokio::test]
#[serial]
async fn integration_test_sign_private() {
    clean_tests();
    let pre_registered_user = AccountKeyring::Eve;
    let dave = AccountKeyring::Dave;

    let signing_address = pre_registered_user.to_account_id().to_ss58check();
    let (_validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), true).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_pointer = test_client::store_program(
        &api,
        &dave.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
    )
    .await
    .unwrap();

    test_client::update_programs(
        &api,
        &rpc,
        &pre_registered_user.pair(),
        &pre_registered_user.pair(),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();

    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);

    let recoverable_signature = test_client::sign(
        &api,
        &rpc,
        pre_registered_user.pair(),
        None,
        PREIMAGE_SHOULD_SUCCEED.to_vec(),
        keyshare_option.clone(),
        Some(AUXILARY_DATA_SHOULD_SUCCEED.to_vec()),
    )
    .await
    .unwrap();

    let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
        &message_should_succeed_hash,
        &recoverable_signature.signature,
        recoverable_signature.recovery_id,
    )
    .unwrap();
    assert_eq!(keyshare_option.clone().unwrap().verifying_key(), recovery_key_from_sig);
}

#[tokio::test]
#[serial]
async fn integration_test_sign_public() {
    clean_tests();
    let pre_registered_public_user = AccountKeyring::Dave;
    let request_author = AccountKeyring::One;
    let eve = AccountKeyring::Eve;

    let signing_address = pre_registered_public_user.to_account_id().to_ss58check();
    let (_validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), false).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_pointer = test_client::store_program(
        &api,
        &eve.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
    )
    .await
    .unwrap();

    test_client::update_programs(
        &api,
        &rpc,
        &pre_registered_public_user.pair(),
        &pre_registered_public_user.pair(),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();

    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);

    let recoverable_signature = test_client::sign(
        &api,
        &rpc,
        request_author.pair(),
        Some(SubxtAccountId32(pre_registered_public_user.public().0)),
        PREIMAGE_SHOULD_SUCCEED.to_vec(),
        None,
        Some(AUXILARY_DATA_SHOULD_SUCCEED.to_vec()),
    )
    .await
    .unwrap();

    let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
        &message_should_succeed_hash,
        &recoverable_signature.signature,
        recoverable_signature.recovery_id,
    )
    .unwrap();
    assert_eq!(keyshare_option.clone().unwrap().verifying_key(), recovery_key_from_sig);
}
