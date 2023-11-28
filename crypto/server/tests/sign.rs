use kvdb::clean_tests;
use serial_test::serial;
use sp_core::crypto::Ss58Codec;
use sp_keyring::AccountKeyring;
use subxt::utils::AccountId32 as SubxtAccountId32;
use synedrion::k256::ecdsa::VerifyingKey;
use testing_utils::{
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE,
    },
    substrate_context::test_context_stationary,
    test_client,
    tss_server_process::spawn_testing_validators,
};

use server::{
    chain_api::{get_api, get_rpc},
    common::Hasher,
};

#[tokio::test]
#[serial]
async fn integration_test_sign() {
    clean_tests();
    let pre_registered_user = AccountKeyring::Dave;

    let signing_address = pre_registered_user.clone().to_account_id().to_ss58check();
    let (_validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), false).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    test_client::update_program(
        &api,
        SubxtAccountId32(pre_registered_user.into()),
        &pre_registered_user.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
    )
    .await
    .unwrap();

    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);

    let recoverable_signature = test_client::sign(
        &api,
        &rpc,
        pre_registered_user.pair(),
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

    let signing_address = pre_registered_user.clone().to_account_id().to_ss58check();
    let (_validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), true).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    test_client::update_program(
        &api,
        SubxtAccountId32(pre_registered_user.into()),
        &pre_registered_user.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
    )
    .await
    .unwrap();

    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);

    let recoverable_signature = test_client::sign(
        &api,
        &rpc,
        pre_registered_user.pair(),
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
