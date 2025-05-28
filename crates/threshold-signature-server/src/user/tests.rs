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

use anyhow::{anyhow, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use entropy_client::substrate::get_registered_details;
use entropy_client::{
    client as test_client,
    client::update_programs,
    substrate::{submit_transaction_with_pair, PairSigner},
    user::{get_all_signers_from_chain, UserSignatureRequest},
};
use entropy_kvdb::clean_tests;
use entropy_protocol::{
    decode_verifying_key,
    protocol_transport::{noise::noise_handshake_initiator, SubscribeMessage},
    SessionId, SigningSessionInfo, ValidatorInfo,
};
use entropy_shared::{
    HashingAlgorithm, OcwMessageDkg, DAVE_VERIFYING_KEY, DEFAULT_VERIFYING_KEY_NOT_REGISTERED,
    DEVICE_KEY_HASH, NETWORK_PARENT_KEY,
};
use entropy_testing_utils::{
    chain_api::{
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec as OtherBoundedVec,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance as OtherProgramInstance,
    },
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, BOB_STASH_ADDRESS, CHARLIE_STASH_ADDRESS, FAUCET_PROGRAM,
        FERDIE_X25519_SECRET_KEY, PREIMAGE_SHOULD_SUCCEED, TEST_BASIC_TRANSACTION,
        TEST_INFINITE_LOOP_BYTECODE, TEST_ORACLE_BYTECODE, TEST_PROGRAM_CUSTOM_HASH,
        TEST_PROGRAM_WASM_BYTECODE, TSS_ACCOUNTS, X25519_PUBLIC_KEYS,
    },
    helpers::spawn_tss_nodes_and_start_chain,
    substrate_context::{test_context_stationary, testing_context},
    test_node_process_testing_state, ChainSpecType,
};
use futures::future::try_join_all;
use k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey};
use more_asserts as ma;
use parity_scale_codec::Encode;
use rand::Rng;
use schemars::{schema_for, JsonSchema};
use schnorrkel::{signing_context, Keypair as Sr25519Keypair, Signature as Sr25519Signature};
use serde::{Deserialize, Serialize};
use serial_test::serial;
use sp_core::{hashing::blake2_256, sr25519, sr25519::Signature, Pair};
use sp_keyring::{sr25519::Keyring, Sr25519Keyring};
use std::{str, str::FromStr, time::Duration};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    config::DefaultExtrinsicParamsBuilder as Params,
    tx::TxStatus,
    utils::{AccountId32 as subxtAccountId32, MultiAddress, MultiSignature},
    OnlineClient,
};
use synedrion::DeriveChildKey;
use tokio_tungstenite::connect_async;

use crate::{
    chain_api::{
        entropy, entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::entropy_runtime::RuntimeCall,
        entropy::runtime_types::pallet_balances::pallet::Call as BalancesCall,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance, get_api, get_rpc,
        EntropyConfig,
    },
    helpers::{
        app_state::BlockNumberFields,
        launch::{
            build_db_path, development_mnemonic, setup_kv_store, Configuration, ValidatorName,
            DEFAULT_ENDPOINT,
        },
        signing::Hasher,
        substrate::{get_oracle_data, get_signers_from_chain, query_chain, submit_transaction},
        tests::{
            do_jump_start, get_port, initialize_test_logger, run_to_block, setup_client,
            spawn_testing_validators, store_program_and_register, unsafe_get_network_keyshare,
        },
        user::compute_hash,
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    r#unsafe::api::{UnsafeBlockNumberQuery, UnsafeQuery, UnsafeRequestLimitQuery},
    user::api::{
        check_hash_pointer_out_of_bounds, increment_or_wipe_request_limit, request_limit_check,
        validate_jump_start, RelayerSignatureRequest,
    },
    validation::EncryptedSignedMessage,
    AppState,
};

#[tokio::test]
#[serial]
async fn test_signature_requests_fail_on_different_conditions() {
    initialize_test_logger().await;
    clean_tests();

    let one = Keyring::One;
    let two = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;
    let mnemonic = development_mnemonic(&Some(ValidatorName::Alice));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        non_signer,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    // Register the user with a test program
    let (verifying_key, program_hash) = store_program_and_register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &one.pair(),
        &two.pair(),
    )
    .await;

    // Test: We check that an account with a program succeeds in submiting a signature request
    let (_validators_info, mut signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;

    // The account we registered does have a program pointer, so this should succeed
    let test_user_res =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    let message_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let decoded_verifying_key =
        decode_verifying_key(verifying_key.as_slice().try_into().unwrap()).unwrap();

    let all_signers_info = get_all_signers_from_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await
    .unwrap();
    verify_signature(test_user_res, message_hash, &decoded_verifying_key, &all_signers_info).await;

    signature_request.block_number =
        spawn_results.chain_connection.rpc.chain_get_header(None).await.unwrap().unwrap().number;

    let mock_client = reqwest::Client::new();

    let signed_message = EncryptedSignedMessage::new(
        &one.pair(),
        serde_json::to_vec(&signature_request.clone()).unwrap(),
        &X25519_PUBLIC_KEYS[0],
        &[],
    )
    .unwrap();
    let url = format!("http://{}/v1/user/sign_tx", spawn_results.validator_ips[0]);
    let signature_request_responses_fail_not_relayer = mock_client
        .post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&signed_message).unwrap())
        .send()
        .await;
    assert_eq!(
        signature_request_responses_fail_not_relayer.unwrap().text().await.unwrap(),
        "Message sent directly to signer"
    );

    // Test: A user that is not registered is not able to send a signature request

    signature_request.block_number =
        spawn_results.chain_connection.rpc.chain_get_header(None).await.unwrap().unwrap().number;
    signature_request.signature_verifying_key = DEFAULT_VERIFYING_KEY_NOT_REGISTERED.to_vec();
    let test_user_res_not_registered =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), two)
            .await;

    assert_eq!(
        test_user_res_not_registered.unwrap().text().await.unwrap(),
        "Substrate: User is not registered on-chain"
    );

    let test_user_res_not_registered_sign_tx = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        relayer_ip_and_key.clone(),
        signature_request.clone(),
        tss_signer.signer().clone(),
        None,
    )
    .await;

    assert_eq!(
        test_user_res_not_registered_sign_tx.unwrap().text().await.unwrap(),
        "Substrate: User is not registered on-chain"
    );

    // Test: Signature requests fail if no auxiliary data is set

    // The test program is written to fail when `auxilary_data` is `None`
    signature_request.block_number =
        spawn_results.chain_connection.rpc.chain_get_header(None).await.unwrap().unwrap().number;
    signature_request.signature_verifying_key = verifying_key.to_vec();
    signature_request.auxilary_data = None;

    let test_user_failed_programs_res =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    assert_eq!(
            test_user_failed_programs_res.unwrap().text().await.unwrap(),
            "Runtime error: Runtime(Error::Evaluation(\"This program requires that `auxilary_data` be `Some`.\"))"
        );

    let test_user_failed_programs_res_sign_tx = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        relayer_ip_and_key.clone(),
        signature_request.clone(),
        tss_signer.signer().clone(),
        None,
    )
    .await;

    assert_eq!(
        test_user_failed_programs_res_sign_tx.unwrap().text().await.unwrap(),
        "Runtime error: Runtime(Error::Evaluation(\"This program requires that `auxilary_data` be `Some`.\"))"
    );

    // The test program is written to fail when `auxilary_data` is `None` but only on the second
    // program
    update_programs(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        verifying_key.as_slice().try_into().unwrap(),
        &two.pair(),
        OtherBoundedVec(vec![
            OtherProgramInstance {
                program_pointer: subxt::utils::H256(program_hash.into()),
                program_config: vec![],
            },
            OtherProgramInstance {
                program_pointer: subxt::utils::H256(program_hash.into()),
                program_config: vec![],
            },
        ]),
    )
    .await
    .unwrap();

    signature_request.block_number =
        spawn_results.chain_connection.rpc.chain_get_header(None).await.unwrap().unwrap().number;
    signature_request.signature_verifying_key = verifying_key.to_vec();
    signature_request.auxilary_data = Some(vec![Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED))]);

    let test_user_failed_aux_data =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    assert_eq!(
        test_user_failed_aux_data.unwrap().text().await.unwrap(),
        "Auxilary data is mismatched"
    );

    let test_user_failed_aux_data_sign_tx = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        relayer_ip_and_key.clone(),
        signature_request.clone(),
        tss_signer.signer().clone(),
        None,
    )
    .await;

    assert_eq!(
        test_user_failed_aux_data_sign_tx.unwrap().text().await.unwrap(),
        "Auxilary data is mismatched"
    );

    // Test: Signature requests fails if a user provides an invalid hashing algorithm option

    signature_request.block_number =
        spawn_results.chain_connection.rpc.chain_get_header(None).await.unwrap().unwrap().number;
    signature_request.signature_verifying_key = verifying_key.to_vec();
    signature_request.hash = HashingAlgorithm::Custom(3);

    let test_user_custom_hash_out_of_bounds =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), two)
            .await;

    assert_eq!(
        test_user_custom_hash_out_of_bounds.unwrap().text().await.unwrap(),
        "Custom hash choice out of bounds"
    );

    let test_user_custom_hash_out_of_bounds_sign_tx = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        relayer_ip_and_key.clone(),
        signature_request.clone(),
        tss_signer.signer().clone(),
        None,
    )
    .await;

    assert_eq!(
        test_user_custom_hash_out_of_bounds_sign_tx.unwrap().text().await.unwrap(),
        "Custom hash choice out of bounds"
    );

    // Test: Signature requests fails if a the network parent key is used

    signature_request.block_number =
        spawn_results.chain_connection.rpc.chain_get_header(None).await.unwrap().unwrap().number;
    signature_request.signature_verifying_key = NETWORK_PARENT_KEY.as_bytes().to_vec();

    let test_user_sign_with_parent_key =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    assert_eq!(
        test_user_sign_with_parent_key.unwrap().text().await.unwrap(),
        "No signing from parent key"
    );

    let test_user_sign_with_parent_key_sign_tx = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        relayer_ip_and_key.clone(),
        signature_request.clone(),
        tss_signer.signer().clone(),
        None,
    )
    .await;

    assert_eq!(
        test_user_sign_with_parent_key_sign_tx.unwrap().text().await.unwrap(),
        "No signing from parent key"
    );

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_signature_requests_fail_validator_info_wrong() {
    initialize_test_logger().await;
    clean_tests();

    let one = Keyring::One;
    let two = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;
    let mnemonic = development_mnemonic(&Some(ValidatorName::Alice));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, tss_account) = validator_name_to_relayer_info(
        non_signer,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    // Register the user with a test program
    let (verifying_key, _program_hash) = store_program_and_register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &one.pair(),
        &two.pair(),
    )
    .await;

    // Test: We check that a relayed signature request with less than t validators selected fails
    let (mut validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;

    // Pops off a validator to trigger the too few validator check
    validators_info.pop();

    let test_user_res_not_registered_sign_tx = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        relayer_ip_and_key.clone(),
        signature_request.clone(),
        tss_signer.signer().clone(),
        Some(validators_info.clone()),
    )
    .await;

    assert_eq!(
        test_user_res_not_registered_sign_tx.unwrap().text().await.unwrap(),
        "Too few signers selected"
    );
    // Adds on a dummy validator to trigger the validator check
    validators_info.push(ValidatorInfo {
        x25519_public_key: relayer_ip_and_key.clone().1,
        ip_address: relayer_ip_and_key.clone().0,
        tss_account,
    });

    let test_user_res_wrong_validator = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        relayer_ip_and_key.clone(),
        signature_request.clone(),
        tss_signer.signer().clone(),
        Some(validators_info),
    )
    .await;

    assert_eq!(
        test_user_res_wrong_validator.unwrap().text().await.unwrap(),
        "Non signer sent from relayer"
    );

    clean_tests();
}

#[tokio::test]
#[serial]
async fn signature_request_with_derived_account_works() {
    initialize_test_logger().await;
    clean_tests();

    let alice = Keyring::Alice;
    let bob = Keyring::Bob;
    let charlie = Keyring::Charlie;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        ValidatorName::Dave,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    // Register the user with a test program
    let (verifying_key, _program_hash) = store_program_and_register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &charlie.pair(),
        &bob.pair(),
    )
    .await;

    let (_validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;
    let signature_request_responses =
        submit_transaction_request(relayer_ip_and_key, signature_request.clone(), alice).await;

    // We expect that the signature we get back is valid
    let message_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let verifying_key =
        VerifyingKey::try_from(signature_request.signature_verifying_key.as_slice()).unwrap();

    let all_signers_info = get_all_signers_from_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await
    .unwrap();
    verify_signature(signature_request_responses, message_hash, &verifying_key, &all_signers_info)
        .await;

    clean_tests();
}

#[tokio::test]
#[serial]
async fn signature_request_overload() {
    initialize_test_logger().await;
    clean_tests();

    let alice = Keyring::Alice;
    let bob = Keyring::Bob;
    let charlie = Keyring::Charlie;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        ValidatorName::Dave,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    // Register the user with a test program
    let (verifying_key, _program_hash) = store_program_and_register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &charlie.pair(),
        &bob.pair(),
    )
    .await;

    let sends = 15;
    let mut calls = Vec::with_capacity(sends);
    let mut rng = rand::thread_rng();

    for _ in 0..sends {
        let randomness: u128 = rng.gen();
        let (_validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
            &spawn_results.chain_connection.api,
            &spawn_results.chain_connection.rpc,
            hex::encode(randomness.encode()),
            verifying_key,
        )
        .await;
        calls.push(signature_request);
    }

    // Spawn all signature requests with proper error handling
    let tasks: Vec<_> = calls
        .into_iter()
        .map(|signature_request| {
            let api = spawn_results.chain_connection.api.clone();
            let rpc = spawn_results.chain_connection.rpc.clone();
            let relayer_ip_and_key = relayer_ip_and_key.clone();

            tokio::spawn(async move {
                let signature_request_responses = submit_transaction_request(
                    relayer_ip_and_key,
                    signature_request.clone(),
                    alice,
                )
                .await
                .map_err(|e| anyhow!("Failed to submit transaction request: {}", e))?;

                let message_hash = Hasher::keccak(&hex::decode(signature_request.message).unwrap());
                let verifying_key =
                    VerifyingKey::try_from(signature_request.signature_verifying_key.as_slice())
                        .map_err(|e| anyhow!("Failed to parse verifying key: {}", e))?;

                let all_signers_info = get_all_signers_from_chain(&api, &rpc)
                    .await
                    .map_err(|e| anyhow!("Failed to fetch signers from chain: {}", e))?;

                verify_signature(
                    Ok(signature_request_responses),
                    message_hash,
                    &verifying_key,
                    &all_signers_info,
                )
                .await;

                Ok::<(), anyhow::Error>(())
            })
        })
        .collect();

    // Await all tasks and propagate errors
    let _results = try_join_all(tasks).await.unwrap();

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_signing_fails_if_wrong_participants_are_used() {
    initialize_test_logger().await;
    clean_tests();

    let one = Keyring::Dave;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        non_signer,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;
    let relayer_url = format!("http://{}/v1/user/relay_tx", relayer_ip_and_key.0.clone());

    let mock_client = reqwest::Client::new();

    let (_validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        DAVE_VERIFYING_KEY,
    )
    .await;

    // fails verification tests
    // wrong key for wrong validator
    let failed_signed_message = EncryptedSignedMessage::new(
        &one.pair(),
        serde_json::to_vec(&signature_request.clone()).unwrap(),
        &X25519_PUBLIC_KEYS[1],
        &[],
    )
    .unwrap();
    let failed_res = mock_client
        .post("http://127.0.0.1:3001/v1/user/sign_tx")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&failed_signed_message).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(failed_res.status(), 500);
    assert_eq!(
        failed_res.text().await.unwrap(),
        "Encryption or signing error: Hpke: HPKE Error: OpenError"
    );

    let failed_res_relay = mock_client
        .post(relayer_url.clone())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&failed_signed_message).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(failed_res_relay.status(), 500);
    assert_eq!(
        failed_res_relay.text().await.unwrap(),
        "Encryption or signing error: Hpke: HPKE Error: OpenError"
    );

    let sig: [u8; 64] = [0; 64];
    let user_input_bad = EncryptedSignedMessage::new_with_given_signature(
        &one.pair(),
        serde_json::to_vec(&signature_request.clone()).unwrap(),
        &X25519_PUBLIC_KEYS[0],
        &[],
        sr25519::Signature::from_raw(sig),
    )
    .unwrap();

    let failed_sign = mock_client
        .post("http://127.0.0.1:3001/v1/user/sign_tx")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&user_input_bad).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(failed_sign.status(), 500);
    assert_eq!(
        failed_sign.text().await.unwrap(),
        "Encryption or signing error: Cannot verify signature"
    );

    let user_input_bad_relayer = EncryptedSignedMessage::new_with_given_signature(
        &one.pair(),
        serde_json::to_vec(&signature_request.clone()).unwrap(),
        &relayer_ip_and_key.1,
        &[],
        sr25519::Signature::from_raw(sig),
    )
    .unwrap();

    let failed_sign_relay = mock_client
        .post(relayer_url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&user_input_bad_relayer).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(failed_sign_relay.status(), 500);
    assert_eq!(
        failed_sign_relay.text().await.unwrap(),
        "Encryption or signing error: Cannot verify signature"
    );

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_request_limit_are_updated_during_signing() {
    initialize_test_logger().await;
    clean_tests();

    let one = Keyring::One;
    let two = Keyring::Two;

    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(crate::helpers::tests::ChainSpecType::IntegrationJumpStarted)
            .await;

    let force_authoring = true;
    let context =
        test_node_process_testing_state(ChainSpecType::IntegrationJumpStarted, force_authoring)
            .await;
    let entropy_api = get_api(&context[0].ws_url).await.unwrap();
    let rpc = get_rpc(&context[0].ws_url).await.unwrap();

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, _) =
        validator_name_to_relayer_info(non_signer, &entropy_api, &rpc).await;
    // Register the user with a test program
    let (verifying_key, _program_hash) =
        store_program_and_register(&entropy_api, &rpc, &one.pair(), &two.pair()).await;

    // Test: We check that the rate limiter changes as expected when signature requests are sent

    // First we need to get a signature request to populate the KVDB for our verifying key
    let (validators_info, mut signature_request, _validator_ips_and_keys) =
        get_sign_tx_data(&entropy_api, &rpc, hex::encode(PREIMAGE_SHOULD_SUCCEED), verifying_key)
            .await;

    let test_user_res =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    let message_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let decoded_verifying_key =
        decode_verifying_key(verifying_key.as_slice().try_into().unwrap()).unwrap();

    let all_signers_info = get_all_signers_from_chain(&entropy_api, &rpc).await.unwrap();
    verify_signature(test_user_res, message_hash, &decoded_verifying_key, &all_signers_info).await;

    // Next we check request limiter increases
    let mock_client = reqwest::Client::new();

    let unsafe_get = UnsafeQuery::new(hex::encode(verifying_key.to_vec()), vec![]).to_json();

    let get_response = mock_client
        .post(format!("http://{}/unsafe/read_from_request_limit", validators_info[0].ip_address))
        .header("Content-Type", "application/json")
        .body(unsafe_get.clone())
        .send()
        .await;

    if get_response.is_ok() {
        let request_amount = get_response.unwrap().text().await.unwrap();
        assert_eq!(request_amount.as_bytes().to_vec(), 1u32.encode());
    }

    // Test: If we send too many requests though, we'll be blocked from signing
    let request_limit_query = entropy::storage().parameters().request_limit();
    let request_limit =
        query_chain(&entropy_api, &rpc, request_limit_query, None).await.unwrap().unwrap();

    // Gets current block number, potential race condition run to block + 1
    // to reset block and give us 6 seconds to hit rate limit
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;

    let unsafe_put = UnsafeRequestLimitQuery {
        key: hex::encode(verifying_key.to_vec()),
        value: request_limit + 1u32,
    };

    // reduce race condition by increasing block number so request limit mapping does not nuke
    let unsafe_put_block_number =
        UnsafeBlockNumberQuery { key: BlockNumberFields::LatestBlock, value: block_number + 5u32 };

    for validator_info in all_signers_info {
        mock_client
            .post(format!("http://{}/unsafe/write_to_request_limit", validator_info.ip_address))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&unsafe_put).unwrap())
            .send()
            .await
            .unwrap();

        mock_client
            .post(format!("http://{}/unsafe/write_to_block_numbers", validator_info.ip_address))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&unsafe_put_block_number).unwrap())
            .send()
            .await
            .unwrap();
    }

    signature_request.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    signature_request.signature_verifying_key = verifying_key.to_vec();

    let test_user_failed_request_limit =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    assert_eq!(test_user_failed_request_limit
        .unwrap()
        .text()
        .await
        .unwrap(),
        "[{\"Err\":\"Too many requests - wait a block\"},{\"Err\":\"Too many requests - wait a block\"}]");

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_fails_to_sign_if_non_signing_group_participants_are_used() {
    initialize_test_logger().await;
    clean_tests();

    let user = Keyring::One;
    let deployer = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    // Register the user with a test program
    let (verifying_key, _program_hash) = store_program_and_register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &user.pair(),
        &deployer.pair(),
    )
    .await;

    let (_validators_info, signature_request, validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;

    let message_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);

    let non_signer = ValidatorName::Dave;
    let mnemonic = development_mnemonic(&Some(non_signer));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    let expected_account_id = tss_signer.account_id().clone();

    let session_id = SessionId::Sign(SigningSessionInfo {
        signature_verifying_key: verifying_key.to_vec(),
        message_hash,
        request_author: expected_account_id,
    });

    // Test attempting to connect over ws by someone who is not in the signing group
    let validator_ip_and_key: (String, [u8; 32]) =
        (validator_ips_and_keys[0].clone().0, validator_ips_and_keys[0].clone().1);

    let connection_attempt_handle = tokio::spawn(async move {
        // Wait for the "user" to submit the signing request
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ws_endpoint = format!("ws://{}/v1/ws", &validator_ip_and_key.0.clone());
        let (ws_stream, _response) = connect_async(ws_endpoint).await.unwrap();

        let ferdie_pair = Keyring::Ferdie.pair();

        // create a SubscribeMessage from a party who is not in the signing commitee
        let subscribe_message_vec =
            bincode::serialize(&SubscribeMessage::new(session_id, &ferdie_pair).unwrap()).unwrap();

        // Attempt a noise handshake including the subscribe message in the payload
        let mut encrypted_connection = noise_handshake_initiator(
            ws_stream,
            &FERDIE_X25519_SECRET_KEY.into(),
            validator_ip_and_key.1,
            subscribe_message_vec,
        )
        .await
        .unwrap();

        // Check the response as to whether they accepted our SubscribeMessage
        let response_message = encrypted_connection.recv().await.unwrap();
        let subscribe_response: Result<(), String> =
            bincode::deserialize(&response_message).unwrap();

        assert_eq!(Err("Decryption(\"Public key does not match any of those expected for this protocol session\")".to_string()), subscribe_response);

        // The stream should not continue to send messages
        // returns true if this part of the test passes
        encrypted_connection.recv().await.is_err()
    });

    let validator_ip_and_key: (String, [u8; 32]) =
        (validator_ips_and_keys[0].clone().0, validator_ips_and_keys[0].clone().1);

    let test_user_bad_connection_res = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        validator_ip_and_key,
        signature_request.clone(),
        tss_signer.signer().clone(),
        None,
    )
    .await;

    assert!(test_user_bad_connection_res.unwrap().text().await.unwrap().contains("Err"),);

    assert!(connection_attempt_handle.await.unwrap());

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_reports_peer_if_they_reject_our_signing_protocol_connection() {
    initialize_test_logger().await;
    clean_tests();

    // Setup: We first spin up the chain nodes, TSS servers, and register an account
    let user = Keyring::One;
    let deployer = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    // Register the user with a test program
    let (verifying_key, _program_hash) = store_program_and_register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &user.pair(),
        &deployer.pair(),
    )
    .await;

    let (_validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;

    // TSS Setup: We want Alice to be the TSS server which starts the signing protocol, so let's
    // get her set up
    let signer = ValidatorName::Alice;

    let mnemonic = development_mnemonic(&Some(signer));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    let validator_ip_and_key: (String, [u8; 32]) =
        (spawn_results.validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]);

    // The other signer can rotate between Bob and Charlie, but we want to always test with Bob
    // since we know that:
    // - As Alice, we will initiate a connection with him
    // - He won't respond to our request (never got his `/sign_tx` endpoint triggered)
    let signers = {
        let alice = ValidatorInfo {
            ip_address: spawn_results.validator_ips[0].clone(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        };

        let bob = ValidatorInfo {
            ip_address: spawn_results.validator_ips[1].clone(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone(),
        };

        vec![alice, bob]
    };

    // Before starting the test, we want to ensure that Bob has no outstanding reports against him.
    let bob_report_query =
        entropy::storage().slashing().failed_registrations(BOB_STASH_ADDRESS.clone());
    let reports = query_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        bob_report_query.clone(),
        None,
    )
    .await
    .unwrap();
    assert!(reports.is_none());

    // Test: Now, we want to initiate a signing session _without_ going through the relayer. So we
    // skip that step using this helper.
    let test_user_bad_connection_res = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        validator_ip_and_key,
        signature_request.clone(),
        tss_signer.signer().clone(),
        Some(signers),
    )
    .await;

    // Check: We expect that the signature request will have failed because we were unable to
    // connect to Bob.
    assert!(test_user_bad_connection_res
        .unwrap()
        .text()
        .await
        .unwrap()
        .contains("Subscribe message rejected"));

    // We expect that a `NoteReport` event want found
    let report_event_found = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        subscribe_to_report_event(&spawn_results.chain_connection.api),
    )
    .await
    .expect("Timed out while waiting for `NoteReport` event.");

    assert!(report_event_found);

    // We expect that the offence count for Bob has gone up
    let reports = query_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        bob_report_query,
        None,
    )
    .await
    .unwrap();
    assert!(matches!(reports, Some(1)));

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_reports_peer_if_they_dont_initiate_a_signing_session() {
    initialize_test_logger().await;
    clean_tests();

    // Setup: We first spin up the chain nodes, TSS servers, and register an account
    let user = Keyring::One;
    let deployer = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    // Register the user with a test program
    let (verifying_key, _program_hash) = store_program_and_register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &user.pair(),
        &deployer.pair(),
    )
    .await;

    let (_validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;

    // TSS Setup: We want Alice to be the TSS server which starts the signing protocol, so let's
    // get her set up
    let signer = ValidatorName::Alice;

    let mnemonic = development_mnemonic(&Some(signer));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    let validator_ip_and_key: (String, [u8; 32]) =
        (spawn_results.validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]);

    // The other signer can rotate between Bob and Charlie, but we want to always test with Charlie
    // since we know that:
    // - As Alice, Charlie will initiate a connection with us
    // - He won't initate a request (never got his `/sign_tx` endpoint triggered)
    let signers = {
        let alice = ValidatorInfo {
            ip_address: spawn_results.validator_ips[0].clone(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        };

        let charlie = ValidatorInfo {
            ip_address: spawn_results.validator_ips[2].clone(),
            x25519_public_key: X25519_PUBLIC_KEYS[2],
            tss_account: TSS_ACCOUNTS[2].clone(),
        };

        vec![alice, charlie]
    };

    // Before starting the test, we want to ensure that Charlie has no outstanding reports against him.
    let charlie_report_query =
        entropy::storage().slashing().failed_registrations(CHARLIE_STASH_ADDRESS.clone());
    let reports = query_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        charlie_report_query.clone(),
        None,
    )
    .await
    .unwrap();
    assert!(reports.is_none());

    // Test: Now, we want to initiate a signing session _without_ going through the relayer. So we
    // skip that step using this helper.
    let test_user_bad_connection_res = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        validator_ip_and_key,
        signature_request.clone(),
        tss_signer.signer().clone(),
        Some(signers),
    )
    .await;

    // Check: We expect that the signature request will have failed because Charlie never initated a
    // connection with us.
    assert!(test_user_bad_connection_res.unwrap().text().await.unwrap().contains("Timed out"));

    // We expect that a `NoteReport` event want found
    let report_event_found = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        subscribe_to_report_event(&spawn_results.chain_connection.api),
    )
    .await
    .expect("Timed out while waiting for `NoteReport` event.");

    assert!(report_event_found);

    // We expect that the offence count for Charlie has gone up
    let reports = query_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        charlie_report_query,
        None,
    )
    .await
    .unwrap();
    assert!(matches!(reports, Some(1)));

    clean_tests();
}

/// Helper for subscribing to the `NoteReport` event from the Slashing pallet.
async fn subscribe_to_report_event(api: &OnlineClient<EntropyConfig>) -> bool {
    let mut blocks_sub = api.blocks().subscribe_best().await.unwrap();

    while let Some(block) = blocks_sub.next().await {
        let block = block.unwrap();
        let events = block.events().await.unwrap();

        if events.has::<entropy::slashing::events::NoteReport>().unwrap() {
            return true;
        }
    }

    false
}

#[tokio::test]
#[serial]
async fn test_program_with_config() {
    initialize_test_logger().await;
    clean_tests();

    let one = Keyring::One;
    let two = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        non_signer,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    let program_hash = test_client::store_program(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &two.pair(),
        TEST_BASIC_TRANSACTION.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    let (verifying_key, _registered_info) = test_client::register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        one.clone().into(), // This is our program modification account
        subxtAccountId32(two.public().0), // This is our signature request account
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await
    .unwrap();

    // This message is an ethereum tx rlp encoded with a proper allow listed address
    let message = "0xef01808094772b9a9e8aa1c9db861c6611a82d251db4fac990019243726561746564204f6e20456e74726f7079018080";
    let config = r#"
        {
            "allowlisted_addresses": [
                "772b9a9e8aa1c9db861c6611a82d251db4fac990"
            ]
        }
    "#
    .as_bytes();

    // We update the program to use the new config
    update_programs(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        verifying_key.as_slice().try_into().unwrap(),
        &two.pair(),
        OtherBoundedVec(vec![
            OtherProgramInstance {
                program_pointer: subxt::utils::H256(program_hash.into()),
                program_config: config.to_vec(),
            },
            OtherProgramInstance {
                program_pointer: subxt::utils::H256(program_hash.into()),
                program_config: config.to_vec(),
            },
        ]),
    )
    .await
    .unwrap();

    // Now we'll send off a signature request using the new program
    let (_validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(message),
        verifying_key,
    )
    .await;

    // Here we check that the signature request was indeed completed successfully
    let signature_request_responses =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    let message_hash = Hasher::keccak(message.as_bytes());
    let verifying_key = decode_verifying_key(verifying_key.as_slice().try_into().unwrap()).unwrap();

    let all_signers_info = get_all_signers_from_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await
    .unwrap();
    verify_signature(signature_request_responses, message_hash, &verifying_key, &all_signers_info)
        .await;

    clean_tests();
}

// FIXME (#1119): This fails intermittently and needs to be addressed. For now we ignore it since
// it's producing false negatives on our CI runs.
#[tokio::test]
#[ignore]
#[serial]
async fn test_jumpstart_network() {
    initialize_test_logger().await;
    clean_tests();

    let (_validator_ips, _validator_ids) =
        spawn_testing_validators(crate::helpers::tests::ChainSpecType::Integration).await;

    let force_authoring = false;
    let context =
        test_node_process_testing_state(ChainSpecType::Integration, force_authoring).await;
    let api = get_api(&context[0].ws_url).await.unwrap();
    let rpc = get_rpc(&context[0].ws_url).await.unwrap();

    do_jump_start(&api, &rpc, Keyring::Alice.pair()).await;

    let signer_query = entropy::storage().staking_extension().signers();
    let signer_stash_accounts = query_chain(&api, &rpc, signer_query, None).await.unwrap().unwrap();
    let client = reqwest::Client::new();
    let mut verifying_key = Vec::new();
    for signer in signer_stash_accounts.iter() {
        let query = entropy::storage().staking_extension().threshold_servers(signer);
        let server_info = query_chain(&api, &rpc, query, None).await.unwrap().unwrap();
        let key_share = unsafe_get_network_keyshare(&client, get_port(&server_info)).await;

        // check to make sure keyshare is correct
        assert!(key_share.is_some());

        verifying_key = key_share
            .unwrap()
            .0
            .verifying_key()
            .unwrap()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
    }

    let jump_start_progress_query = entropy::storage().staking_extension().jump_start_progress();
    let jump_start_progress =
        query_chain(&api, &rpc, jump_start_progress_query, None).await.unwrap().unwrap();

    assert_eq!(jump_start_progress.verifying_key.unwrap().0, verifying_key);
    clean_tests();
}

/// Registers an account on-chain using the new registration flow.
pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signature_request_account: &Sr25519Keyring,
    program_modification_account: subxtAccountId32,
    program_instances: BoundedVec<ProgramInstance>,
) -> Result<entropy::registry::events::AccountRegistered, entropy_client::substrate::SubstrateError>
{
    let signature_request_account = PairSigner::new(signature_request_account.pair());

    let registering_tx =
        entropy::tx().registry().register(program_modification_account, program_instances);

    let events =
        submit_transaction(api, rpc, &signature_request_account, &registering_tx, None).await?;

    // Since we're only submitting one request above, looking for the first event as opposed to
    // say, all events, should be fine.
    let registered_event =
        events.find_first::<entropy::registry::events::AccountRegistered>()?.unwrap();

    Ok(registered_event)
}

#[tokio::test]
async fn test_compute_hash() {
    initialize_test_logger().await;
    clean_tests();
    let one = Keyring::Dave;
    let substrate_context = testing_context().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_hash = test_client::store_program(
        &api,
        &rpc,
        &one.pair(),
        TEST_PROGRAM_CUSTOM_HASH.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    let message_hash = compute_hash(
        &api,
        &rpc,
        &HashingAlgorithm::Custom(0),
        10000000u64,
        &vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }],
        PREIMAGE_SHOULD_SUCCEED,
    )
    .await
    .unwrap();
    // custom hash program uses blake 3 to hash
    let expected_hash = blake3::hash(PREIMAGE_SHOULD_SUCCEED).as_bytes().to_vec();
    assert_eq!(message_hash.to_vec(), expected_hash);

    const EXPECTED_MAX_HASH_LENGTH: usize = 32;
    let no_hash = vec![0u8; EXPECTED_MAX_HASH_LENGTH];
    let no_hash_too_long = vec![0u8; EXPECTED_MAX_HASH_LENGTH + 1];

    // no hash
    let message_hash_no_hash = compute_hash(
        &api,
        &rpc,
        &HashingAlgorithm::Identity,
        10000000u64,
        &vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }],
        &no_hash,
    )
    .await
    .unwrap();

    assert_eq!(message_hash_no_hash.to_vec(), no_hash);

    // no hash too long error
    let message_hash_no_hash_too_long = compute_hash(
        &api,
        &rpc,
        &HashingAlgorithm::Identity,
        10000000u64,
        &vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }],
        &no_hash_too_long,
    )
    .await;

    assert_eq!(
        message_hash_no_hash_too_long.unwrap_err().to_string(),
        "Conversion Error: could not convert slice to array".to_string()
    );
}

#[tokio::test]
async fn test_check_hash_pointer_out_of_bounds() {
    assert!(check_hash_pointer_out_of_bounds(&HashingAlgorithm::Custom(2), 5).is_ok());
    assert_eq!(
        check_hash_pointer_out_of_bounds(&HashingAlgorithm::Custom(5), 5).unwrap_err().to_string(),
        "Custom hash choice out of bounds".to_string()
    );
}

pub async fn verify_signature(
    test_user_res: Result<reqwest::Response, reqwest::Error>,
    message_should_succeed_hash: [u8; 32],
    verifying_key: &VerifyingKey,
    validators_info: &Vec<ValidatorInfo>,
) {
    let mut test_user_res = test_user_res.unwrap();
    let chunk = test_user_res.chunk().await.unwrap().unwrap();

    let signing_results: Vec<Result<(String, Signature), String>> =
        serde_json::from_slice(&chunk).unwrap();
    for signing_result in signing_results {
        assert_eq!(signing_result.clone().unwrap().0.len(), 88);
        let mut decoded_sig = BASE64_STANDARD.decode(signing_result.clone().unwrap().0).unwrap();
        let recovery_digit = decoded_sig.pop().unwrap();
        let signature = k256Signature::from_slice(&decoded_sig).unwrap();
        let recover_id = RecoveryId::from_byte(recovery_digit).unwrap();
        let recovery_key_from_sig = VerifyingKey::recover_from_prehash(
            &message_should_succeed_hash,
            &signature,
            recover_id,
        )
        .unwrap();
        assert_eq!(verifying_key, &recovery_key_from_sig);
        let mut sig_recovery_results = vec![];

        // do not know which validator created which message, run through them all
        for validator_info in validators_info {
            let sig_recovery = <sr25519::Pair as Pair>::verify(
                &signing_result.clone().unwrap().1,
                BASE64_STANDARD.decode(signing_result.clone().unwrap().0).unwrap(),
                &sr25519::Public::from(validator_info.tss_account.0),
            );
            sig_recovery_results.push(sig_recovery)
        }
        assert!(sig_recovery_results.contains(&true));
    }
}

#[tokio::test]
#[serial]
async fn test_fail_infinite_program() {
    initialize_test_logger().await;
    clean_tests();

    let one = Keyring::One;
    let two = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;
    let mnemonic = development_mnemonic(&Some(ValidatorName::Alice));
    let (tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        non_signer,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    let program_hash = test_client::store_program(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &two.pair(),
        TEST_INFINITE_LOOP_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    let (verifying_key, _registered_info) = test_client::register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        one.clone().into(), // This is our program modification account
        subxtAccountId32(two.public().0), // This is our signature request account
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await
    .unwrap();

    // Now we'll send off a signature request using the new program
    let (_validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;

    let test_infinite_loop =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    assert_eq!(test_infinite_loop.unwrap().text().await.unwrap(), "Runtime error: OutOfFuel");

    let test_infinite_loop_sign_tx = submit_transaction_sign_tx_requests(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        relayer_ip_and_key.clone(),
        signature_request.clone(),
        tss_signer.signer().clone(),
        None,
    )
    .await;

    assert_eq!(
        test_infinite_loop_sign_tx.unwrap().text().await.unwrap(),
        "Runtime error: OutOfFuel"
    );
}

#[tokio::test]
#[serial]
async fn test_oracle_program() {
    initialize_test_logger().await;
    clean_tests();

    let one = Keyring::One;
    let two = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let mnemonic = development_mnemonic(&Some(ValidatorName::Alice));
    let (_tss_signer, _static_secret) =
        get_signer_and_x25519_secret_from_mnemonic(&mnemonic.to_string()).unwrap();

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        non_signer,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    let program_hash = test_client::store_program(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &two.pair(),
        TEST_ORACLE_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec!["block_number_entropy".encode()],
        0u8,
    )
    .await
    .unwrap();

    let (verifying_key, _registered_info) = test_client::register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        one.clone().into(), // This is our program modification account
        subxtAccountId32(two.public().0), // This is our signature request account
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await
    .unwrap();

    // Now we'll send off a signature request using the new program
    let (_validators_info, signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;

    let test_user_res =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    let message_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let decoded_verifying_key =
        decode_verifying_key(verifying_key.as_slice().try_into().unwrap()).unwrap();
    let all_signers_info = get_all_signers_from_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await
    .unwrap();
    verify_signature(test_user_res, message_hash, &decoded_verifying_key, &all_signers_info).await;
}

#[tokio::test]
#[serial]
async fn test_device_key_proxy() {
    initialize_test_logger().await;
    clean_tests();

    /// JSON-deserializable struct that will be used to derive the program-JSON interface.
    /// Note how this uses JSON-native types only.
    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
    pub struct UserConfig {
        /// base64-encoded compressed point (33-byte) ECDSA public keys, (eg. "A572dqoue5OywY/48dtytQimL9WO0dpSObaFbAxoEWW9")
        pub ecdsa_public_keys: Option<Vec<String>>,
        pub sr25519_public_keys: Option<Vec<String>>,
        pub ed25519_public_keys: Option<Vec<String>>,
    }

    /// JSON representation of the auxiliary data
    #[cfg_attr(feature = "std", derive(schemars::JsonSchema))]
    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
    pub struct AuxData {
        /// "ecdsa", "ed25519", "sr25519"
        pub public_key_type: String,
        /// base64-encoded public key
        pub public_key: String,
        /// base64-encoded signature
        pub signature: String,
        /// The context for the signature only needed in sr25519 signature type
        pub context: String,
    }

    let one = Keyring::One;
    let two = Keyring::Two;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        non_signer,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    // We need to store a program in order to be able to register succesfully
    let program_hash = test_client::store_program(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &two.pair(), // This is our program deployer
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    let (verifying_key, _registered_info) = test_client::register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        one.clone().into(), // This is our program modification account
        subxtAccountId32(two.public().0), // This is our signature request account
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await
    .unwrap();

    let keypair = Sr25519Keypair::generate();
    let public_key = BASE64_STANDARD.encode(keypair.public);

    let device_key_user_config = UserConfig {
        ecdsa_public_keys: None,
        sr25519_public_keys: Some(vec![public_key.clone()]),
        ed25519_public_keys: None,
    };

    // check to make sure config data stored properly
    let program_query =
        entropy::storage().programs().programs(subxt::utils::H256(DEVICE_KEY_HASH.0));
    let program_data = query_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        program_query,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    let schema_config_device_key_proxy = schema_for!(UserConfig);
    let schema_aux_data_device_key_proxy = schema_for!(AuxData);

    assert_eq!(
        serde_json::to_vec(&schema_config_device_key_proxy).unwrap(),
        program_data.configuration_schema,
        "configuration interface recoverable through schemars"
    );
    assert_eq!(
        serde_json::to_vec(&schema_aux_data_device_key_proxy).unwrap(),
        program_data.auxiliary_data_schema,
        "aux data interface recoverable through schemers"
    );

    update_programs(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        verifying_key.as_slice().try_into().unwrap(),
        &two.pair(),
        OtherBoundedVec(vec![OtherProgramInstance {
            program_pointer: subxt::utils::H256(DEVICE_KEY_HASH.0),
            program_config: serde_json::to_vec(&device_key_user_config).unwrap(),
        }]),
    )
    .await
    .unwrap();

    // We now set up the auxilary data for our program
    let context = signing_context(b"");
    let sr25519_signature: Sr25519Signature = keypair.sign(context.bytes(PREIMAGE_SHOULD_SUCCEED));

    let aux_data_json_sr25519 = AuxData {
        public_key_type: "sr25519".to_string(),
        public_key,
        signature: BASE64_STANDARD.encode(sr25519_signature.to_bytes()),
        context: "".to_string(),
    };

    let auxilary_data = Some(vec![Some(hex::encode(
        &serde_json::to_string(&aux_data_json_sr25519.clone()).unwrap(),
    ))]);

    // Now we'll send off a signature request using the new program with auxilary data
    let (_validators_info, mut signature_request, _validator_ips_and_keys) = get_sign_tx_data(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        hex::encode(PREIMAGE_SHOULD_SUCCEED),
        verifying_key,
    )
    .await;

    signature_request.auxilary_data = auxilary_data;

    let test_user_res =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;

    let message_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let verifying_key = decode_verifying_key(verifying_key.as_slice().try_into().unwrap()).unwrap();
    let all_signers_info = get_all_signers_from_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await
    .unwrap();
    verify_signature(test_user_res, message_hash, &verifying_key, &all_signers_info).await;
}

#[tokio::test]
#[serial]
async fn test_faucet() {
    initialize_test_logger().await;
    clean_tests();
    /// JSON representation of the auxiliary data
    #[cfg_attr(feature = "std", derive(schemars::JsonSchema))]
    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
    pub struct AuxData {
        pub spec_version: u32,
        pub transaction_version: u32,
        pub string_account_id: String,
        pub amount: u128,
    }

    /// JSON-deserializable struct that will be used to derive the program-JSON interface.
    #[cfg_attr(feature = "std", derive(schemars::JsonSchema))]
    #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
    pub struct UserConfig {
        max_transfer_amount: u128,
        genesis_hash: String,
    }

    let one = Keyring::Dave;
    let two = Keyring::Eve;
    let alice = Keyring::Alice;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let non_signer = ValidatorName::Dave;
    let (relayer_ip_and_key, _) = validator_name_to_relayer_info(
        non_signer,
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
    )
    .await;

    let program_hash = test_client::store_program(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &two.pair(),
        FAUCET_PROGRAM.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    let amount_to_send = 200000001;
    let genesis_hash = &spawn_results.chain_connection.api.genesis_hash();

    let faucet_user_config = UserConfig {
        max_transfer_amount: amount_to_send,
        genesis_hash: hex::encode(genesis_hash.encode()),
    };

    let (verifying_key, _registered_info) = test_client::register(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        one.clone().into(), // This is our program modification account
        subxtAccountId32(two.public().0), // This is our signature request account
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await
    .unwrap();

    let verfiying_key_account_hash = blake2_256(&verifying_key);
    let verfiying_key_account = subxtAccountId32(verfiying_key_account_hash);

    // Add funds to faucet
    let call = RuntimeCall::Balances(BalancesCall::force_set_balance {
        who: verfiying_key_account.clone().into(),
        new_free: 10000000000000000000000u128,
    });
    let add_balance_tx = entropy::tx().sudo().sudo(call);

    let signature_request_pair_signer = PairSigner::new(alice.into());

    let tx_params_balance = Params::new().build();
    spawn_results
        .chain_connection
        .api
        .tx()
        .create_signed(&add_balance_tx, &signature_request_pair_signer, tx_params_balance)
        .await
        .unwrap()
        .submit_and_watch()
        .await
        .unwrap();

    update_programs(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        verifying_key.clone().try_into().unwrap(),
        &two.pair(),
        OtherBoundedVec(vec![OtherProgramInstance {
            program_pointer: program_hash,
            program_config: serde_json::to_vec(&faucet_user_config).unwrap(),
        }]),
    )
    .await
    .unwrap();

    // get tx data for aux data
    let spec_version = spawn_results.chain_connection.api.runtime_version().spec_version;
    let transaction_version =
        spawn_results.chain_connection.api.runtime_version().transaction_version;

    let aux_data = AuxData {
        spec_version,
        transaction_version,
        string_account_id: one.to_account_id().to_string(),
        amount: amount_to_send,
    };
    // create a partial tx to sign
    let tx_params = Params::new().build();
    let balance_transfer_tx = entropy::tx()
        .balances()
        .transfer_allow_death(MultiAddress::Id(subxtAccountId32(one.public().0)), aux_data.amount);
    let mut partial = spawn_results
        .chain_connection
        .api
        .tx()
        .create_partial_offline(&balance_transfer_tx, tx_params)
        .unwrap();

    let mut signature_request = UserSignatureRequest {
        message: hex::encode(partial.signer_payload()),
        auxilary_data: Some(vec![Some(hex::encode(
            &serde_json::to_string(&aux_data.clone()).unwrap(),
        ))]),
        block_number: spawn_results
            .chain_connection
            .rpc
            .chain_get_header(None)
            .await
            .unwrap()
            .unwrap()
            .number,
        hash: HashingAlgorithm::Blake2_256,
        signature_verifying_key: verifying_key.clone().to_vec(),
    };

    signature_request.block_number =
        spawn_results.chain_connection.rpc.chain_get_header(None).await.unwrap().unwrap().number;
    let test_user_res =
        submit_transaction_request(relayer_ip_and_key.clone(), signature_request.clone(), one)
            .await;
    let chunk = test_user_res.unwrap().chunk().await.unwrap().unwrap();
    let signing_result: Vec<Result<(String, Signature), String>> =
        serde_json::from_slice(&chunk).unwrap();
    let decoded_sig = BASE64_STANDARD.decode(signing_result.clone()[0].clone().unwrap().0).unwrap();

    // take signed tx and repack it into a submitable tx
    let submittable_extrinsic = partial.sign_with_account_and_signature(
        &verfiying_key_account.clone().into(),
        &MultiSignature::Ecdsa(decoded_sig.try_into().unwrap()),
    );
    let account = subxtAccountId32::from_str(&aux_data.string_account_id).unwrap();
    // get balance before for checking if succeful
    let balance_query = entropy::storage().system().account(account.clone());
    let account_info = query_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        balance_query,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    let balance_before = account_info.data.free;
    // submit then wait for tx
    let mut tx = submittable_extrinsic.submit_and_watch().await.unwrap();

    while let Some(status) = tx.next().await {
        match status.unwrap() {
            TxStatus::InBestBlock(tx_in_block) | TxStatus::InFinalizedBlock(tx_in_block) => {
                assert!(tx_in_block.wait_for_success().await.is_ok());
                break;
            },
            TxStatus::Error { message } => {
                panic!("{}", message);
            },
            TxStatus::Invalid { message } => {
                panic!("{}", message);
            },
            TxStatus::Dropped { message } => {
                panic!("{}", message);
            },
            // Continue otherwise:
            _ => continue,
        };
    }

    // balance after
    let balance_after_query = entropy::storage().system().account(account);
    let account_info = query_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        balance_after_query,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    let balance_after = account_info.data.free;
    // make sure funds were transfered
    ma::assert_gt!(balance_after, balance_before);
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_registration_flow() {
    initialize_test_logger().await;
    clean_tests();

    let alice = Keyring::Alice;
    let bob = Keyring::Bob;
    let charlie = Keyring::Charlie;

    let spawn_results =
        spawn_tss_nodes_and_start_chain(ChainSpecType::IntegrationJumpStarted).await;

    let jump_start_progress_query = entropy::storage().staking_extension().jump_start_progress();
    let jump_start_progress = query_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        jump_start_progress_query,
        None,
    )
    .await
    .unwrap()
    .unwrap();

    let network_verifying_key = jump_start_progress.verifying_key.unwrap().0;

    // We need to store a program in order to be able to register succesfully
    let program_hash = test_client::store_program(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &bob.pair(), // This is our program deployer
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
        0u8,
    )
    .await
    .unwrap();

    let registration_request = put_register_request_on_chain(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        &alice,                               // This is our signature request account
        subxtAccountId32(charlie.public().0), // This is our program modification account
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await;

    assert!(
        matches!(registration_request, Ok(_)),
        "We expect our registration request to succeed."
    );

    let entropy::registry::events::AccountRegistered(
        _actual_signature_request_account,
        actual_verifying_key,
    ) = registration_request.unwrap();

    // This is slightly more convenient to work with later one
    let actual_verifying_key = actual_verifying_key.0;

    // Next we want to check that the info that's on-chain is what we actually expect
    let registered_info = get_registered_details(
        &spawn_results.chain_connection.api,
        &spawn_results.chain_connection.rpc,
        actual_verifying_key.to_vec(),
    )
    .await;

    assert!(
        matches!(registered_info, Ok(_)),
        "We expect that the verifying key we got back matches registration entry in storage."
    );

    assert_eq!(
        registered_info.unwrap().program_modification_account,
        subxtAccountId32(charlie.public().0),
    );

    // Next, let's check that the child verifying key matches
    let network_verifying_key = VerifyingKey::try_from(network_verifying_key.as_slice()).unwrap();

    // We hardcode the derivation path here since we know that there's only been one registration
    // request (ours).
    let derivation_path = "m/0/0".parse().unwrap();
    let expected_verifying_key =
        network_verifying_key.derive_verifying_key_bip32(&derivation_path).unwrap();
    let expected_verifying_key = expected_verifying_key.to_encoded_point(true).as_bytes().to_vec();

    assert_eq!(
        expected_verifying_key, actual_verifying_key,
        "The derived child key doesn't match our registered verifying key."
    );

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_increment_or_wipe_request_limit() {
    initialize_test_logger().await;
    clean_tests();
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let (kv_store, sr25519_pair, x25519_secret, _should_backup) =
        setup_kv_store(&Some(ValidatorName::Alice), Some(build_db_path(&None))).await.unwrap();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());

    let app_state =
        AppState::new(configuration.clone(), kv_store.clone(), sr25519_pair, x25519_secret).await;

    let request_limit_query = entropy::storage().parameters().request_limit();
    let request_limit = query_chain(&api, &rpc, request_limit_query, None).await.unwrap().unwrap();

    // no error
    assert!(request_limit_check(
        &rpc,
        &app_state.cache,
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        request_limit
    )
    .await
    .is_ok());

    // run up the request check to one less then max (to check integration)
    for _ in 0..request_limit {
        increment_or_wipe_request_limit(
            &app_state.cache,
            hex::encode(DAVE_VERIFYING_KEY.to_vec()),
            request_limit,
        )
        .await
        .unwrap();
    }
    // should now fail
    let err_too_many_requests = request_limit_check(
        &rpc,
        &app_state.cache,
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        request_limit,
    )
    .await
    .map_err(|e| e.to_string());
    assert_eq!(err_too_many_requests, Err("Too many requests - wait a block".to_string()));

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    run_to_block(&rpc, block_number + 1).await;

    // no error while mapping is empty
    assert!(request_limit_check(
        &rpc,
        &app_state.cache,
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        request_limit
    )
    .await
    .is_ok());
    // request limit gets cleared
    let request_limit_mapping = app_state.cache.request_limit.read().unwrap();
    assert!(request_limit_mapping.is_empty());

    clean_tests();
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_oracle_data() {
    initialize_test_logger().await;
    let cxt = testing_context().await;
    setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();
    run_to_block(&rpc, 1).await;

    let oracle_data =
        get_oracle_data(&api, &rpc, vec!["block_number_entropy".encode()]).await.unwrap();
    let current_block = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    assert_eq!(oracle_data.len(), 1);
    assert_eq!(current_block.encode(), oracle_data[0]);

    // fails gracefully
    let oracle_data_fail =
        get_oracle_data(&api, &rpc, vec!["random_heading".encode()]).await.unwrap();
    assert_eq!(oracle_data_fail.len(), 1);
    assert_eq!(oracle_data_fail[0].len(), 0);
}

#[tokio::test]
#[serial]
async fn test_validate_jump_start_fail_repeated() {
    initialize_test_logger().await;
    clean_tests();

    let alice = Keyring::Alice;

    let cxt = &test_node_process_testing_state(ChainSpecType::Integration, false).await[0];
    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();

    let (kv_store, sr25519_pair, x25519_secret, _should_backup) =
        setup_kv_store(&Some(ValidatorName::Alice), Some(build_db_path(&None))).await.unwrap();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());

    let app_state =
        AppState::new(configuration.clone(), kv_store.clone(), sr25519_pair, x25519_secret).await;

    let jump_start_request = entropy::tx().registry().jump_start_network();
    let block_number = 2;

    run_to_block(&rpc, block_number - 1).await;
    let _result =
        submit_transaction_with_pair(&api, &rpc, &alice.pair(), &jump_start_request, None)
            .await
            .unwrap();
    // manipulates cache to get to repeated data error
    app_state.cache.write_to_block_numbers(BlockNumberFields::NewUser, block_number).unwrap();
    run_to_block(&rpc, block_number + 1).await;

    let jump_start_progress_query = entropy::storage().registry().jumpstart_dkg(block_number);
    let jump_start_progress =
        query_chain(&api, &rpc, jump_start_progress_query, None).await.unwrap().unwrap();
    let validators_info: Vec<_> = jump_start_progress.into_iter().map(|v| v.0).collect();

    let mut ocw_message = OcwMessageDkg { validators_info, block_number };
    let err_stale_data = validate_jump_start(&ocw_message, &api, &rpc, &app_state.cache)
        .await
        .map_err(|e| e.to_string());
    assert_eq!(err_stale_data, Err("Data is repeated".to_string()));

    ocw_message.block_number = 1;

    let err_incorrect_data = validate_jump_start(&ocw_message, &api, &rpc, &app_state.cache)
        .await
        .map_err(|e| e.to_string());
    assert_eq!(err_incorrect_data, Err("Data is stale".to_string()));

    clean_tests();
}

pub async fn submit_transaction_request(
    validator_urls_and_keys: (String, entropy_shared::X25519PublicKey),
    signature_request: UserSignatureRequest,
    keyring: Sr25519Keyring,
) -> std::result::Result<reqwest::Response, reqwest::Error> {
    let mock_client = reqwest::Client::new();
    let signed_message = EncryptedSignedMessage::new(
        &keyring.pair(),
        serde_json::to_vec(&signature_request.clone()).unwrap(),
        &validator_urls_and_keys.1,
        &[],
    )
    .unwrap();

    let url = format!("http://{}/v1/user/relay_tx", validator_urls_and_keys.0.clone());
    mock_client
        .post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&signed_message).unwrap())
        .send()
        .await
}

pub async fn submit_transaction_sign_tx_requests(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    validator_urls_and_keys: (String, entropy_shared::X25519PublicKey),
    user_signature_request: UserSignatureRequest,
    signer: sr25519::Pair,
    validators_info_option: Option<Vec<ValidatorInfo>>,
) -> std::result::Result<reqwest::Response, reqwest::Error> {
    let mock_client = reqwest::Client::new();
    let validators_info = if let Some(validators_info) = validators_info_option {
        validators_info
    } else {
        get_signers_from_chain(api, rpc).await.unwrap().0
    };

    let relayer_sig_req = RelayerSignatureRequest { user_signature_request, validators_info };

    let signed_message = EncryptedSignedMessage::new(
        &signer,
        serde_json::to_vec(&relayer_sig_req.clone()).unwrap(),
        &validator_urls_and_keys.1,
        &[],
    )
    .unwrap();

    let url = format!("http://{}/v1/user/sign_tx", validator_urls_and_keys.0.clone());
    mock_client
        .post(url)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&signed_message).unwrap())
        .send()
        .await
}
pub async fn get_sign_tx_data(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    message: String,
    signature_verifying_key: [u8; 33],
) -> (Vec<ValidatorInfo>, UserSignatureRequest, Vec<(String, [u8; 32])>) {
    let (validators_info, _) = get_signers_from_chain(api, rpc).await.unwrap();

    let signature_request = UserSignatureRequest {
        message,
        auxilary_data: Some(vec![
            Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
            Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
        ]),
        block_number: rpc.chain_get_header(None).await.unwrap().unwrap().number,
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key: signature_verifying_key.to_vec(),
    };

    let validator_ips_and_keys =
        validators_info.iter().map(|v| (v.ip_address.clone(), v.x25519_public_key)).collect();

    (validators_info, signature_request, validator_ips_and_keys)
}

/// Takes a validator name and returns relayer info needed for tests
pub async fn validator_name_to_relayer_info(
    validator_name: ValidatorName,
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> ((String, entropy_shared::X25519PublicKey), subxtAccountId32) {
    let stash_address = match validator_name {
        ValidatorName::Alice => Keyring::AliceStash,
        ValidatorName::Bob => Keyring::BobStash,
        ValidatorName::Charlie => Keyring::CharlieStash,
        ValidatorName::Dave => Keyring::DaveStash,
        ValidatorName::Eve => Keyring::EveStash,
    };
    let block_hash = rpc.chain_get_block_hash(None).await.unwrap();
    let threshold_address_query = entropy::storage()
        .staking_extension()
        .threshold_servers(subxtAccountId32(stash_address.public().0));
    let server_info =
        query_chain(&api, &rpc, threshold_address_query, block_hash).await.unwrap().unwrap();
    (
        (
            std::str::from_utf8(&server_info.endpoint).unwrap().to_string(),
            server_info.x25519_public_key,
        ),
        server_info.tss_account,
    )
}
