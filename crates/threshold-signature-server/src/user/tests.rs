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

use axum::http::StatusCode;
use base64::prelude::{Engine, BASE64_STANDARD};
use bip39::{Language, Mnemonic};
use blake3::hash;
use entropy_client::{
    client::{store_program, update_programs},
    user::get_current_subgroup_signers,
};
use entropy_kvdb::{
    clean_tests,
    encrypted_sled::PasswordMethod,
    kv_manager::{helpers::deserialize as keyshare_deserialize, value::KvManager},
};
use entropy_programs_runtime::{Runtime, SignatureRequest};
use entropy_protocol::{
    protocol_transport::{noise::noise_handshake_initiator, SubscribeMessage, WsConnection},
    user::{user_participates_in_dkg_protocol, user_participates_in_signing_protocol},
    KeyParams, PartyId, SessionId, SigningSessionInfo, ValidatorInfo,
};
use entropy_shared::{
    HashingAlgorithm, KeyVisibility, OcwMessageDkg, DAVE_VERIFYING_KEY, DEFAULT_VERIFYING_KEY,
    DEFAULT_VERIFYING_KEY_NOT_REGISTERED, DEVICE_KEY_HASH, EVE_VERIFYING_KEY, FERDIE_VERIFYING_KEY,
    NETWORK_PARENT_KEY,
};
use entropy_testing_utils::{
    chain_api::{
        entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec as OtherBoundedVec,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance as OtherProgramInstance,
    },
    constants::{
        ALICE_STASH_ADDRESS, AUXILARY_DATA_SHOULD_FAIL, AUXILARY_DATA_SHOULD_SUCCEED,
        EVE_X25519_SECRET_KEY, FAUCET_PROGRAM, FERDIE_X25519_SECRET_KEY, PREIMAGE_SHOULD_FAIL,
        PREIMAGE_SHOULD_SUCCEED, TEST_BASIC_TRANSACTION, TEST_INFINITE_LOOP_BYTECODE,
        TEST_PROGRAM_CUSTOM_HASH, TEST_PROGRAM_WASM_BYTECODE, TSS_ACCOUNTS, X25519_PUBLIC_KEYS,
    },
    substrate_context::{
        test_context_stationary, test_node_process_testing_state, testing_context,
        SubstrateTestingContext,
    },
};
use futures::{
    future::{self, join_all},
    join, Future, SinkExt, StreamExt,
};
use hex_literal::hex;
use more_asserts as ma;
use parity_scale_codec::{Decode, DecodeAll, Encode};
use rand_core::OsRng;
use schemars::{schema_for, JsonSchema};
use schnorrkel::{signing_context, Keypair as Sr25519Keypair, Signature as Sr25519Signature};
use serde::{Deserialize, Serialize};
use serial_test::serial;
use sp_core::{crypto::Ss58Codec, Pair as OtherPair, H160};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use std::{
    env, fs,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    config::substrate::{BlakeTwo256, SubstrateHeader},
    config::{DefaultExtrinsicParamsBuilder, PolkadotExtrinsicParamsBuilder as Params},
    events::EventsClient,
    ext::{
        sp_core::{hashing::blake2_256, sr25519, sr25519::Signature, Bytes, Pair},
        sp_runtime::AccountId32,
    },
    tx::{PairSigner, TxStatus},
    utils::{AccountId32 as subxtAccountId32, MultiAddress, MultiSignature, Static, H256},
    Config, OnlineClient,
};
use subxt_signer::ecdsa::PublicKey as EcdsaPublicKey;
use synedrion::{
    k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey},
    KeyShare,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    task::JoinHandle,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use x25519_dalek::{PublicKey, StaticSecret};

use super::UserInputPartyInfo;
use crate::{
    chain_api::{
        entropy, entropy::runtime_types::bounded_collections::bounded_vec::BoundedVec,
        entropy::runtime_types::entropy_runtime::RuntimeCall,
        entropy::runtime_types::pallet_balances::pallet::Call as BalancesCall,
        entropy::runtime_types::pallet_registry::pallet::ProgramInstance, get_api, get_rpc,
        EntropyConfig,
    },
    get_signer,
    helpers::{
        launch::{
            development_mnemonic, load_kv_store, setup_mnemonic, Configuration, ValidatorName,
            DEFAULT_BOB_MNEMONIC, DEFAULT_CHARLIE_MNEMONIC, DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
        },
        signing::Hasher,
        substrate::{
            get_subgroup, query_chain, return_all_addresses_of_subgroup, submit_transaction,
        },
        tests::{
            check_has_confirmation, check_if_confirmation, create_clients, initialize_test_logger,
            remove_program, run_to_block, setup_client, spawn_testing_validators,
        },
        user::{compute_hash, send_key},
        validator::get_signer_and_x25519_secret_from_mnemonic,
    },
    new_user,
    r#unsafe::api::UnsafeQuery,
    signing_client::ListenerState,
    user::{
        api::{
            check_hash_pointer_out_of_bounds, confirm_registered, increment_or_wipe_request_limit,
            recover_key, request_limit_check, request_limit_key, RequestLimitStorage,
            UserRegistrationInfo, UserSignatureRequest,
        },
        UserErr,
    },
    validation::{mnemonic_to_pair, new_mnemonic, EncryptedSignedMessage},
    validator::api::get_random_server_info,
};

#[tokio::test]
#[serial]
async fn test_get_signer_does_not_throw_err() {
    initialize_test_logger().await;
    clean_tests();

    let kv_store = load_kv_store(&None, None).await;

    let mnemonic = development_mnemonic(&None);
    setup_mnemonic(&kv_store, mnemonic).await;

    get_signer(&kv_store).await.unwrap();
    clean_tests();
}
#[tokio::test]
#[serial]
async fn test_sign_tx_no_chain() {
    initialize_test_logger().await;
    clean_tests();

    let one = AccountKeyring::Dave;
    let two = AccountKeyring::Two;

    let (validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(DAVE_VERIFYING_KEY.to_vec()), false, false).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_hash = store_program(
        &entropy_api,
        &rpc,
        &two.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    let message_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let signature_request_account = subxtAccountId32(one.pair().public().0);
    let session_id = SessionId::Sign(SigningSessionInfo {
        signature_verifying_key: DAVE_VERIFYING_KEY.to_vec(),
        message_hash,
        request_author: signature_request_account.clone(),
    });

    let (_validators_info, mut generic_msg, validator_ips_and_keys) =
        get_sign_tx_data(validator_ips, hex::encode(PREIMAGE_SHOULD_SUCCEED));

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    // test points to no program
    let test_no_program =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_no_program {
        assert_eq!(res.unwrap().text().await.unwrap(), "No program pointer defined for account");
    }
    update_programs(
        &entropy_api,
        &rpc,
        DAVE_VERIFYING_KEY,
        &one.pair(),
        OtherBoundedVec(vec![
            OtherProgramInstance { program_pointer: program_hash, program_config: vec![] },
            OtherProgramInstance { program_pointer: program_hash, program_config: vec![] },
        ]),
    )
    .await
    .unwrap();

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    let test_user_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    verify_signature(test_user_res, message_hash, keyshare_option.clone()).await;
    let mock_client = reqwest::Client::new();
    // check request limiter increases
    let unsafe_get =
        UnsafeQuery::new(request_limit_key(hex::encode(DAVE_VERIFYING_KEY.to_vec())), vec![])
            .to_json();

    // check get key before registration to see if key gets replaced
    let get_response = mock_client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(unsafe_get.clone())
        .send()
        .await
        .unwrap();
    let serialized_request_amount = get_response.text().await.unwrap();

    let request_info: RequestLimitStorage =
        RequestLimitStorage::decode(&mut serialized_request_amount.as_ref()).unwrap();
    assert_eq!(request_info.request_amount, 1);

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    generic_msg.validators_info = generic_msg.validators_info.into_iter().rev().collect::<Vec<_>>();
    let test_user_res_order =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    verify_signature(test_user_res_order, message_hash, keyshare_option.clone()).await;

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    generic_msg.signature_verifying_key = DEFAULT_VERIFYING_KEY_NOT_REGISTERED.to_vec();
    let test_user_res_not_registered =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), two).await;

    for res in test_user_res_not_registered {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Chain Fetch: Not Registering error: Register Onchain first"
        );
    }

    // Test attempting to connect over ws by someone who is not in the signing group
    let validator_ip_and_key = validator_ips_and_keys[0].clone();
    let connection_attempt_handle = tokio::spawn(async move {
        // Wait for the "user" to submit the signing request
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ws_endpoint = format!("ws://{}/ws", validator_ip_and_key.0);
        let (ws_stream, _response) = connect_async(ws_endpoint).await.unwrap();

        let ferdie_pair = AccountKeyring::Ferdie.pair();

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

        assert_eq!(Err("NoListener(\"no listener\")".to_string()), subscribe_response);
        // The stream should not continue to send messages
        // returns true if this part of the test passes
        encrypted_connection.recv().await.is_err()
    });

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    generic_msg.signature_verifying_key = DAVE_VERIFYING_KEY.to_vec().to_vec();
    let test_user_bad_connection_res = submit_transaction_requests(
        vec![validator_ips_and_keys[1].clone()],
        generic_msg.clone(),
        one,
    )
    .await;

    for res in test_user_bad_connection_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "{\"Err\":\"Timed out waiting for remote party\"}"
        );
    }

    assert!(connection_attempt_handle.await.unwrap());

    // Bad Account ID - an account ID is given which is not in the signing group
    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    let mut generic_msg_bad_account_id = generic_msg.clone();
    generic_msg_bad_account_id.validators_info[0].tss_account =
        subxtAccountId32(AccountKeyring::Dave.into());

    let test_user_failed_tss_account = submit_transaction_requests(
        validator_ips_and_keys.clone(),
        generic_msg_bad_account_id,
        one,
    )
    .await;

    for res in test_user_failed_tss_account {
        let res = res.unwrap();
        assert_eq!(res.status(), 500);
        assert_eq!(res.text().await.unwrap(), "Invalid Signer: Invalid Signer in Signing group");
    }

    // Now, test a signature request that should fail
    // The test program is written to fail when `auxilary_data` is `None`
    generic_msg.auxilary_data = None;
    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;

    let test_user_failed_programs_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_programs_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Runtime error: Runtime(Error::Evaluation(\"This program requires that `auxilary_data` be `Some`.\"))"
        );
    }

    // The test program is written to fail when `auxilary_data` is `None` but only on the second program
    generic_msg.auxilary_data = Some(vec![Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED))]);
    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;

    let test_user_failed_aux_data =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_aux_data {
        assert_eq!(res.unwrap().text().await.unwrap(), "Auxilary data is mismatched");
    }

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    generic_msg.hash = HashingAlgorithm::Custom(3);
    let test_user_custom_hash_out_of_bounds =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), two).await;

    for res in test_user_custom_hash_out_of_bounds {
        assert_eq!(res.unwrap().text().await.unwrap(), "Custom hash choice out of bounds");
    }

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    generic_msg.signature_verifying_key = NETWORK_PARENT_KEY.as_bytes().to_vec();
    let test_user_sign_with_parent_key = submit_transaction_requests(
        vec![validator_ips_and_keys[1].clone()],
        generic_msg.clone(),
        one,
    )
    .await;
    for res in test_user_sign_with_parent_key {
        assert_eq!(res.unwrap().text().await.unwrap(), "No signing from parent key");
    }
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_sign_tx_no_chain_fail() {
    initialize_test_logger().await;
    clean_tests();

    let one = AccountKeyring::Dave;

    let (validator_ips, _validator_ids, _keyshare_option) =
        spawn_testing_validators(Some(DAVE_VERIFYING_KEY.to_vec()), false, false).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();
    let mock_client = reqwest::Client::new();

    let (_validators_info, generic_msg, validator_ips_and_keys) =
        get_sign_tx_data(validator_ips, hex::encode(PREIMAGE_SHOULD_SUCCEED));

    // fails verification tests
    // wrong key for wrong validator
    let failed_signed_message = EncryptedSignedMessage::new(
        &one.pair(),
        serde_json::to_vec(&generic_msg.clone()).unwrap(),
        &X25519_PUBLIC_KEYS[1],
        &[],
    )
    .unwrap();
    let failed_res = mock_client
        .post("http://127.0.0.1:3001/user/sign_tx")
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

    let sig: [u8; 64] = [0; 64];
    let user_input_bad = EncryptedSignedMessage::new_with_given_signature(
        &one.pair(),
        serde_json::to_vec(&generic_msg.clone()).unwrap(),
        &X25519_PUBLIC_KEYS[0],
        &[],
        sr25519::Signature::from_raw(sig),
    )
    .unwrap();

    let failed_sign = mock_client
        .post("http://127.0.0.1:3001/user/sign_tx")
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

    let request_limit_query = entropy::storage().parameters().request_limit();
    let request_limit =
        query_chain(&entropy_api, &rpc, request_limit_query, None).await.unwrap().unwrap();

    // test request limit reached

    // gets current blocknumber, potential race condition run to block + 1
    // to reset block and give us 6 seconds to hit rate limit
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    run_to_block(&rpc, block_number + 1).await;
    let unsafe_put = UnsafeQuery::new(
        request_limit_key(hex::encode(DAVE_VERIFYING_KEY.to_vec())),
        RequestLimitStorage { request_amount: request_limit + 1, block_number: block_number + 1 }
            .encode(),
    )
    .to_json();

    let _ = mock_client
        .post("http://127.0.0.1:3001/unsafe/put")
        .header("Content-Type", "application/json")
        .body(unsafe_put.clone())
        .send()
        .await
        .unwrap();
    let _ = mock_client
        .post("http://127.0.0.1:3002/unsafe/put")
        .header("Content-Type", "application/json")
        .body(unsafe_put.clone())
        .send()
        .await
        .unwrap();

    let test_user_failed_request_limit =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_request_limit {
        assert_eq!(res.unwrap().text().await.unwrap(), "Too many requests - wait a block");
    }
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_program_with_config() {
    initialize_test_logger().await;
    clean_tests();

    let one = AccountKeyring::Dave;
    let two = AccountKeyring::Two;

    let (validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(DAVE_VERIFYING_KEY.to_vec().clone()), false, false).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_hash = store_program(
        &entropy_api,
        &rpc,
        &two.pair(),
        TEST_BASIC_TRANSACTION.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    // this message is an ethereum tx rlp encoded with a proper allow listed address
    let message = "0xef01808094772b9a9e8aa1c9db861c6611a82d251db4fac990019243726561746564204f6e20456e74726f7079018080";

    let message_hash = Hasher::keccak(message.as_bytes());
    let (_validators_info, mut generic_msg, validator_ips_and_keys) =
        get_sign_tx_data(validator_ips, hex::encode(message));

    let config = r#"
        {
            "allowlisted_addresses": [
                "772b9a9e8aa1c9db861c6611a82d251db4fac990"
            ]
        }
    "#
    .as_bytes();

    update_programs(
        &entropy_api,
        &rpc,
        DAVE_VERIFYING_KEY,
        &one.pair(),
        OtherBoundedVec(vec![
            OtherProgramInstance { program_pointer: program_hash, program_config: config.to_vec() },
            OtherProgramInstance { program_pointer: program_hash, program_config: config.to_vec() },
        ]),
    )
    .await
    .unwrap();

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    let test_user_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    verify_signature(test_user_res, message_hash, keyshare_option.clone()).await;
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_fail_signing_group() {
    initialize_test_logger().await;
    clean_tests();

    let dave = AccountKeyring::Dave;
    let eve = AccountKeyring::Eve;
    let (validator_ips, _, _) = spawn_testing_validators(None, false, false).await;

    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_hash = store_program(
        &entropy_api,
        &rpc,
        &eve.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    update_programs(
        &entropy_api,
        &rpc,
        DAVE_VERIFYING_KEY,
        &dave.pair(),
        OtherBoundedVec(vec![OtherProgramInstance {
            program_pointer: program_hash,
            program_config: vec![],
        }]),
    )
    .await
    .unwrap();

    let (_, mut generic_msg, _validator_ips_and_keys) =
        get_sign_tx_data(validator_ips, hex::encode(PREIMAGE_SHOULD_SUCCEED));
    generic_msg.validators_info[0].tss_account =
        hex!["a664add5dfaca1dd560b949b5699b5f0c3c1df3a2ea77ceb0eeb4f77cc3ade04"].into();

    let signed_message = EncryptedSignedMessage::new(
        &dave.pair(),
        serde_json::to_vec(&generic_msg.clone()).unwrap(),
        &X25519_PUBLIC_KEYS[0],
        &[],
    )
    .unwrap();

    let mock_client = reqwest::Client::new();
    let response = mock_client
        .post("http://127.0.0.1:3001/user/sign_tx")
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&signed_message).unwrap())
        .send()
        .await;
    assert_eq!(
        response.unwrap().text().await.unwrap(),
        "Invalid Signer: Invalid Signer in Signing group"
    );
    clean_tests();
}

// TODO negative validation tests on user/tx

#[tokio::test]
#[serial]
async fn test_store_share() {
    initialize_test_logger().await;
    clean_tests();

    let alice = AccountKeyring::Alice;
    let alice_program = AccountKeyring::Charlie;
    let program_manager = AccountKeyring::Dave;

    let cxt = test_context_stationary().await;
    let (_validator_ips, _validator_ids, _) =
        spawn_testing_validators(Some(DEFAULT_VERIFYING_KEY.to_vec()), false, false).await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let client = reqwest::Client::new();

    let program_hash = store_program(
        &api,
        &rpc,
        &program_manager.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    let mut block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let validators_info = vec![
        entropy_shared::ValidatorInfo {
            ip_address: b"127.0.0.1:3001".to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone().encode(),
        },
        entropy_shared::ValidatorInfo {
            ip_address: b"127.0.0.1:3002".to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone().encode(),
        },
    ];
    let mut onchain_user_request = OcwMessageDkg {
        sig_request_accounts: vec![alice.public().encode()],
        block_number,
        validators_info,
    };

    put_register_request_on_chain(
        &api,
        &rpc,
        &alice,
        alice_program.to_account_id().into(),
        KeyVisibility::Public,
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await;

    run_to_block(&rpc, block_number + 1).await;

    // succeeds
    let user_registration_response = client
        .post("http://127.0.0.1:3002/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(user_registration_response.text().await.unwrap(), "");

    let mut new_verifying_key = vec![];
    // wait for registered event check that key exists in kvdb
    for _ in 0..45 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let block_hash = rpc.chain_get_block_hash(None).await.unwrap();
        let events = EventsClient::new(api.clone()).at(block_hash.unwrap()).await.unwrap();
        let registered_event = events.find::<entropy::registry::events::AccountRegistered>();
        for event in registered_event.flatten() {
            let registered_query = entropy::storage().registry().registered(&event.1);
            let query_registered_status =
                query_chain(&api, &rpc, registered_query, block_hash).await;
            if query_registered_status.unwrap().is_some() {
                if event.0 == alice.to_account_id().into() {
                    new_verifying_key = event.1 .0;
                    break;
                }
            }
        }
    }
    // Check that the timeout was not reached
    assert!(new_verifying_key.len() > 0);

    let get_query =
        UnsafeQuery::new(hex::encode(new_verifying_key.to_vec()), [].to_vec()).to_json();
    // check get key before registration to see if key gets replaced
    let response_key = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();
    // check to make sure keyshare is correct
    let key_share: Option<KeyShare<KeyParams>> =
        entropy_kvdb::kv_manager::helpers::deserialize(&response_key.bytes().await.unwrap());
    assert_eq!(key_share.is_some(), true);

    // fails repeated data
    let response_repeated_data = client
        .post("http://127.0.0.1:3001/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response_repeated_data.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_repeated_data.text().await.unwrap(), "Data is repeated");

    run_to_block(&rpc, block_number + 3).await;
    onchain_user_request.block_number = block_number + 1;
    // fails stale data
    let response_stale = client
        .post("http://127.0.0.1:3001/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response_stale.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_stale.text().await.unwrap(), "Data is stale");

    block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    put_register_request_on_chain(
        &api,
        &rpc,
        &alice_program,
        alice_program.to_account_id().into(),
        KeyVisibility::Public,
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await;
    onchain_user_request.block_number = block_number;
    run_to_block(&rpc, block_number + 1).await;

    // fails not verified data
    let response_not_verified = client
        .post("http://127.0.0.1:3001/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response_not_verified.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_not_verified.text().await.unwrap(), "Data is not verifiable");

    onchain_user_request.validators_info[0].tss_account = TSS_ACCOUNTS[1].clone().encode();
    // fails not in validator group data
    let response_not_validator = client
        .post("http://127.0.0.1:3001/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(response_not_validator.status(), StatusCode::MISDIRECTED_REQUEST);

    check_if_confirmation(&api, &rpc, &alice.pair(), new_verifying_key).await;
    // TODO check if key is in other subgroup member
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_jumpstart_network() {
    initialize_test_logger().await;
    clean_tests();

    let alice = AccountKeyring::Alice;

    let cxt = test_context_stationary().await;
    let (_validator_ips, _validator_ids, _) =
        spawn_testing_validators(Some(DEFAULT_VERIFYING_KEY.to_vec()), false, false).await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let client = reqwest::Client::new();

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;
    let validators_info = vec![
        entropy_shared::ValidatorInfo {
            ip_address: b"127.0.0.1:3001".to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone().encode(),
        },
        entropy_shared::ValidatorInfo {
            ip_address: b"127.0.0.1:3002".to_vec(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone().encode(),
        },
    ];
    let onchain_user_request = OcwMessageDkg {
        sig_request_accounts: vec![NETWORK_PARENT_KEY.encode()],
        block_number,
        validators_info,
    };

    put_jumpstart_request_on_chain(&api, &rpc, &alice).await;

    run_to_block(&rpc, block_number + 1).await;

    // succeeds
    let user_registration_response = client
        .post("http://127.0.0.1:3002/user/new")
        .body(onchain_user_request.clone().encode())
        .send()
        .await
        .unwrap();

    assert_eq!(user_registration_response.text().await.unwrap(), "");
    // wait for jump start event check that key exists in kvdb
    for _ in 0..45 {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let block_hash = rpc.chain_get_block_hash(None).await.unwrap();
        let events = EventsClient::new(api.clone()).at(block_hash.unwrap()).await.unwrap();
        let jump_start_event = events.find::<entropy::registry::events::FinishedNetworkJumpStart>();
        for _event in jump_start_event.flatten() {
            break;
        }
    }

    let get_query = UnsafeQuery::new(hex::encode(NETWORK_PARENT_KEY), [].to_vec()).to_json();
    // check get key before registration to see if key gets replaced
    let response_key = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();
    // check to make sure keyshare is correct
    let key_share: Option<KeyShare<KeyParams>> =
        entropy_kvdb::kv_manager::helpers::deserialize(&response_key.bytes().await.unwrap());
    assert_eq!(key_share.is_some(), true);
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_return_addresses_of_subgroup() {
    initialize_test_logger().await;

    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let result = return_all_addresses_of_subgroup(&api, &rpc, 0u8).await.unwrap();
    assert_eq!(result.len(), 1);
}

#[tokio::test]
#[serial]
async fn test_send_and_receive_keys() {
    initialize_test_logger().await;
    clean_tests();

    let alice = AccountKeyring::Alice;
    let program_manager = AccountKeyring::Dave;
    let signature_request_account = subxtAccountId32(alice.pair().public().0);

    let cxt = test_context_stationary().await;
    setup_client().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let share = {
        let share = &KeyShare::<KeyParams>::new_centralized(&mut rand_core::OsRng, 2, None)[0];
        entropy_kvdb::kv_manager::helpers::serialize(&share).unwrap()
    };

    let user_registration_info = UserRegistrationInfo {
        key: alice.to_account_id().to_string(),
        value: share.clone(),
        proactive_refresh: false,
        sig_request_address: Some(signature_request_account.clone()),
    };

    let (signer_alice, _) = get_signer_and_x25519_secret_from_mnemonic(DEFAULT_MNEMONIC).unwrap();

    // First try sending a keyshare for a user who is not registering - should fail
    let result = send_key(
        &api,
        &rpc,
        &alice.to_account_id().into(),
        &mut vec![ALICE_STASH_ADDRESS.clone(), alice.to_account_id().into()],
        user_registration_info.clone(),
        &signer_alice,
    )
    .await;

    if let Err(UserErr::KeyShareRejected(error_message)) = result {
        assert_eq!(
            error_message,
            "Not Registering error: Provided account ID not from a registering user".to_string()
        );
    } else {
        panic!("Should give not registering error");
    }

    // The happy path - the user is in a registering state - should succeed
    let program_hash = store_program(
        &api,
        &rpc,
        &program_manager.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    put_register_request_on_chain(
        &api,
        &rpc,
        &alice.clone(),
        alice.to_account_id().into(),
        KeyVisibility::Public,
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await;

    // sends key to alice validator, while filtering out own key
    send_key(
        &api,
        &rpc,
        &alice.to_account_id().into(),
        &mut vec![ALICE_STASH_ADDRESS.clone(), alice.to_account_id().into()],
        user_registration_info.clone(),
        &signer_alice,
    )
    .await
    .unwrap();

    let get_query = UnsafeQuery::new(user_registration_info.key.clone(), vec![]).to_json();

    let client = reqwest::Client::new();
    // check alice has new key
    let response_new_key = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_new_key.bytes().await.unwrap(), &user_registration_info.value.clone());

    // A keyshare can be overwritten when the user is still in a registering state
    let some_other_share = {
        let share = &KeyShare::<KeyParams>::new_centralized(&mut rand_core::OsRng, 2, None)[0];
        entropy_kvdb::kv_manager::helpers::serialize(&share).unwrap()
    };

    let user_registration_info_overwrite = UserRegistrationInfo {
        key: alice.to_account_id().to_string(),
        value: some_other_share.clone(),
        proactive_refresh: false,
        sig_request_address: Some(signature_request_account.clone()),
    };

    let signed_message = serde_json::to_string(
        &EncryptedSignedMessage::new(
            signer_alice.signer(),
            serde_json::to_vec(&user_registration_info_overwrite).unwrap(),
            &X25519_PUBLIC_KEYS[0],
            &[],
        )
        .unwrap(),
    )
    .unwrap();

    let response_overwrites_key = client
        .post("http://127.0.0.1:3001/user/receive_key")
        .header("Content-Type", "application/json")
        .body(signed_message.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_overwrites_key.status(), StatusCode::OK);
    assert_eq!(response_overwrites_key.text().await.unwrap(), "");

    // Check that the key has been successfully overwritten
    let get_query = UnsafeQuery::new(user_registration_info.key.clone(), vec![]).to_json();
    let response_new_key = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_new_key.bytes().await.unwrap(), &some_other_share);

    // Try writing a 'forbidden key' - should fail
    let user_registration_info_forbidden = UserRegistrationInfo {
        key: "MNEMONIC".to_string(),
        value: share.clone(),
        proactive_refresh: false,
        sig_request_address: Some(signature_request_account.clone()),
    };

    let signed_message = serde_json::to_string(
        &EncryptedSignedMessage::new(
            signer_alice.signer(),
            serde_json::to_vec(&user_registration_info_forbidden).unwrap(),
            &X25519_PUBLIC_KEYS[0],
            &[],
        )
        .unwrap(),
    )
    .unwrap();

    let response_overwrites_key = client
        .post("http://127.0.0.1:3001/user/receive_key")
        .header("Content-Type", "application/json")
        .body(signed_message.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_overwrites_key.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response_overwrites_key.text().await.unwrap(), "The given key is forbidden");

    // Try sending a badly formed keyshare - should fail
    let user_registration_info_bad_keyshare = UserRegistrationInfo {
        key: alice.to_account_id().to_string(),
        value: b"This will not deserialize to KeyShare<KeyParams>".to_vec(),
        proactive_refresh: false,
        sig_request_address: Some(signature_request_account.clone()),
    };

    let signed_message = serde_json::to_string(
        &EncryptedSignedMessage::new(
            signer_alice.signer(),
            serde_json::to_vec(&user_registration_info_bad_keyshare).unwrap(),
            &X25519_PUBLIC_KEYS[0],
            &[],
        )
        .unwrap(),
    )
    .unwrap();

    let response_overwrites_key = client
        .post("http://127.0.0.1:3001/user/receive_key")
        .header("Content-Type", "application/json")
        .body(signed_message.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(response_overwrites_key.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_overwrites_key.text().await.unwrap(),
        "Input Validation error: Not a valid keyshare"
    );

    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_recover_key() {
    initialize_test_logger().await;
    clean_tests();

    let cxt = test_node_process_testing_state(false).await;
    setup_client().await;
    let (_, bob_kv) =
        create_clients("validator2".to_string(), vec![], vec![], &Some(ValidatorName::Bob)).await;

    let api = get_api(&cxt.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.ws_url).await.unwrap();
    let unsafe_query = UnsafeQuery::new("key".to_string(), vec![10]);
    let client = reqwest::Client::new();

    let _ = client
        .post("http://127.0.0.1:3001/unsafe/put")
        .header("Content-Type", "application/json")
        .body(unsafe_query.clone().to_json())
        .send()
        .await
        .unwrap();

    let (signer_alice, x25519_alice) =
        get_signer_and_x25519_secret_from_mnemonic(DEFAULT_CHARLIE_MNEMONIC).unwrap();

    recover_key(&api, &rpc, &bob_kv, &signer_alice, &x25519_alice, unsafe_query.key.clone())
        .await
        .unwrap();

    let value = bob_kv.kv().get(&unsafe_query.key).await.unwrap();
    assert_eq!(value, unsafe_query.value);
    clean_tests();
}

pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    sig_req_keyring: &Sr25519Keyring,
    program_modification_account: subxtAccountId32,
    key_visibility: KeyVisibility,
    program_instance: BoundedVec<ProgramInstance>,
) {
    let sig_req_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keyring.pair());

    let registering_tx = entropy::tx().registry().register(
        program_modification_account,
        Static(key_visibility),
        program_instance,
    );
    submit_transaction(api, rpc, &sig_req_account, &registering_tx, None).await.unwrap();
}

pub async fn put_jumpstart_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    sig_req_keyring: &Sr25519Keyring,
) {
    let sig_req_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keyring.pair());

    let registering_tx = entropy::tx().registry().jump_start_network();
    submit_transaction(api, rpc, &sig_req_account, &registering_tx, None).await.unwrap();
}

#[tokio::test]
#[serial]
async fn test_sign_tx_user_participates() {
    initialize_test_logger().await;
    clean_tests();

    let one = AccountKeyring::Eve;
    let two = AccountKeyring::Two;

    let (validator_ips, _validator_ids, users_keyshare_option) =
        spawn_testing_validators(Some(EVE_VERIFYING_KEY.to_vec()), true, true).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();
    let verifying_key = users_keyshare_option
        .clone()
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let program_hash = store_program(
        &entropy_api,
        &rpc,
        &two.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    update_programs(
        &entropy_api,
        &rpc,
        verifying_key.clone().try_into().unwrap(),
        &one.pair(),
        OtherBoundedVec(vec![OtherProgramInstance {
            program_pointer: program_hash,
            program_config: vec![],
        }]),
    )
    .await
    .unwrap();

    let encoded_transaction_request: String = hex::encode(PREIMAGE_SHOULD_SUCCEED);
    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);

    let signature_request_account = subxtAccountId32(one.pair().public().0);
    let session_id = SessionId::Sign(SigningSessionInfo {
        signature_verifying_key: verifying_key.clone(),
        message_hash: message_should_succeed_hash,
        request_author: signature_request_account.clone(),
    });

    let (validators_info, mut generic_msg, validator_ips_and_keys) =
        get_sign_tx_data(validator_ips, encoded_transaction_request);
    generic_msg.auxilary_data = Some(vec![Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED))]);
    generic_msg.signature_verifying_key = verifying_key.clone();

    // Submit transaction requests, and connect and participate in signing
    let (test_user_res, sig_result) = future::join(
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one),
        user_participates_in_signing_protocol(
            &users_keyshare_option.clone().unwrap(),
            validators_info.clone(),
            &one.pair(),
            EVE_X25519_SECRET_KEY.into(),
            message_should_succeed_hash,
        ),
    )
    .await;

    let signature_base64 = BASE64_STANDARD.encode(sig_result.unwrap().to_rsv_bytes());
    assert_eq!(signature_base64.len(), 88);

    verify_signature(test_user_res, message_should_succeed_hash, users_keyshare_option.clone())
        .await;

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    generic_msg.signature_verifying_key = DEFAULT_VERIFYING_KEY_NOT_REGISTERED.to_vec();

    // test failing cases
    let test_user_res_not_registered =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), two).await;

    for res in test_user_res_not_registered {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Chain Fetch: Not Registering error: Register Onchain first"
        );
    }

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    generic_msg.signature_verifying_key = verifying_key;
    let mut generic_msg_bad_validators = generic_msg.clone();
    generic_msg_bad_validators.validators_info[0].x25519_public_key = [0; 32];

    let test_user_failed_x25519_pub_key = submit_transaction_requests(
        validator_ips_and_keys.clone(),
        generic_msg_bad_validators,
        one,
    )
    .await;

    let mut responses = test_user_failed_x25519_pub_key.into_iter();
    assert_eq!(
        responses.next().unwrap().unwrap().text().await.unwrap(),
        "{\"Err\":\"Timed out waiting for remote party\"}"
    );

    assert_eq!(
        responses.next().unwrap().unwrap().text().await.unwrap(),
        "{\"Err\":\"Timed out waiting for remote party\"}"
    );

    // Test attempting to connect over ws by someone who is not in the signing group
    let validator_ip_and_key = validator_ips_and_keys[0].clone();
    let connection_attempt_handle = tokio::spawn(async move {
        // Wait for the "user" to submit the signing request
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ws_endpoint = format!("ws://{}/ws", validator_ip_and_key.0);
        let (ws_stream, _response) = connect_async(ws_endpoint).await.unwrap();

        let ferdie_pair = AccountKeyring::Ferdie.pair();

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

        assert_eq!(
            Err("Decryption(\"Public key does not match that given in UserTransactionRequest or \
                 register transaction\")"
                .to_string()),
            subscribe_response
        );
        // The stream should not continue to send messages
        // returns true if this part of the test passes
        encrypted_connection.recv().await.is_err()
    });
    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;

    let test_user_bad_connection_res = submit_transaction_requests(
        vec![validator_ips_and_keys[1].clone()],
        generic_msg.clone(),
        one,
    )
    .await;

    for res in test_user_bad_connection_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "{\"Err\":\"Timed out waiting for remote party\"}"
        );
    }

    assert!(connection_attempt_handle.await.unwrap());
    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    // Bad Account ID - an account ID is given which is not in the signing group
    let mut generic_msg_bad_account_id = generic_msg.clone();
    generic_msg_bad_account_id.validators_info[0].tss_account =
        subxtAccountId32(AccountKeyring::Dave.into());

    let test_user_failed_tss_account = submit_transaction_requests(
        validator_ips_and_keys.clone(),
        generic_msg_bad_account_id,
        one,
    )
    .await;

    for res in test_user_failed_tss_account {
        let res = res.unwrap();
        assert_eq!(res.status(), 500);
        assert_eq!(res.text().await.unwrap(), "Invalid Signer: Invalid Signer in Signing group");
    }

    // Now, test a signature request that should fail
    // The test program is written to fail when `auxilary_data` is `None`
    generic_msg.auxilary_data = None;
    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;

    let test_user_failed_programs_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;

    for res in test_user_failed_programs_res {
        assert_eq!(
            res.unwrap().text().await.unwrap(),
            "Runtime error: Runtime(Error::Evaluation(\"This program requires that `auxilary_data` be `Some`.\"))"
        );
    }

    let mock_client = reqwest::Client::new();
    // fails verification tests
    // wrong key for wrong validator
    let failed_signed_message = EncryptedSignedMessage::new(
        &one.pair(),
        serde_json::to_vec(&generic_msg.clone()).unwrap(),
        &X25519_PUBLIC_KEYS[1],
        &[],
    )
    .unwrap();
    let failed_res = mock_client
        .post("http://127.0.0.1:3001/user/sign_tx")
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

    let sig: [u8; 64] = [0; 64];
    let user_input_bad = EncryptedSignedMessage::new_with_given_signature(
        &one.pair(),
        serde_json::to_vec(&generic_msg.clone()).unwrap(),
        &X25519_PUBLIC_KEYS[0],
        &[],
        sr25519::Signature::from_raw(sig),
    )
    .unwrap();

    let failed_sign = mock_client
        .post("http://127.0.0.1:3001/user/sign_tx")
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

    clean_tests();
}

/// Test demonstrating registering with private key visibility, where the user participates in DKG
/// and holds a keyshare.
#[tokio::test]
#[serial]
async fn test_register_with_private_key_visibility() {
    initialize_test_logger().await;
    clean_tests();

    let one = AccountKeyring::One;
    let program_modification_account = AccountKeyring::Charlie;
    let program_manager = AccountKeyring::Dave;

    let (validator_ips, _validator_ids, _users_keyshare_option) =
        spawn_testing_validators(None, false, false).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_hash = store_program(
        &api,
        &rpc,
        &program_manager.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;

    let one_x25519_sk = StaticSecret::random_from_rng(rand_core::OsRng);
    let x25519_public_key = PublicKey::from(&one_x25519_sk).to_bytes();

    put_register_request_on_chain(
        &api,
        &rpc,
        &one,
        program_modification_account.to_account_id().into(),
        KeyVisibility::Private(x25519_public_key),
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await;
    run_to_block(&rpc, block_number + 1).await;

    // Simulate the propagation pallet making a `user/new` request to the second validator
    // as we only have one chain node running
    let onchain_user_request = {
        // Since we only have two validators we use both of them, but if we had more we would
        // need to select them using same method as the chain does (based on block number)
        let validators_info: Vec<entropy_shared::ValidatorInfo> = validator_ips
            .iter()
            .enumerate()
            .map(|(i, ip)| entropy_shared::ValidatorInfo {
                ip_address: ip.as_bytes().to_vec(),
                x25519_public_key: X25519_PUBLIC_KEYS[i],
                tss_account: TSS_ACCOUNTS[i].clone().encode(),
            })
            .collect();
        OcwMessageDkg {
            sig_request_accounts: vec![one.public().encode()],
            block_number,
            validators_info,
        }
    };

    let client = reqwest::Client::new();
    let validators_info: Vec<ValidatorInfo> = validator_ips
        .iter()
        .enumerate()
        .map(|(i, ip)| ValidatorInfo {
            ip_address: ip.to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[i],
            tss_account: TSS_ACCOUNTS[i].clone(),
        })
        .collect();

    // Call the `user/new` endpoint, and connect and participate in the protocol
    let (new_user_response_result, keyshare_result) = future::join(
        client
            .post("http://127.0.0.1:3002/user/new")
            .body(onchain_user_request.clone().encode())
            .send(),
        user_participates_in_dkg_protocol(
            validators_info.clone(),
            &one.pair(),
            one_x25519_sk,
            block_number,
        ),
    )
    .await;

    let response = new_user_response_result.unwrap();
    assert_eq!(response.text().await.unwrap(), "");

    assert!(keyshare_result.is_ok());
    clean_tests();
}

#[tokio::test]
async fn test_compute_hash() {
    initialize_test_logger().await;
    clean_tests();
    let one = AccountKeyring::Dave;
    let substrate_context = testing_context().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let mut runtime = Runtime::default();
    let program_hash = store_program(
        &api,
        &rpc,
        &one.pair(),
        TEST_PROGRAM_CUSTOM_HASH.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    let message_hash = compute_hash(
        &api,
        &rpc,
        &HashingAlgorithm::Custom(0),
        &mut runtime,
        &vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }],
        PREIMAGE_SHOULD_SUCCEED,
    )
    .await
    .unwrap();
    // custom hash program uses blake 3 to hash
    let expected_hash = blake3::hash(PREIMAGE_SHOULD_SUCCEED).as_bytes().to_vec();
    assert_eq!(message_hash.to_vec(), expected_hash);
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
    test_user_res: Vec<Result<reqwest::Response, reqwest::Error>>,
    message_should_succeed_hash: [u8; 32],
    keyshare_option: Option<KeyShare<KeyParams>>,
) {
    let mut i = 0;
    for res in test_user_res {
        let mut res = res.unwrap();
        assert_eq!(res.status(), 200);
        let chunk = res.chunk().await.unwrap().unwrap();
        let signing_result: Result<(String, Signature), String> =
            serde_json::from_slice(&chunk).unwrap();
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
        assert_eq!(keyshare_option.clone().unwrap().verifying_key(), recovery_key_from_sig);
        let sig_recovery = <sr25519::Pair as Pair>::verify(
            &signing_result.clone().unwrap().1,
            BASE64_STANDARD.decode(signing_result.unwrap().0).unwrap(),
            &sr25519::Public(TSS_ACCOUNTS[i].0),
        );
        assert!(sig_recovery);
        i += 1;
    }
}

#[tokio::test]
#[serial]
async fn test_fail_infinite_program() {
    initialize_test_logger().await;
    clean_tests();

    let one = AccountKeyring::Dave;
    let two = AccountKeyring::Two;

    let (validator_ips, _validator_ids, _) =
        spawn_testing_validators(Some(DAVE_VERIFYING_KEY.to_vec()), false, false).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();

    let program_hash = store_program(
        &entropy_api,
        &rpc,
        &two.pair(),
        TEST_INFINITE_LOOP_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    update_programs(
        &entropy_api,
        &rpc,
        DAVE_VERIFYING_KEY,
        &one.pair(),
        OtherBoundedVec(vec![OtherProgramInstance {
            program_pointer: program_hash,
            program_config: vec![],
        }]),
    )
    .await
    .unwrap();

    let validators_info = vec![
        ValidatorInfo {
            ip_address: "localhost:3001".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        },
        ValidatorInfo {
            ip_address: "127.0.0.1:3002".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone(),
        },
    ];

    let mut generic_msg = UserSignatureRequest {
        message: hex::encode(PREIMAGE_SHOULD_SUCCEED),
        auxilary_data: Some(vec![
            Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
            Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
        ]),
        validators_info,
        block_number: rpc.chain_get_header(None).await.unwrap().unwrap().number,
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key: DAVE_VERIFYING_KEY.to_vec(),
    };

    let validator_ips_and_keys = vec![
        (validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]),
        (validator_ips[1].clone(), X25519_PUBLIC_KEYS[1]),
    ];

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;

    let test_infinite_loop =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;
    for res in test_infinite_loop {
        assert_eq!(res.unwrap().text().await.unwrap(), "Runtime error: OutOfFuel");
    }
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

    let one = AccountKeyring::Dave;

    let (validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(DAVE_VERIFYING_KEY.to_vec()), false, false).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();
    let keypair = Sr25519Keypair::generate();
    let public_key = BASE64_STANDARD.encode(keypair.public);

    let device_key_user_config = UserConfig {
        ecdsa_public_keys: None,
        sr25519_public_keys: Some(vec![public_key.clone()]),
        ed25519_public_keys: None,
    };
    // check to make sure config data stored properly
    let program_query = entropy::storage().programs().programs(*DEVICE_KEY_HASH);
    let program_data = query_chain(&entropy_api, &rpc, program_query, None).await.unwrap().unwrap();
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
        &entropy_api,
        &rpc,
        DAVE_VERIFYING_KEY,
        &one.pair(),
        OtherBoundedVec(vec![OtherProgramInstance {
            program_pointer: *DEVICE_KEY_HASH,
            program_config: serde_json::to_vec(&device_key_user_config).unwrap(),
        }]),
    )
    .await
    .unwrap();

    let validators_info = vec![
        ValidatorInfo {
            ip_address: "localhost:3001".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        },
        ValidatorInfo {
            ip_address: "127.0.0.1:3002".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone(),
        },
    ];
    let context = signing_context(b"");

    let sr25519_signature: Sr25519Signature = keypair.sign(context.bytes(PREIMAGE_SHOULD_SUCCEED));

    let aux_data_json_sr25519 = AuxData {
        public_key_type: "sr25519".to_string(),
        public_key,
        signature: BASE64_STANDARD.encode(sr25519_signature.to_bytes()),
        context: "".to_string(),
    };
    let mut generic_msg = UserSignatureRequest {
        message: hex::encode(PREIMAGE_SHOULD_SUCCEED),
        auxilary_data: Some(vec![Some(hex::encode(
            &serde_json::to_string(&aux_data_json_sr25519.clone()).unwrap(),
        ))]),
        validators_info,
        block_number: rpc.chain_get_header(None).await.unwrap().unwrap().number,
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key: DAVE_VERIFYING_KEY.to_vec(),
    };

    let validator_ips_and_keys = vec![
        (validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]),
        (validator_ips[1].clone(), X25519_PUBLIC_KEYS[1]),
    ];

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    let message_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);
    let test_user_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;
    verify_signature(test_user_res, message_hash, keyshare_option.clone()).await;
}

/// FIXME (#909): Ignored due to block number changing message causing signing selection to be the incorrect nodes
#[ignore]
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

    let one = AccountKeyring::Dave;
    let two = AccountKeyring::Eve;
    let alice = AccountKeyring::Alice;

    let (validator_ips, _validator_ids, keyshare_option) =
        spawn_testing_validators(Some(EVE_VERIFYING_KEY.to_vec()), false, true).await;
    let substrate_context = test_node_process_testing_state(true).await;
    let entropy_api = get_api(&substrate_context.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.ws_url).await.unwrap();

    let verifying_key =
        keyshare_option.clone().unwrap().verifying_key().to_encoded_point(true).as_bytes().to_vec();
    let verfiying_key_account_hash = blake2_256(&verifying_key);
    let verfiying_key_account = subxtAccountId32(verfiying_key_account_hash);

    // Add funds to faucet
    let call = RuntimeCall::Balances(BalancesCall::force_set_balance {
        who: verfiying_key_account.clone().into(),
        new_free: 10000000000000000000000u128,
    });
    let add_balance_tx = entropy::tx().sudo().sudo(call);

    let signature_request_pair_signer =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(alice.into());

    let tx_params_balance = Params::new().build();
    entropy_api
        .tx()
        .create_signed(&add_balance_tx, &signature_request_pair_signer, tx_params_balance)
        .await
        .unwrap()
        .submit_and_watch()
        .await
        .unwrap();

    let program_hash = store_program(
        &entropy_api,
        &rpc,
        &two.pair(),
        FAUCET_PROGRAM.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    let amount_to_send = 200000001;
    let genesis_hash = &entropy_api.genesis_hash();

    let faucet_user_config = UserConfig {
        max_transfer_amount: amount_to_send,
        genesis_hash: hex::encode(genesis_hash.encode()),
    };

    update_programs(
        &entropy_api,
        &rpc,
        verifying_key.clone().try_into().unwrap(),
        &two.pair(),
        OtherBoundedVec(vec![OtherProgramInstance {
            program_pointer: program_hash,
            program_config: serde_json::to_vec(&faucet_user_config).unwrap(),
        }]),
    )
    .await
    .unwrap();

    let validators_info = vec![
        ValidatorInfo {
            ip_address: "localhost:3001".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        },
        ValidatorInfo {
            ip_address: "127.0.0.1:3002".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone(),
        },
    ];
    // get tx data for aux data
    let spec_version = entropy_api.runtime_version().spec_version;
    let transaction_version = entropy_api.runtime_version().transaction_version;

    let aux_data = AuxData {
        spec_version,
        transaction_version,
        string_account_id: one.to_account_id().to_string(),
        amount: amount_to_send,
    };
    // create a partial tx to sign
    let tx_params = Params::new().build();
    let balance_transfer_tx =
        entropy::tx().balances().transfer_allow_death(one.to_account_id().into(), aux_data.amount);
    let partial =
        entropy_api.tx().create_partial_signed_offline(&balance_transfer_tx, tx_params).unwrap();

    let mut generic_msg = UserSignatureRequest {
        message: hex::encode(partial.signer_payload()),
        auxilary_data: Some(vec![Some(hex::encode(
            &serde_json::to_string(&aux_data.clone()).unwrap(),
        ))]),
        validators_info,
        block_number: rpc.chain_get_header(None).await.unwrap().unwrap().number,
        hash: HashingAlgorithm::Blake2_256,
        signature_verifying_key: verifying_key.clone().to_vec(),
    };

    let validator_ips_and_keys = vec![
        (validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]),
        (validator_ips[1].clone(), X25519_PUBLIC_KEYS[1]),
    ];

    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    let test_user_res =
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one).await;
    let mut decoded_sig: Vec<u8> = vec![];
    for res in test_user_res {
        let chunk = res.unwrap().chunk().await.unwrap().unwrap();
        let signing_result: Result<(String, Signature), String> =
            serde_json::from_slice(&chunk).unwrap();
        decoded_sig = BASE64_STANDARD.decode(signing_result.clone().unwrap().0).unwrap();
    }
    // take signed tx and repack it into a submitable tx
    let submittable_extrinsic = partial.sign_with_address_and_signature(
        &MultiAddress::Id(verfiying_key_account.clone().into()),
        &MultiSignature::Ecdsa(decoded_sig.try_into().unwrap()),
    );
    let account = subxtAccountId32::from_str(&aux_data.string_account_id).unwrap();
    // get balance before for checking if succeful
    let balance_query = entropy::storage().system().account(account.clone());
    let account_info = query_chain(&entropy_api, &rpc, balance_query, None).await.unwrap().unwrap();
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
    let account_info =
        query_chain(&entropy_api, &rpc, balance_after_query, None).await.unwrap().unwrap();
    let balance_after = account_info.data.free;
    // make sure funds were transfered
    ma::assert_gt!(balance_after, balance_before);
    clean_tests();
}

#[tokio::test]
#[serial]
async fn test_mutiple_confirm_done() {
    initialize_test_logger().await;
    clean_tests();

    let alice = AccountKeyring::Alice;
    let bob = AccountKeyring::Bob;

    let alice_program = AccountKeyring::Charlie;
    let program_manager = AccountKeyring::Dave;

    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&cxt.node_proc.ws_url).await.unwrap();

    let program_hash = store_program(
        &api,
        &rpc,
        &program_manager.pair(),
        TEST_PROGRAM_WASM_BYTECODE.to_owned(),
        vec![],
        vec![],
        vec![],
    )
    .await
    .unwrap();

    put_register_request_on_chain(
        &api,
        &rpc,
        &alice,
        alice_program.to_account_id().into(),
        KeyVisibility::Public,
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await;

    put_register_request_on_chain(
        &api,
        &rpc,
        &bob,
        alice_program.to_account_id().into(),
        KeyVisibility::Public,
        BoundedVec(vec![ProgramInstance { program_pointer: program_hash, program_config: vec![] }]),
    )
    .await;

    let (signer_alice, _) = get_signer_and_x25519_secret_from_mnemonic(DEFAULT_MNEMONIC).unwrap();

    confirm_registered(
        &api,
        &rpc,
        alice.to_account_id().into(),
        0u8,
        &signer_alice,
        DEFAULT_VERIFYING_KEY.to_vec(),
        0u32,
    )
    .await
    .unwrap();
    confirm_registered(
        &api,
        &rpc,
        bob.to_account_id().into(),
        0u8,
        &signer_alice,
        DEFAULT_VERIFYING_KEY.to_vec(),
        1u32,
    )
    .await
    .unwrap();
    check_has_confirmation(&api, &rpc, &alice.pair()).await;
    check_has_confirmation(&api, &rpc, &bob.pair()).await;
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
    let kv_store = load_kv_store(&None, None).await;

    let request_limit_query = entropy::storage().parameters().request_limit();
    let request_limit = query_chain(&api, &rpc, request_limit_query, None).await.unwrap().unwrap();

    // no error
    assert!(request_limit_check(
        &rpc,
        &kv_store,
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        request_limit
    )
    .await
    .is_ok());

    // run up the request check to one less then max (to check integration)
    for _ in 0..request_limit {
        increment_or_wipe_request_limit(
            &rpc,
            &kv_store,
            hex::encode(DAVE_VERIFYING_KEY.to_vec()),
            request_limit,
        )
        .await
        .unwrap();
    }
    // should now fail
    let err_too_many_requests = request_limit_check(
        &rpc,
        &kv_store,
        hex::encode(DAVE_VERIFYING_KEY.to_vec()),
        request_limit,
    )
    .await
    .map_err(|e| e.to_string());
    assert_eq!(err_too_many_requests, Err("Too many requests - wait a block".to_string()));

    clean_tests();
}

pub async fn submit_transaction_requests(
    validator_urls_and_keys: Vec<(String, [u8; 32])>,
    signature_request: UserSignatureRequest,
    keyring: Sr25519Keyring,
) -> Vec<std::result::Result<reqwest::Response, reqwest::Error>> {
    let mock_client = reqwest::Client::new();
    join_all(
        validator_urls_and_keys
            .iter()
            .map(|validator_tuple| async {
                let signed_message = EncryptedSignedMessage::new(
                    &keyring.pair(),
                    serde_json::to_vec(&signature_request.clone()).unwrap(),
                    &validator_tuple.1,
                    &[],
                )
                .unwrap();
                let url = format!("http://{}/user/sign_tx", validator_tuple.0.clone());
                mock_client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(serde_json::to_string(&signed_message).unwrap())
                    .send()
                    .await
            })
            .collect::<Vec<_>>(),
    )
    .await
}

pub fn get_sign_tx_data(
    validator_ips: Vec<String>,
    message: String,
) -> (Vec<ValidatorInfo>, UserSignatureRequest, Vec<(String, [u8; 32])>) {
    let validators_info = vec![
        ValidatorInfo {
            ip_address: "localhost:3001".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        },
        ValidatorInfo {
            ip_address: "127.0.0.1:3002".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone(),
        },
    ];
    let generic_msg = UserSignatureRequest {
        message,
        auxilary_data: Some(vec![
            Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
            Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
        ]),
        validators_info: validators_info.clone(),
        block_number: 0,
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key: DAVE_VERIFYING_KEY.to_vec(),
    };

    let validator_ips_and_keys = vec![
        (validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]),
        (validator_ips[1].clone(), X25519_PUBLIC_KEYS[1]),
    ];

    (validators_info, generic_msg, validator_ips_and_keys)
}
