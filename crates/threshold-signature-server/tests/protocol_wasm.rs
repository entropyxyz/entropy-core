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

#![cfg(feature = "wasm_test")]

//! Integration tests which use a nodejs process to test wasm bindings to the entropy-protocol
//! client functions.
//!
//! These tests require additional build steps and are not run by default.

mod helpers;

use axum::http::StatusCode;
use entropy_client::{
    chain_api::{
        entropy::{
            self,
            runtime_types::{
                bounded_collections::bounded_vec::BoundedVec,
                pallet_registry::pallet::ProgramInstance,
            },
        },
        get_api, get_rpc, EntropyConfig,
    },
    client::{put_register_request_on_chain, store_program, update_programs},
    user::UserSignatureRequest,
    Hasher,
};
use entropy_kvdb::clean_tests;
use entropy_protocol::{sign_and_encrypt::EncryptedSignedMessage, KeyParams, ValidatorInfo};
use entropy_shared::{HashingAlgorithm, KeyVisibility, OcwMessageDkg, EVE_VERIFYING_KEY};
use entropy_testing_utils::{
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, EVE_X25519_SECRET_KEY, PREIMAGE_SHOULD_SUCCEED,
        TEST_PROGRAM_WASM_BYTECODE, TSS_ACCOUNTS, X25519_PUBLIC_KEYS,
    },
    substrate_context::test_context_stationary,
    tss_server_process::spawn_testing_validators,
};
use futures::future::join_all;
use futures::future::{self};
use parity_scale_codec::Encode;
use serde::{Deserialize, Serialize};
use serial_test::serial;
use sp_core::crypto::{AccountId32, Pair};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{
    backend::legacy::LegacyRpcMethods, events::EventsClient, ext::sp_core::sr25519::Signature,
    Config, OnlineClient,
};
use synedrion::KeyShare;
use x25519_dalek::{PublicKey, StaticSecret};

/// Test demonstrating signing a message with private key visibility on wasm
#[tokio::test]
#[serial]
async fn test_wasm_sign_tx_user_participates() {
    clean_tests();
    let one = AccountKeyring::Eve;
    let dave = AccountKeyring::Dave;

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
    let program_pointer = store_program(
        &entropy_api,
        &rpc,
        &dave.pair(),
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
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();

    let validators_info = vec![
        ValidatorInfo {
            ip_address: "127.0.0.1:3001".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[0],
            tss_account: TSS_ACCOUNTS[0].clone(),
        },
        ValidatorInfo {
            ip_address: "127.0.0.1:3002".to_string(),
            x25519_public_key: X25519_PUBLIC_KEYS[1],
            tss_account: TSS_ACCOUNTS[1].clone(),
        },
    ];

    let encoded_transaction_request: String = hex::encode(PREIMAGE_SHOULD_SUCCEED);
    let message_should_succeed_hash = Hasher::keccak(PREIMAGE_SHOULD_SUCCEED);

    let mut generic_msg = UserSignatureRequest {
        message: encoded_transaction_request.clone(),
        auxilary_data: Some(vec![
            Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
            Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
        ]),
        validators_info: validators_info.clone(),
        block_number: rpc.chain_get_header(None).await.unwrap().unwrap().number,
        hash: HashingAlgorithm::Keccak,
        signature_verifying_key: verifying_key.clone(),
    };

    let submit_transaction_requests =
        |validator_urls_and_keys: Vec<(String, [u8; 32])>,
         generic_msg: UserSignatureRequest,
         keyring: Sr25519Keyring| async move {
            let mock_client = reqwest::Client::new();
            join_all(
                validator_urls_and_keys
                    .iter()
                    .map(|validator_tuple| async {
                        let encryped_message = EncryptedSignedMessage::new(
                            &keyring.pair(),
                            serde_json::to_vec(&generic_msg.clone()).unwrap(),
                            &validator_tuple.1,
                            &[],
                        )
                        .unwrap();
                        let url = format!("http://{}/user/sign_tx", validator_tuple.0.clone());
                        mock_client
                            .post(url)
                            .header("Content-Type", "application/json")
                            .body(serde_json::to_string(&encryped_message).unwrap())
                            .send()
                            .await
                    })
                    .collect::<Vec<_>>(),
            )
            .await
        };
    let validator_ips_and_keys = vec![
        (validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]),
        (validator_ips[1].clone(), X25519_PUBLIC_KEYS[1]),
    ];
    generic_msg.block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number;

    // Submit transaction requests, and connect and participate in signing
    let (mut test_user_res, user_sig) = future::join(
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one),
        spawn_user_participates_in_signing_protocol(
            &users_keyshare_option.clone().unwrap(),
            &message_should_succeed_hash,
            validators_info.clone(),
            one.pair().to_raw_vec(),
            EVE_X25519_SECRET_KEY.to_vec(),
        ),
    )
    .await;

    // Check that the signature the user gets matches the first of the server's signatures
    let user_sig = if let Some(user_sig_stripped) = user_sig.strip_suffix('\n') {
        user_sig_stripped.to_string()
    } else {
        user_sig
    };
    let mut server_res = test_user_res.pop().unwrap().unwrap();
    assert_eq!(server_res.status(), 200);
    let chunk = server_res.chunk().await.unwrap().unwrap();
    let signing_result: Result<(String, Signature), String> =
        serde_json::from_slice(&chunk).unwrap();
    assert_eq!(user_sig, signing_result.unwrap().0);

    // Verify the remaining server results, which should be the same
    helpers::verify_signature(
        test_user_res,
        message_should_succeed_hash,
        users_keyshare_option.clone(),
    )
    .await;

    clean_tests();
}

/// Test demonstrating registering with private key visibility on wasm
#[tokio::test]
#[serial]
async fn test_wasm_register_with_private_key_visibility() {
    clean_tests();

    let one = AccountKeyring::One;
    let program_modification_account = AccountKeyring::Charlie;
    let dave = AccountKeyring::Dave;

    let (validator_ips, _validator_ids, _users_keyshare_option) =
        spawn_testing_validators(None, false, false).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();
    let program_pointer = store_program(
        &api,
        &rpc,
        &dave.pair(),
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
        one.pair(),
        program_modification_account.to_account_id().into(),
        KeyVisibility::Private(x25519_public_key),
        BoundedVec(vec![ProgramInstance { program_pointer, program_config: vec![] }]),
    )
    .await
    .unwrap();
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
            ip_address: ip.clone(),
            x25519_public_key: X25519_PUBLIC_KEYS[i],
            tss_account: TSS_ACCOUNTS[i].clone(),
        })
        .collect();

    // Call the `user/new` endpoint, and connect and participate in the protocol
    let (new_user_response_result, user_keyshare_json) = future::join(
        client
            .post("http://127.0.0.1:3002/user/new")
            .body(onchain_user_request.clone().encode())
            .send(),
        spawn_user_participates_in_dkg_protocol(
            validators_info.clone(),
            one.pair().to_raw_vec(),
            one_x25519_sk.as_bytes().to_vec(),
            block_number,
        ),
    )
    .await;

    let response = new_user_response_result.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "");

    let verifying_key = wait_for_register_confirmation(one.to_account_id(), api, rpc).await;

    let user_keyshare: KeyShare<KeyParams> = serde_json::from_str(&user_keyshare_json).unwrap();
    let user_verifying_key =
        user_keyshare.verifying_key().to_encoded_point(true).as_bytes().to_vec();

    assert_eq!(user_verifying_key, verifying_key);

    clean_tests();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserParticipatesInSigningProtocolArgs {
    user_sig_req_secret_key: Vec<u8>,
    user_x25519_secret_key: Vec<u8>,
    message_hash: Vec<u8>,
    key_share: String,
    validators_info: Vec<ValidatorInfoParsed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserParticipatesInDkgProtocolArgs {
    user_sig_req_secret_key: Vec<u8>,
    user_x25519_secret_key: Vec<u8>,
    validators_info: Vec<ValidatorInfoParsed>,
    block_number: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorInfoParsed {
    x25519_public_key: [u8; 32],
    ip_address: String,
    tss_account: [u8; 32],
}

/// For testing running the protocol on wasm, spawn a process running nodejs and pass
/// the protocol runnning parameters as JSON as a command line argument
async fn spawn_user_participates_in_signing_protocol(
    key_share: &KeyShare<KeyParams>,
    message_hash: &[u8; 32],
    validators_info: Vec<ValidatorInfo>,
    user_sig_req_secret_key: Vec<u8>,
    user_x25519_secret_key: Vec<u8>,
) -> String {
    let args = UserParticipatesInSigningProtocolArgs {
        message_hash: message_hash.to_vec(),
        user_sig_req_secret_key,
        user_x25519_secret_key,
        validators_info: validators_info
            .into_iter()
            .map(|validator_info| ValidatorInfoParsed {
                x25519_public_key: validator_info.x25519_public_key,
                ip_address: validator_info.ip_address.to_string(),
                tss_account: *validator_info.tss_account.as_ref(),
            })
            .collect(),
        key_share: serde_json::to_string(key_share).unwrap(),
    };
    let json_params = serde_json::to_string(&args).unwrap();

    spawn_node_process(json_params, "sign".to_string()).await
}

/// For testing running the DKG protocol on wasm, spawn a process running nodejs and pass
/// the protocol runnning parameters as JSON as a command line argument
async fn spawn_user_participates_in_dkg_protocol(
    validators_info: Vec<ValidatorInfo>,
    user_sig_req_secret_key: Vec<u8>,
    user_x25519_secret_key: Vec<u8>,
    block_number: u32,
) -> String {
    let args = UserParticipatesInDkgProtocolArgs {
        user_sig_req_secret_key,
        user_x25519_secret_key,
        validators_info: validators_info
            .into_iter()
            .map(|validator_info| ValidatorInfoParsed {
                x25519_public_key: validator_info.x25519_public_key,
                ip_address: validator_info.ip_address.to_string(),
                tss_account: *validator_info.tss_account.as_ref(),
            })
            .collect(),
        block_number,
    };
    let json_params = serde_json::to_string(&args).unwrap();

    spawn_node_process(json_params, "register".to_string()).await
}

async fn spawn_node_process(json_params: String, command_for_script: String) -> String {
    let test_script_path = format!(
        "{}/crates/protocol/nodejs-test/index.js",
        project_root::get_project_root().unwrap().to_string_lossy()
    );
    let output = tokio::process::Command::new("node")
        .arg(test_script_path)
        .arg(command_for_script)
        .arg(json_params)
        .output()
        .await
        .unwrap();

    let std_err = String::from_utf8(output.stderr).unwrap();
    if !std_err.is_empty() {
        tracing::warn!("Standard error from node process {}", std_err);
    }
    String::from_utf8(output.stdout).unwrap()
}

async fn run_to_block(rpc: &LegacyRpcMethods<EntropyConfig>, block_run: u32) {
    let mut current_block = 0;
    while current_block < block_run {
        current_block = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    }
}

async fn wait_for_register_confirmation(
    account_id: AccountId32,
    api: OnlineClient<EntropyConfig>,
    rpc: LegacyRpcMethods<EntropyConfig>,
) -> Vec<u8> {
    let account_id: <EntropyConfig as Config>::AccountId = account_id.into();
    for _ in 0..50 {
        let block_hash = rpc.chain_get_block_hash(None).await.unwrap();
        let events = EventsClient::new(api.clone()).at(block_hash.unwrap()).await.unwrap();
        let registered_event = events.find::<entropy::registry::events::AccountRegistered>();
        for event in registered_event.flatten() {
            // check if the event belongs to this user
            if event.0 == account_id {
                return event.1 .0;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    panic!("Timed out waiting for register confirmation");
}
