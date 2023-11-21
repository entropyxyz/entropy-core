use axum::http::StatusCode;
use entropy_protocol::{KeyParams, ValidatorInfo};
use entropy_shared::{KeyVisibility, OcwMessageDkg};
use futures::future::join_all;
use futures::future::{self};
use kvdb::{clean_tests, kv_manager::helpers::deserialize as keyshare_deserialize};
use parity_scale_codec::Encode;
use serde::{Deserialize, Serialize};
use serial_test::serial;
use sp_core::{crypto::Ss58Codec, Pair as OtherPair};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use std::time::SystemTime;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    ext::sp_core::{sr25519, sr25519::Signature, Bytes, Pair},
    tx::PairSigner,
    utils::{AccountId32 as subxtAccountId32, Static},
    OnlineClient,
};
use synedrion::{
    k256::ecdsa::{RecoveryId, Signature as k256Signature, VerifyingKey},
    KeyShare,
};
use testing_utils::{
    constants::{
        AUXILARY_DATA_SHOULD_SUCCEED, PREIMAGE_SHOULD_SUCCEED, TEST_PROGRAM_WASM_BYTECODE,
        TSS_ACCOUNTS, X25519_PUBLIC_KEYS,
    },
    substrate_context::test_context_stationary,
};
use testing_utils::{test_client::update_programs, tss_server_proc::spawn_testing_validators};
use x25519_dalek::PublicKey;

use server::{
    chain_api::{entropy, get_api, get_rpc, EntropyConfig},
    common::{create_unique_tx_id, Hasher, UnsafeQuery, UserSignatureRequest},
    launch::{DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC},
    validation::{derive_static_secret, SignedMessage},
};

#[tokio::test]
#[serial]
async fn test_wasm_sign_tx_user_participates() {
    clean_tests();
    let one = AccountKeyring::Eve;

    let signing_address = one.clone().to_account_id().to_ss58check();
    let (validator_ips, _validator_ids, users_keyshare_option) =
        spawn_testing_validators(Some(signing_address.clone()), true).await;
    let substrate_context = test_context_stationary().await;
    let entropy_api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();

    update_programs(&entropy_api, &one.pair(), &one.pair(), TEST_PROGRAM_WASM_BYTECODE.to_owned())
        .await;

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

    let signing_address = one.to_account_id().to_ss58check();
    let hash_as_hexstring = hex::encode(message_should_succeed_hash);
    let sig_uid = create_unique_tx_id(&signing_address, &hash_as_hexstring);

    let mut generic_msg = UserSignatureRequest {
        message: encoded_transaction_request.clone(),
        auxilary_data: Some(hex::encode(AUXILARY_DATA_SHOULD_SUCCEED)),
        validators_info: validators_info.clone(),
        timestamp: SystemTime::now(),
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
                        let server_public_key = PublicKey::from(validator_tuple.1);
                        let signed_message = SignedMessage::new(
                            &keyring.pair(),
                            &Bytes(serde_json::to_vec(&generic_msg.clone()).unwrap()),
                            &server_public_key,
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
        };
    let validator_ips_and_keys = vec![
        (validator_ips[0].clone(), X25519_PUBLIC_KEYS[0]),
        (validator_ips[1].clone(), X25519_PUBLIC_KEYS[1]),
    ];
    generic_msg.timestamp = SystemTime::now();

    let one_x25519_sk = derive_static_secret(&one.pair());

    let eve_seed: [u8; 32] =
        hex::decode("786ad0e2df456fe43dd1f91ebca22e235bc162e0bb8d53c633e8c85b2af68b7a")
            .unwrap()
            .try_into()
            .unwrap();

    // Submit transaction requests, and connect and participate in signing
    let (mut test_user_res, user_sig) = future::join(
        submit_transaction_requests(validator_ips_and_keys.clone(), generic_msg.clone(), one),
        spawn_user_participates_in_signing_protocol(
            &users_keyshare_option.clone().unwrap(),
            &sig_uid,
            validators_info.clone(),
            eve_seed,
            &one_x25519_sk,
        ),
    )
    .await;

    // Check that the signature the user gets matches the first of the server's signatures
    let user_sig = if let Some(user_sig_stripped) = user_sig.strip_suffix("\n") {
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
    verify_signature(test_user_res, message_should_succeed_hash, users_keyshare_option.clone())
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

    let (validator_ips, _validator_ids, _users_keyshare_option) =
        spawn_testing_validators(None, false).await;
    let substrate_context = test_context_stationary().await;
    let api = get_api(&substrate_context.node_proc.ws_url).await.unwrap();
    let rpc = get_rpc(&substrate_context.node_proc.ws_url).await.unwrap();
    let block_number = rpc.chain_get_header(None).await.unwrap().unwrap().number + 1;

    let one_x25519_sk = derive_static_secret(&one.pair());
    let x25519_public_key = PublicKey::from(&one_x25519_sk).to_bytes();

    put_register_request_on_chain(
        &api,
        &one,
        program_modification_account.to_account_id().into(),
        KeyVisibility::Private(x25519_public_key),
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
        OcwMessageDkg { sig_request_accounts: vec![one.encode()], block_number, validators_info }
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

    let one_seed: [u8; 32] =
        hex::decode("3b3993c957ed9342cbb011eb9029c53fb253345114eff7da5951e98a41ba5ad5")
            .unwrap()
            .try_into()
            .unwrap();

    // Call the `user/new` endpoint, and connect and participate in the protocol
    let (new_user_response_result, user_keyshare_json) = future::join(
        client
            .post("http://127.0.0.1:3002/user/new")
            .body(onchain_user_request.clone().encode())
            .send(),
        spawn_user_participates_in_dkg_protocol(validators_info.clone(), one_seed, &one_x25519_sk),
    )
    .await;

    let response = new_user_response_result.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "");

    let signing_address = one.to_account_id().to_ss58check();
    let get_query = UnsafeQuery::new(signing_address, vec![]).to_json();
    let server_keyshare_response = client
        .post("http://127.0.0.1:3001/unsafe/get")
        .header("Content-Type", "application/json")
        .body(get_query.clone())
        .send()
        .await
        .unwrap();

    println!("user keyshare: {}", user_keyshare_json);
    let user_keyshare: KeyShare<KeyParams> = serde_json::from_str(&user_keyshare_json).unwrap();

    let server_keyshare_serialized = server_keyshare_response.bytes().await.unwrap();
    let server_keyshare: KeyShare<KeyParams> =
        keyshare_deserialize(&server_keyshare_serialized).unwrap();

    let user_verifying_key = user_keyshare.verifying_key();
    let server_verifying_key = server_keyshare.verifying_key();
    assert_eq!(user_verifying_key, server_verifying_key);

    clean_tests();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserParticipatesInSigningProtocolArgs {
    user_sig_req_seed: Vec<u8>,
    x25519_private_key: Vec<u8>,
    sig_uid: String,
    key_share: String,
    validators_info: Vec<ValidatorInfoParsed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserParticipatesInDkgProtocolArgs {
    user_sig_req_seed: Vec<u8>,
    x25519_private_key: Vec<u8>,
    validators_info: Vec<ValidatorInfoParsed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidatorInfoParsed {
    x25519_public_key: [u8; 32],
    ip_address: String,
    tss_account: [u8; 32],
}

/// For testing running the protocol on wasm, spawn a process running nodejs and pass
/// the protocol runnning parameters as JSON as a command line argument
pub async fn spawn_user_participates_in_signing_protocol(
    key_share: &KeyShare<KeyParams>,
    sig_uid: &str,
    validators_info: Vec<ValidatorInfo>,
    user_sig_req_seed: [u8; 32],
    x25519_private_key: &x25519_dalek::StaticSecret,
) -> String {
    let args = UserParticipatesInSigningProtocolArgs {
        sig_uid: sig_uid.to_string(),
        user_sig_req_seed: user_sig_req_seed.to_vec(),
        validators_info: validators_info
            .into_iter()
            .map(|validator_info| ValidatorInfoParsed {
                x25519_public_key: validator_info.x25519_public_key,
                ip_address: validator_info.ip_address.to_string(),
                tss_account: *validator_info.tss_account.as_ref(),
            })
            .collect(),
        key_share: serde_json::to_string(key_share).unwrap(),
        x25519_private_key: x25519_private_key.to_bytes().to_vec(),
    };
    let json_params = serde_json::to_string(&args).unwrap();

    let test_script_path = format!(
        "{}/crypto/protocol/nodejs-test/index.js",
        project_root::get_project_root().unwrap().to_string_lossy()
    );

    let output = tokio::process::Command::new("node")
        .arg(test_script_path)
        .arg("sign")
        .arg(json_params)
        .output()
        .await
        .unwrap();
    String::from_utf8(output.stdout).unwrap()
}

/// For testing running the DKG protocol on wasm, spawn a process running nodejs and pass
/// the protocol runnning parameters as JSON as a command line argument
pub async fn spawn_user_participates_in_dkg_protocol(
    validators_info: Vec<ValidatorInfo>,
    user_sig_req_seed: [u8; 32],
    x25519_private_key: &x25519_dalek::StaticSecret,
) -> String {
    let args = UserParticipatesInDkgProtocolArgs {
        user_sig_req_seed: user_sig_req_seed.to_vec(),
        validators_info: validators_info
            .into_iter()
            .map(|validator_info| ValidatorInfoParsed {
                x25519_public_key: validator_info.x25519_public_key,
                ip_address: validator_info.ip_address.to_string(),
                tss_account: *validator_info.tss_account.as_ref(),
            })
            .collect(),
        x25519_private_key: x25519_private_key.to_bytes().to_vec(),
    };
    let json_params = serde_json::to_string(&args).unwrap();

    let test_script_path = format!(
        "{}/crypto/protocol/nodejs-test/index.js",
        project_root::get_project_root().unwrap().to_string_lossy()
    );
    let output = tokio::process::Command::new("node")
        .arg(test_script_path)
        .arg("register")
        .arg(json_params)
        .output()
        .await
        .unwrap();
    println!("stderr {}", String::from_utf8(output.stderr).unwrap());
    String::from_utf8(output.stdout).unwrap()
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
        let mut decoded_sig = base64::decode(signing_result.clone().unwrap().0).unwrap();
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
        let mnemonic = if i == 0 { DEFAULT_MNEMONIC } else { DEFAULT_BOB_MNEMONIC };
        let sk = <sr25519::Pair as Pair>::from_string(mnemonic, None).unwrap();
        let sig_recovery = <sr25519::Pair as Pair>::verify(
            &signing_result.clone().unwrap().1,
            base64::decode(signing_result.unwrap().0).unwrap(),
            &sr25519::Public(sk.public().0),
        );
        assert!(sig_recovery);
        i += 1;
    }
}

pub async fn put_register_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: &Sr25519Keyring,
    program_modification_account: subxtAccountId32,
    key_visibility: KeyVisibility,
) {
    let sig_req_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keyring.pair());

    let empty_program = vec![];
    let registering_tx = entropy::tx().relayer().register(
        program_modification_account,
        Static(key_visibility),
        empty_program,
    );

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &sig_req_account)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();
}

pub async fn run_to_block(rpc: &LegacyRpcMethods<EntropyConfig>, block_run: u32) {
    let mut current_block = 0;
    while current_block < block_run {
        current_block = rpc.chain_get_header(None).await.unwrap().unwrap().number;
    }
}
