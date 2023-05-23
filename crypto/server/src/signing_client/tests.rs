use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Message, OCWMessage, SigRequest, ValidatorInfo, PRUNE_BLOCK};
use hex_literal::hex;
use kvdb::clean_tests;
use parity_scale_codec::Encode;
use rocket::http::{ContentType, Status};
use serial_test::serial;
use sp_core::{
    crypto::AccountId32,
    sr25519::{Pair, Public, Signature},
    Pair as PairTrait,
};
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{tx::PairSigner, OnlineClient};
use testing_utils::{
    constants::{TSS_ACCOUNTS, X25519_PUBLIC_KEYS},
    substrate_context::test_context_stationary,
};

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    helpers::{signing::create_unique_tx_id, tests::setup_client},
    r#unsafe::api::UnsafeQuery,
    signing_client::{
        new_party::signing_protocol::{create_signed_message, validate_signed_message},
        tests::entropy::runtime_types::entropy_shared::types::SigRequest as otherSigRequest,
        SigningErr,
    },
};

#[rocket::async_test]
#[serial]
async fn test_new_party() {
    clean_tests();
    let client = setup_client().await;

    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let dave = AccountKeyring::Dave;
    // transaction_request comes from ethers-js serializeTransaction()
    // See frontend threshold-server tests for more context
    let transaction_request = r#"0xef01808094772b9a9e8aa1c9db861c6611a82d251db4fac990019243726561746564204f6e20456e74726f7079018080"#;
    let parsed_tx =
        <Evm as Architecture>::TransactionRequest::parse(transaction_request.to_string()).unwrap();
    let sig_hash = parsed_tx.sighash();
    let block_number = api.rpc().block(None).await.unwrap().unwrap().block.header.number + 1;
    put_tx_request_on_chain(&api, &dave, sig_hash.as_bytes().to_vec()).await;
    let onchain_signature_request = OCWMessage {
        messages: vec![Message {
            sig_request: SigRequest { sig_hash: sig_hash.as_bytes().to_vec() },
            account: dave.to_raw_public_vec(),
            validators_info: vec![
                ValidatorInfo {
                    ip_address: b"127.0.0.1:3001".to_vec(),
                    x25519_public_key: X25519_PUBLIC_KEYS[0],
                    tss_account: TSS_ACCOUNTS[0].encode(),
                },
                ValidatorInfo {
                    ip_address: b"127.0.0.1:3002".to_vec(),
                    x25519_public_key: X25519_PUBLIC_KEYS[1],
                    tss_account: TSS_ACCOUNTS[1].encode(),
                },
            ],
        }],
        block_number,
    };

    run_to_block(&api, block_number + 1).await;

    let response = client
        .post("/signer/new_party")
        .body(onchain_signature_request.clone().encode())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let tx_id = create_unique_tx_id(&dave.to_account_id().to_string(), &hex::encode(sig_hash));
    // check that the signature request was stored in the kvdb
    let query_parsed_tx = client
        .post("/unsafe/get")
        .header(ContentType::JSON)
        .body(UnsafeQuery::new(tx_id.clone(), String::new()).to_json())
        .dispatch()
        .await;
    assert_eq!(
        query_parsed_tx.into_string().await,
        Some(serde_json::to_string(&onchain_signature_request.messages[0]).unwrap())
    );

    // check tx gets pruned
    let onchain_signature_request_prune =
        OCWMessage { messages: vec![], block_number: PRUNE_BLOCK + block_number };

    let response_2 = client
        .post("/signer/new_party")
        .body(onchain_signature_request_prune.clone().encode())
        .dispatch()
        .await;
    assert_eq!(response_2.status(), Status::NoContent);
    // tx no longer in kvdb
    let query_parsed_tx_pruned = client
        .post("/unsafe/get")
        .header(ContentType::JSON)
        .body(UnsafeQuery::new(tx_id, String::new()).to_json())
        .dispatch()
        .await;
    assert_eq!(query_parsed_tx_pruned.status(), Status::InternalServerError);

    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_new_party_fail_unverified() {
    clean_tests();
    let client = setup_client().await;
    let cxt = test_context_stationary().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let dave = AccountKeyring::Dave;
    // transaction_request comes from ethers-js serializeTransaction()
    // See frontend threshold-server tests for more context
    let transaction_request = r#"0xef01808094772b9a9e8aa1c9db861c6611a82d251db4fac990019243726561746564204f6e20456e74726f7079018080"#;
    let not_matching_sig_request =
        "0xe61e139a15f27f3d5ba043756aaca2b6fe9597a95973befa36dbe6095ee16da2";
    let parsed_tx =
        <Evm as Architecture>::TransactionRequest::parse(transaction_request.to_string()).unwrap();
    let sig_hash = parsed_tx.sighash();
    let block_number = api.rpc().block(None).await.unwrap().unwrap().block.header.number + 1;
    put_tx_request_on_chain(&api, &dave, sig_hash.as_bytes().to_vec()).await;

    let mut onchain_signature_request = OCWMessage {
        messages: vec![Message {
            sig_request: SigRequest { sig_hash: not_matching_sig_request.as_bytes().to_vec() },
            account: dave.to_raw_public_vec(),
            validators_info: vec![
                ValidatorInfo {
                    ip_address: b"127.0.0.1:3001".to_vec(),
                    x25519_public_key: [0; 32],
                    tss_account: TSS_ACCOUNTS[0].encode(),
                },
                ValidatorInfo {
                    ip_address: b"127.0.0.1:3002".to_vec(),
                    x25519_public_key: [0; 32],
                    tss_account: TSS_ACCOUNTS[1].encode(),
                },
            ],
        }],
        block_number,
    };

    run_to_block(&api, block_number + 1).await;

    let response = client
        .post("/signer/new_party")
        .body(onchain_signature_request.clone().encode())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::InternalServerError);
    assert_eq!(response.into_string().await.unwrap(), "Data is not verifiable");

    // change data to bad block number
    onchain_signature_request.block_number = 100;

    let response_2 = client
        .post("/signer/new_party")
        .body(onchain_signature_request.clone().encode())
        .dispatch()
        .await;
    assert_eq!(response_2.status(), Status::InternalServerError);
    assert_eq!(response_2.into_string().await.unwrap(), "Data is stale");

    clean_tests();
}

#[rocket::async_test]
async fn create_verify_signed_message() {
    let message: Box<[u8]> = Box::new([10]);
    let bad_message: Box<[u8]> = Box::new([11]);

    let seed: [u8; 32] = hex!("29b55504652cedded9ce0ee1f5a25b328ae6c6e97827f84eee6315d0f44816d8");
    let pair = sp_core::sr25519::Pair::from_seed(&seed);

    let signed_message = create_signed_message(&message, &pair);
    assert_eq!(hex::encode(signed_message.clone()).len(), 128);

    let _ = validate_signed_message(
        &message.to_vec(),
        signed_message.clone(),
        pair.public(),
        &vec![AccountId32::new(pair.public().0)],
    )
    .unwrap();

    // failing validation

    let failed_in_threshold_group = validate_signed_message(
        &message.to_vec(),
        signed_message.clone(),
        pair.public(),
        &vec![AccountId32::new(seed)],
    );
    assert!(matches!(
        failed_in_threshold_group,
        Err(SigningErr::MessageValidation("Unable to verify sender of message"))
    ));

    let failed_message_decrypt = validate_signed_message(
        &bad_message.to_vec(),
        signed_message,
        pair.public(),
        &vec![AccountId32::new(pair.public().0)],
    );
    assert!(matches!(
        failed_message_decrypt,
        Err(SigningErr::MessageValidation("Unable to verify origins of message"))
    ));
}
#[rocket::async_test]
#[serial]
async fn new_party_fail_wrong_data() {
    // Construct a client to use for dispatching requests.
    let client = setup_client().await;

    let response = client
        .post("/signer/new_party")
        .body(
            r##"{
		"name": "John Doe",
		"email": "j.doe@m.com",
		"password": "123456"
	}"##,
        )
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::new(500));
    clean_tests();
}

pub async fn run_to_block(api: &OnlineClient<EntropyConfig>, block_run: u32) {
    let mut current_block = 0;
    while current_block < block_run {
        current_block = api.rpc().block(None).await.unwrap().unwrap().block.header.number;
    }
}

pub async fn put_tx_request_on_chain(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: &Sr25519Keyring,
    sig_hash: Vec<u8>,
) {
    let sig_req_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keyring.pair());
    let prep_transaction_message = otherSigRequest { sig_hash };
    let registering_tx = entropy::tx().relayer().prep_transaction(prep_transaction_message);

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
