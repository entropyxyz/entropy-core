use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Message, OCWMessage, SigRequest};
use kvdb::clean_tests;
use parity_scale_codec::Encode;
use rocket::http::{ContentType, Status};
use serial_test::serial;
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{tx::PairSigner, OnlineClient};
use testing_utils::context::test_context_stationary;

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    helpers::tests::setup_client,
    r#unsafe::api::UnsafeQuery,
    signing_client::tests::entropy::runtime_types::entropy_shared::types::SigRequest as otherSigRequest,
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
            ip_addresses: vec![b"127.0.0.1:3001".to_vec(), b"127.0.0.1:3002".to_vec()],
        }],
        block_number,
    };

    let response = client
        .post("/signer/new_party")
        .body(onchain_signature_request.clone().encode())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    // check that the signature request was stored in the kvdb
    let query_parsed_tx = client
        .post("/unsafe/get")
        .header(ContentType::JSON)
        .body(UnsafeQuery::new(hex::encode(sig_hash), String::new()).to_json())
        .dispatch()
        .await;
    assert_eq!(
        query_parsed_tx.into_string().await,
        Some(serde_json::to_string(&onchain_signature_request.messages[0]).unwrap().to_string())
    );

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
	let not_matching_sig_request = "0xe61e139a15f27f3d5ba043756aaca2b6fe9597a95973befa36dbe6095ee16da2";
    let parsed_tx =
        <Evm as Architecture>::TransactionRequest::parse(transaction_request.to_string()).unwrap();
    let sig_hash = parsed_tx.sighash();
    let block_number = api.rpc().block(None).await.unwrap().unwrap().block.header.number + 1;
    put_tx_request_on_chain(&api, &dave, sig_hash.as_bytes().to_vec()).await;

    let mut onchain_signature_request = OCWMessage {
        messages: vec![Message {
            sig_request: SigRequest { sig_hash: not_matching_sig_request.as_bytes().to_vec() },
            account: dave.to_raw_public_vec(),
            ip_addresses: vec![b"127.0.0.1:3001".to_vec(), b"127.0.0.1:3002".to_vec()],
        }],
        block_number,
    };

    let response = client
        .post("/signer/new_party")
        .body(onchain_signature_request.clone().encode())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::InternalServerError);
    assert_eq!(response.into_string().await.unwrap(), "Data is not verifiable");

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
