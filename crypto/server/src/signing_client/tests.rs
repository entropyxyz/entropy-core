use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Message, SigRequest};
use kvdb::clean_tests;
use parity_scale_codec::Encode;
use rocket::http::{ContentType, Status};
use serial_test::serial;
use sp_keyring::AccountKeyring;

use crate::{
    helpers::tests::setup_client,
    r#unsafe::api::UnsafeQuery,
};

#[rocket::async_test]
#[serial]
async fn test_new_party() {
    if cfg!(feature = "unsafe") {
        clean_tests();
        let client = setup_client().await;

        // transaction_request comes from ethers-js serializeTransaction()
        // See frontend threshold-server tests for more context
        let transaction_request = r#"0xef01808094772b9a9e8aa1c9db861c6611a82d251db4fac990019243726561746564204f6e20456e74726f7079018080"#;
        let parsed_tx =
            <Evm as Architecture>::TransactionRequest::parse(transaction_request.to_string())
                .unwrap();
        let sig_hash = parsed_tx.sighash();

        let onchain_signature_request = Message {
            sig_request: SigRequest { sig_hash: sig_hash.as_bytes().to_vec() },
            account: AccountKeyring::Alice.to_raw_public_vec(),
            ip_addresses: vec![b"127.0.0.1:3001".to_vec(), b"127.0.0.1:3002".to_vec()],
        };

        // mock ocw posting to /signer/new_party
        let response = client
            .post("/signer/new_party")
            .body(vec![onchain_signature_request.clone()].encode())
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
            Some(serde_json::to_string(&onchain_signature_request).unwrap().to_string())
        );

        clean_tests();
    }
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
