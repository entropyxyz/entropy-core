use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Message, OCWMessage, RefreshMessages, RefreshMessage};
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
};

#[rocket::async_test]
#[serial]
async fn test_new_refresh() {
    clean_tests();
    let client = setup_client().await;
	let mock_refresh_message_alice = RefreshMessage {
		validator_ip: b"127.0.0.1:3001".to_vec(),
		validator_account: b"5H8qc7f4mXFY16NBWSB9qkc6pTks98HdVuoQTs1aova5fRtN".to_vec()
	};
	let mock_refresh_message_bob = RefreshMessage {
		validator_ip: b"127.0.0.1:3002".to_vec(),
		validator_account: b"5D2SVCUkK5FgFiBwPTJuTN65J6fACSEoZrL41thZBAycwnQV".to_vec()
	};
	let mock_refresh_messages: RefreshMessages = vec![mock_refresh_message_alice, mock_refresh_message_bob];

	let response = client
        .post("/refresh/proactive_refresh")
        .body(mock_refresh_messages.clone().encode())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}
