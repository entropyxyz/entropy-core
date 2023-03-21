use entropy_constraints::{Architecture, Evm, Parse};
use entropy_shared::{Message, OCWMessage, RefreshMessages, RefreshMessage};
use bip39::{Language, Mnemonic};
use kvdb::clean_tests;
use parity_scale_codec::Encode;
use rocket::http::{ContentType, Status};
use serial_test::serial;
use sp_keyring::{AccountKeyring, Sr25519Keyring};
use subxt::{tx::PairSigner, OnlineClient};
use testing_utils::context::test_context_stationary;
use sp_core::{crypto::AccountId32, Pair};

use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    helpers::{tests::setup_client, launch::{DEFAULT_MNEMONIC, DEFAULT_BOB_MNEMONIC}},
    r#unsafe::api::UnsafeQuery,
	message::mnemonic_to_pair,
};

#[rocket::async_test]
#[serial]
async fn test_new_refresh() {
    clean_tests();
    let client = setup_client().await;
	let alice_pair = mnemonic_to_pair(&Mnemonic::from_phrase(DEFAULT_MNEMONIC, Language::English).unwrap());
	let alice_address = AccountId32::new(alice_pair.public().0);
	let bob_pair = mnemonic_to_pair(&Mnemonic::from_phrase(DEFAULT_BOB_MNEMONIC, Language::English).unwrap());
	let bob_address = AccountId32::new(bob_pair.public().0);

	let mock_refresh_message_alice = RefreshMessage {
		validator_ip: b"127.0.0.1:3001".encode(),
		validator_account: alice_address.encode()
	};
	let mock_refresh_message_bob = RefreshMessage {
		validator_ip: b"127.0.0.1:3002".encode(),
		validator_account: bob_address.encode()
	};
	let mock_refresh_messages: RefreshMessages = vec![mock_refresh_message_alice, mock_refresh_message_bob];

	let response = client
        .post("/refresh/proactive_refresh")
        .body(mock_refresh_messages.clone().encode())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}
