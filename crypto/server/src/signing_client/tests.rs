use hex_literal::hex;
use sp_core::{crypto::AccountId32, Pair};
use sp_keyring::Sr25519Keyring;
use subxt::{tx::PairSigner, OnlineClient};

use crate::{
    chain_api::{entropy, EntropyConfig},
    signing_client::{
        new_party::signing_protocol::{create_signed_message, validate_signed_message},
        tests::entropy::runtime_types::entropy_shared::types::SigRequest as otherSigRequest,
        SigningErr,
    },
};

#[tokio::test]
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

    let _err =
        Box::new(SigningErr::MessageValidation("Unable to verify sender of message".to_string()));
    assert!(matches!(failed_in_threshold_group, Err(_err)));

    let failed_message_decrypt = validate_signed_message(
        &bad_message.to_vec(),
        signed_message,
        pair.public(),
        &vec![AccountId32::new(pair.public().0)],
    );

    let _err_2 =
        Box::new(SigningErr::MessageValidation("Unable to verify origins of message".to_string()));
    assert!(matches!(failed_message_decrypt, Err(_err_2)));
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
