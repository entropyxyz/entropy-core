use hex_literal::hex;
use sp_core::{crypto::AccountId32, Pair};

use crate::signing_client::{
    new_party::signing_protocol::{create_signed_message, validate_signed_message},
    SigningErr,
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
