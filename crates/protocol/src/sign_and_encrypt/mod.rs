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

//! Encryption using Hybrid Public Key Encryption [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)
//! as well as signing with sr25519
mod hpke;
#[cfg(feature = "wasm")]
pub mod wasm;

use entropy_shared::X25519PublicKey;
use hpke::HpkeMessage;
use hpke_rs::{HpkeError, HpkePrivateKey, HpkePublicKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sp_core::{crypto::AccountId32, sr25519, Bytes, Pair};
use thiserror::Error;
use x25519_dalek::StaticSecret;

/// Encrypted wire message
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EncryptedSignedMessage {
    hpke_message: HpkeMessage,
}

/// A plaintext signed message
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignedMessage {
    pub message: Bytes,
    /// The message authors signing public key
    pub sender: sr25519::Public,
    signature: sr25519::Signature,
    /// An optional ephemeral x25519 public key to be used when sending a response to this message
    pub receiver_x25519: Option<X25519PublicKey>,
}

impl SignedMessage {
    /// Create and sign a new message. This is not public as it is expected that this
    /// will only be created internally by [EncryptedSignedMessage]
    fn new(
        message: Vec<u8>,
        secret_key: &sr25519::Pair,
        receiver_x25519: Option<X25519PublicKey>,
    ) -> Self {
        let signature = secret_key.sign(&message);
        Self { message: Bytes(message), sender: secret_key.public(), signature, receiver_x25519 }
    }

    /// Verify the signature - this is called internally when decrypting an [EncryptedSignedMessage]
    /// so there should be no reason to call it again - hence it is not public
    fn verify(&self) -> bool {
        <sr25519::Pair as Pair>::verify(&self.signature, &self.message.0, &self.sender)
    }

    /// Returns the AccountId32 of the message signer.
    pub fn account_id(&self) -> AccountId32 {
        AccountId32::new(self.sender.into())
    }
}

impl EncryptedSignedMessage {
    /// Sign and encrypt a message
    pub fn new(
        sender: &sr25519::Pair,
        message: Vec<u8>,
        recipient: &X25519PublicKey,
        associated_data: &[u8],
    ) -> Result<Self, EncryptedSignedMessageErr> {
        let signed_message = SignedMessage::new(message, sender, None);
        let serialized_signed_message = serde_json::to_vec(&signed_message).unwrap();

        Ok(Self {
            hpke_message: HpkeMessage::new(
                &serialized_signed_message,
                &HpkePublicKey::new(recipient.to_vec()),
                associated_data,
            )?,
        })
    }

    /// Decrypt an incoming message
    pub fn decrypt(
        &self,
        x25519_sk: &StaticSecret,
        associated_data: &[u8],
    ) -> Result<SignedMessage, EncryptedSignedMessageErr> {
        let hpke_sk = HpkePrivateKey::new(x25519_sk.to_bytes().to_vec());
        let plaintext = self.hpke_message.decrypt(&hpke_sk, associated_data)?;
        let signed_message: SignedMessage = serde_json::from_slice(&plaintext).unwrap();
        if !signed_message.verify() {
            return Err(EncryptedSignedMessageErr::BadSignature);
        };
        Ok(signed_message)
    }

    /// A new message, containing an ephemeral public key with which we want the recieve a response
    /// The ephemeral private key is returned together with the [HpkeMessage]
    pub fn new_with_receiver(
        sender: &sr25519::Pair,
        message: Vec<u8>,
        recipient: &X25519PublicKey,
        associated_data: &[u8],
    ) -> Result<(Self, StaticSecret), EncryptedSignedMessageErr> {
        let response_secret_key = StaticSecret::random_from_rng(OsRng);
        let response_public_key = x25519_dalek::PublicKey::from(&response_secret_key);

        let signed_message =
            SignedMessage::new(message, sender, Some(response_public_key.to_bytes()));
        let serialized_signed_message = serde_json::to_vec(&signed_message).unwrap();

        Ok((
            Self {
                hpke_message: HpkeMessage::new(
                    &serialized_signed_message,
                    &HpkePublicKey::new(recipient.to_vec()),
                    associated_data,
                )?,
            },
            response_secret_key,
        ))
    }

    /// Allows creating an EncryptedSignedMessage with a given signature.
    /// This is used in testing to ensure that giving a message with a bad signature will fail. It
    /// should not be used in production.
    #[cfg(feature = "unsafe")]
    pub fn new_with_given_signature(
        sender: &sr25519::Pair,
        message: Vec<u8>,
        recipient: &X25519PublicKey,
        associated_data: &[u8],
        signature: sr25519::Signature,
    ) -> Result<Self, EncryptedSignedMessageErr> {
        let signed_message = SignedMessage {
            message: Bytes(message),
            sender: sender.public(),
            signature,
            receiver_x25519: None,
        };
        let serialized_signed_message = serde_json::to_vec(&signed_message).unwrap();

        Ok(Self {
            hpke_message: HpkeMessage::new(
                &serialized_signed_message,
                &HpkePublicKey::new(recipient.to_vec()),
                associated_data,
            )?,
        })
    }
}

/// An error related to an [EncryptedSignedMessage]
#[derive(Debug, Error)]
pub enum EncryptedSignedMessageErr {
    #[error("Hpke: {0}")]
    Hpke(HpkeError),
    #[error("Cannot verify signature")]
    BadSignature,
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

// Needed because for some reason HpkeError doesn't have the required traits to derive this with
// thiserror
impl From<HpkeError> for EncryptedSignedMessageErr {
    fn from(hpke_error: HpkeError) -> EncryptedSignedMessageErr {
        EncryptedSignedMessageErr::Hpke(hpke_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_keyring::sr25519::Keyring;

    #[test]
    fn test_encrypt() {
        let plaintext = b"Its nice to be important but its more important to be nice".to_vec();

        let alice_sr25519 = Keyring::Alice.pair();
        let bob_x25519_sk = StaticSecret::random_from_rng(OsRng);
        let bob_x25519_pk = x25519_dalek::PublicKey::from(&bob_x25519_sk).to_bytes();

        let aad = b"Some additional context";

        let ciphertext =
            EncryptedSignedMessage::new(&alice_sr25519, plaintext.clone(), &bob_x25519_pk, aad)
                .unwrap();

        let decrypted_signed_message = ciphertext.decrypt(&bob_x25519_sk, aad).unwrap();

        assert_eq!(decrypted_signed_message.message, Bytes(plaintext.clone()));
        assert_ne!(ciphertext.hpke_message.ciphertext.0, plaintext);

        let mallory = StaticSecret::random_from_rng(OsRng);
        assert!(ciphertext.decrypt(&mallory, aad).is_err());
    }

    #[test]
    fn test_encrypt_with_receiver() {
        let plaintext = b"Its nice to be important but its more important to be nice".to_vec();

        let alice = Keyring::Alice.pair();
        let bob = Keyring::Bob.pair();

        let bob_x25519_sk = StaticSecret::random_from_rng(OsRng);
        let bob_x25519_pk = x25519_dalek::PublicKey::from(&bob_x25519_sk).to_bytes();

        let aad = b"Some additional context";

        let (ciphertext, receiver_secret_key) = EncryptedSignedMessage::new_with_receiver(
            &alice,
            plaintext.clone(),
            &bob_x25519_pk,
            aad,
        )
        .unwrap();

        let decrypted_signed_message = ciphertext.decrypt(&bob_x25519_sk, aad).unwrap();

        assert_eq!(decrypted_signed_message.message, Bytes(plaintext.clone()));
        assert_ne!(ciphertext.hpke_message.ciphertext.0, plaintext);
        let mallory = StaticSecret::random_from_rng(OsRng);
        assert!(ciphertext.decrypt(&mallory, aad).is_err());

        // Now make a response using the public key from the request
        let ciphertext_response = EncryptedSignedMessage::new(
            &bob,
            plaintext.clone(),
            &decrypted_signed_message.receiver_x25519.unwrap(),
            aad,
        )
        .unwrap();

        let decrypted_signed_message_response =
            ciphertext_response.decrypt(&receiver_secret_key, aad).unwrap();

        assert_eq!(decrypted_signed_message_response.message, Bytes(plaintext.clone()));
        assert_ne!(ciphertext_response.hpke_message.ciphertext.0, plaintext);
        let mallory = StaticSecret::random_from_rng(OsRng);
        assert!(ciphertext_response.decrypt(&mallory, aad).is_err());
    }
}
