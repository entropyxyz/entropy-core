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
use hpke_rs::{prelude::HpkeMode, Hpke};
pub use hpke_rs::{HpkeError, HpkePrivateKey, HpkePublicKey};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use serde::{Deserialize, Serialize};
use sp_core::Bytes;

pub mod with_sr25519;

/// Configure Hpke
fn get_hpke(hpke_mode: HpkeMode) -> Hpke<HpkeRustCrypto> {
    Hpke::<HpkeRustCrypto>::new(
        hpke_mode,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

/// Generate a keypair optionally giving input key material to derive from
pub fn generate_key_pair(
    input_key_material: Option<&[u8]>,
) -> Result<(HpkePrivateKey, HpkePublicKey), HpkeError> {
    let mut hpke = get_hpke(HpkeMode::Base);

    let keypair = match input_key_material {
        Some(ikm) => hpke.derive_key_pair(ikm)?,
        None => hpke.generate_key_pair()?,
    };
    Ok(keypair.into_keys())
}

/// The encrypted wire message
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HpkeMessage {
    /// The encrypted message
    pub ct: Bytes,
    /// Ephemeral public key (Encapsulation of shared secret)
    pub enc: Bytes,
    /// An optional Ephemeral public key for receiving a response
    pub receiver: Option<[u8; 32]>,
}

impl HpkeMessage {
    /// New single shot message, with optional sender authentication
    pub fn new(
        msg: &[u8],
        recipient: &HpkePublicKey,
        private_key_authenticated_sender: Option<&HpkePrivateKey>,
        associated_data: &[u8],
    ) -> Result<Self, HpkeError> {
        let mut hpke = get_hpke(if private_key_authenticated_sender.is_some() {
            HpkeMode::Auth
        } else {
            HpkeMode::Base
        });

        let (enc, ct) = hpke.seal(
            recipient,
            &[],
            associated_data,
            msg,
            None,
            None,
            private_key_authenticated_sender,
        )?;

        Ok(Self { ct: Bytes(ct), enc: Bytes(enc), receiver: None })
    }

    /// Decrypt an incoming message, with optional sender authentication
    pub fn decrypt(
        &self,
        sk: &HpkePrivateKey,
        public_key_authenticated_sender: Option<&HpkePublicKey>,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let hpke = get_hpke(if public_key_authenticated_sender.is_some() {
            HpkeMode::Auth
        } else {
            HpkeMode::Base
        });

        let info = match &self.receiver {
            Some(public_key) => public_key.as_ref(),
            None => &[],
        };

        hpke.open(
            &self.enc,
            sk,
            info,
            associated_data,
            &self.ct,
            None,
            None,
            public_key_authenticated_sender,
        )
    }

    /// A new message, containing an ephemeral public key with which we want the recieve a response
    /// The ephemeral private key is returned together with the [HpkeMessage]
    pub fn new_with_receiver(
        msg: &[u8],
        recipient: &HpkePublicKey,
        private_key_authenticated_sender: Option<&HpkePrivateKey>,
        associated_data: &[u8],
    ) -> Result<(Self, HpkePrivateKey), HpkeError> {
        let (response_private_key, response_public_key) = generate_key_pair(None)?;
        let info = response_public_key.as_slice();

        let mut hpke = get_hpke(if private_key_authenticated_sender.is_some() {
            HpkeMode::Auth
        } else {
            HpkeMode::Base
        });

        let (enc, ct) = hpke.seal(
            recipient,
            info,
            associated_data,
            msg,
            None,
            None,
            private_key_authenticated_sender,
        )?;

        Ok((
            Self {
                ct: Bytes(ct),
                enc: Bytes(enc),
                receiver: Some(response_public_key.as_slice().try_into().unwrap()),
            },
            response_private_key,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt() {
        let plaintext = b"Its nice to be important but its more important to be nice".to_vec();

        // Alice, the sender, doesn't have a keypair
        let (bob_sk, bob_pk) = generate_key_pair(None).unwrap();

        let aad = b"Some additional context";

        let ciphertext = HpkeMessage::new(&plaintext, &bob_pk, None, aad).unwrap();
        let decrypted_plain_text = ciphertext.decrypt(&bob_sk, None, aad).unwrap();

        assert_eq!(decrypted_plain_text, plaintext);
        assert_ne!(ciphertext.ct.0, plaintext);

        let (mallory_sk, _mallory_pk) = generate_key_pair(None).unwrap();
        assert!(ciphertext.decrypt(&mallory_sk, None, aad).is_err());
    }

    #[test]
    fn test_encrypt_with_authenticated_sender() {
        let plaintext = b"Its nice to be important but its more important to be nice".to_vec();

        let (alice_sk, alice_pk) = generate_key_pair(None).unwrap();
        let (bob_sk, bob_pk) = generate_key_pair(None).unwrap();

        let aad = b"Some additional context";

        let ciphertext = HpkeMessage::new(&plaintext, &bob_pk, Some(&alice_sk), aad).unwrap();
        let decrypted_plain_text = ciphertext.decrypt(&bob_sk, Some(&alice_pk), aad).unwrap();

        assert_eq!(decrypted_plain_text, plaintext);
        assert_ne!(ciphertext.ct.0, plaintext);

        let (mallory_sk, _mallory_pk) = generate_key_pair(None).unwrap();
        assert!(ciphertext.decrypt(&mallory_sk, Some(&alice_pk), aad).is_err());
    }

    #[test]
    fn test_encrypt_with_response() {
        let plaintext_request = b"Please make me a signature".to_vec();
        let plaintext_response = b"Here is your signature".to_vec();

        let (bob_sk, bob_pk) = generate_key_pair(None).unwrap();

        let aad = b"Some additional context";

        let (ciphertext_request, response_secret_key) =
            HpkeMessage::new_with_receiver(&plaintext_request, &bob_pk, None, aad).unwrap();

        let decrypted_request = ciphertext_request.decrypt(&bob_sk, None, aad).unwrap();

        assert_eq!(decrypted_request, plaintext_request);
        assert_ne!(ciphertext_request.ct.0, plaintext_request);

        let ciphertext_response = HpkeMessage::new(
            &plaintext_response,
            &HpkePublicKey::new(ciphertext_request.receiver.unwrap().try_into().unwrap()),
            None,
            aad,
        )
        .unwrap();

        let decrypted_response =
            ciphertext_response.decrypt(&response_secret_key, None, aad).unwrap();

        assert_eq!(decrypted_response, plaintext_response);
        assert_ne!(ciphertext_response.ct.0, plaintext_response);
    }

    #[test]
    fn test_encrypt_with_response_and_authenticated_sender() {
        let plaintext_request = b"Please make me a signature".to_vec();
        let plaintext_response = b"Here is your signature".to_vec();

        let (alice_sk, alice_pk) = generate_key_pair(None).unwrap();
        let (bob_sk, bob_pk) = generate_key_pair(None).unwrap();

        let aad = b"Some additional context";

        let (ciphertext_request, response_secret_key) =
            HpkeMessage::new_with_receiver(&plaintext_request, &bob_pk, Some(&alice_sk), aad)
                .unwrap();

        let decrypted_request = ciphertext_request.decrypt(&bob_sk, Some(&alice_pk), aad).unwrap();

        assert_eq!(decrypted_request, plaintext_request);
        assert_ne!(ciphertext_request.ct.0, plaintext_request);

        let ciphertext_response = HpkeMessage::new(
            &plaintext_response,
            &HpkePublicKey::new(ciphertext_request.receiver.unwrap().try_into().unwrap()),
            None,
            aad,
        )
        .unwrap();

        let decrypted_response =
            ciphertext_response.decrypt(&response_secret_key, None, aad).unwrap();

        assert_eq!(decrypted_response, plaintext_response);
        assert_ne!(ciphertext_response.ct.0, plaintext_response);
    }
}
