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
//
//! Encryption using Hybrid Public Key Encryption [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)
use hpke_rs::{prelude::HpkeMode, Hpke};
use hpke_rs::{HpkeError, HpkePrivateKey, HpkePublicKey};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use serde::{Deserialize, Serialize};
use sp_core::Bytes;

/// Configure Hpke
fn get_hpke() -> Hpke<HpkeRustCrypto> {
    Hpke::<HpkeRustCrypto>::new(
        HpkeMode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

/// The encrypted wire message
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HpkeMessage {
    /// The encrypted message
    pub(crate) ciphertext: Bytes,
    /// Ephemeral public key (Encapsulation of shared secret)
    encapsulation: Bytes,
}

impl HpkeMessage {
    /// New single shot message
    pub fn new(
        msg: &[u8],
        recipient: &HpkePublicKey,
        associated_data: &[u8],
    ) -> Result<Self, HpkeError> {
        let mut hpke = get_hpke();

        let (enc, ct) = hpke.seal(recipient, &[], associated_data, msg, None, None, None)?;

        Ok(Self { ciphertext: Bytes(ct), encapsulation: Bytes(enc) })
    }

    /// Decrypt an incoming message
    pub fn decrypt(
        &self,
        sk: &HpkePrivateKey,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let hpke = get_hpke();

        hpke.open(&self.encapsulation, sk, &[], associated_data, &self.ciphertext, None, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a keypair optionally giving input key material to derive from
    fn generate_key_pair(
        input_key_material: Option<&[u8]>,
    ) -> Result<(HpkePrivateKey, HpkePublicKey), HpkeError> {
        let mut hpke = get_hpke();

        let keypair = match input_key_material {
            Some(ikm) => hpke.derive_key_pair(ikm)?,
            None => hpke.generate_key_pair()?,
        };
        Ok(keypair.into_keys())
    }

    #[test]
    fn test_encrypt() {
        let plaintext = b"Its nice to be important but its more important to be nice".to_vec();

        // Alice, the sender, doesn't have a keypair
        let (bob_sk, bob_pk) = generate_key_pair(None).unwrap();

        let aad = b"Some additional context";

        let encrypted = HpkeMessage::new(&plaintext, &bob_pk, aad).unwrap();
        let decrypted_plain_text = encrypted.decrypt(&bob_sk, aad).unwrap();

        assert_eq!(decrypted_plain_text, plaintext);
        assert_ne!(encrypted.ciphertext.0, plaintext);

        let (mallory_sk, _mallory_pk) = generate_key_pair(None).unwrap();
        assert!(encrypted.decrypt(&mallory_sk, aad).is_err());
    }
}
