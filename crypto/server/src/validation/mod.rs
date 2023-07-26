use bip39::Mnemonic;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::to_string;
use subxt::ext::sp_core::{crypto::AccountId32, sr25519, sr25519::Signature, Bytes, Pair};
use utoipa::ToSchema;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;
pub mod errors;

use errors::ValidationErr;
/// Used for signing, encrypting and often sending arbitrary Bytes.
/// sr25519 is the signature scheme.
/// Use SignedMessage::new(secret_key, message) to construct
/// a new signed message.
#[derive(Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct SignedMessage {
    /// The encrypted message.
    pub msg: Bytes,
    /// The signature of the message hash.
    pub sig: Signature,
    /// The public key of the message signer.
    pk: [u8; 32],
    /// The intended recipients public key to be included in the signature.
    recip: [u8; 32],
    /// The signers public parameter used in diffie-hellman.
    a: [u8; 32],
    /// The message nonce used in ChaCha20Poly1305.
    nonce: [u8; 12],
}

impl SignedMessage {
    /// Encrypts and signs msg.
    /// sk is the sr25519 key used for signing and deriving a symmetric shared key
    /// via Diffie-Hellman for encryption.
    /// msg is the plaintext message to encrypt and sign
    /// recip is the public Diffie-Hellman parameter of the recipient.
    pub fn new(
        sk: &sr25519::Pair,
        msg: &Bytes,
        recip: &x25519_dalek::PublicKey,
    ) -> Result<SignedMessage, ValidationErr> {
        let mut s = derive_static_secret(sk);
        let a = x25519_dalek::PublicKey::from(&s);
        let shared_secret = s.diffie_hellman(recip);
        s.zeroize();
        let msg_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| ValidationErr::Conversion(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(&msg_nonce, msg.0.as_slice())
            .map_err(|e| ValidationErr::Encryption(e.to_string()))?;
        let mut static_nonce: [u8; 12] = [0; 12];
        static_nonce.copy_from_slice(&msg_nonce);

        let mut hasher = Blake2s256::new();
        hasher.update(&ciphertext);
        hasher.update(recip.as_bytes());
        let hash = hasher.finalize().to_vec();
        Ok(SignedMessage {
            pk: sk.public().0,
            a: *a.as_bytes(),
            msg: subxt::ext::sp_core::Bytes(ciphertext),
            nonce: static_nonce,
            sig: sk.sign(&hash),
            recip: recip.to_bytes(),
        })
    }

    #[cfg(test)]
    pub fn new_test(
        msg: Bytes,
        sig: Signature,
        pk: [u8; 32],
        recip: [u8; 32],
        a: [u8; 32],
        nonce: [u8; 12],
    ) -> SignedMessage {
        SignedMessage { pk, a, msg, nonce, sig, recip }
    }

    /// Decrypts the message and returns the plaintext.
    pub fn decrypt(&self, sk: &sr25519::Pair) -> Result<Vec<u8>, ValidationErr> {
        let mut static_secret = derive_static_secret(sk);
        let shared_secret = static_secret.diffie_hellman(&PublicKey::from(self.a));
        static_secret.zeroize();
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| ValidationErr::Conversion(e.to_string()))?
            .decrypt(&generic_array::GenericArray::from(self.nonce), self.msg.0.as_slice())
            .map_err(|e| ValidationErr::Decryption(e.to_string()))?;
        Ok(cipher)
    }

    /// Returns the AccountId32 of the message signer.
    pub fn account_id(&self) -> AccountId32 { AccountId32::new(self.pk) }

    /// Returns the public DH parameter of the message sender.
    pub fn sender(&self) -> x25519_dalek::PublicKey { x25519_dalek::PublicKey::from(self.a) }

    /// Verifies the signature of the hash of self.msg stored in self.sig
    /// with the public key self.pk.
    pub fn verify(&self) -> bool {
        let mut hasher = Blake2s256::new();
        hasher.update(&self.msg.0);
        hasher.update(self.recip);
        let hash = hasher.finalize().to_vec();
        <sr25519::Pair as Pair>::verify(&self.sig, hash, &sr25519::Public(self.pk))
    }

    #[cfg(test)]
    /// Returns a serialized json string of self.
    pub fn to_json(&self) -> String { to_string(self).unwrap() }
}

/// Derives a static secret from a sr25519 private key for usage in static Diffie-Hellman.
pub fn derive_static_secret(sk: &sr25519::Pair) -> x25519_dalek::StaticSecret {
    let mut buffer: [u8; 32] = [0; 32];
    let mut hasher = Blake2s256::new();
    hasher.update(sk.to_raw_vec());
    let hash = hasher.finalize().to_vec();
    buffer.copy_from_slice(&hash);
    let result = StaticSecret::from(buffer);
    buffer.zeroize();
    result
}

/// Derives a sr25519::Pair from a Mnemonic
pub fn mnemonic_to_pair(m: &Mnemonic) -> Result<sr25519::Pair, ValidationErr> {
    Ok(<sr25519::Pair as Pair>::from_phrase(m.phrase(), None)
        .map_err(|_| ValidationErr::SecretString("Secret String Error"))?
        .0)
}
#[cfg(test)]
/// Creates a new random Mnemonic.
pub fn new_mnemonic() -> Mnemonic {
    Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English)
}

#[cfg(test)]
pub fn to_bytes(b: &[u8]) -> Bytes { Bytes(b.to_vec()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_signatures_fails() {
        let plaintext = Bytes(vec![69, 42, 0]);

        let alice = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let alice_secret = derive_static_secret(&alice);
        let alice_public_key = PublicKey::from(&alice_secret);

        let bob = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let bob_secret = derive_static_secret(&bob);
        let bob_public_key = PublicKey::from(&bob_secret);

        let alice_to_alice = SignedMessage::new(&alice, &plaintext, &alice_public_key).unwrap();
        let mut alice_to_bob = SignedMessage::new(&alice, &plaintext, &bob_public_key).unwrap();

        // Test that replacing the public key fails to verify the signature.
        alice_to_bob.sig = alice_to_alice.sig;
        assert!(!alice_to_bob.verify());

        // Test that decrypting with the wrong private key throws an error.
        let res = alice_to_bob.decrypt(&alice);
        assert!(res.is_err());
    }

    #[test]
    fn test_sign_and_encrypt() {
        let plaintext = Bytes(vec![69, 42, 0]);

        let alice = mnemonic_to_pair(&new_mnemonic()).unwrap();

        let bob = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let bob_secret = derive_static_secret(&bob);
        let bob_public_key = PublicKey::from(&bob_secret);

        // Test encryption & signing.
        let encrypt_result = SignedMessage::new(&alice, &plaintext, &bob_public_key);
        // Assert no error received in encryption.
        assert!(encrypt_result.is_ok());
        let encrypted_message = encrypt_result.unwrap();

        // Test signature validity
        assert!(encrypted_message.verify());

        // Test decryption
        let decrypt_result = encrypted_message.decrypt(&bob);
        // Assert no error received in decryption.
        assert!(decrypt_result.is_ok());
        let decrypted_result = decrypt_result.unwrap();

        // Check the decrypted message equals the plaintext.
        assert_eq!(Bytes(decrypted_result), plaintext);

        // Check the encrypted message != the plaintext.
        assert_ne!(encrypted_message.msg, plaintext);
    }
}
