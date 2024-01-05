//! Wasm bindings to the [SignedMessage] API, as well as some helper functions
use super::{derive_static_secret, SignedMessage};
use js_sys::Error;
use schnorrkel::{MiniSecretKey, SecretKey};
use sp_core::{sr25519, Bytes};
use wasm_bindgen::prelude::*;
use x25519_dalek::PublicKey;

const HEX_PREFIX: [u8; 2] = [48, 120];

/// Functions for creating and using 'SignedMessage's which use chacha20poly1305
/// encryption, x25519 key agreement and sr25519 signing.
#[wasm_bindgen]
pub struct X25519Chacha20Poly1305 {}

#[wasm_bindgen]
impl X25519Chacha20Poly1305 {
    /// Generates a Ristretto Schnorr secret key.
    /// This method is used for testing, applications that implement this
    /// library should rely on user provided keys generated from substrate
    /// or polkadot-js.
    #[wasm_bindgen(js_name = generateSigningKey)]
    pub fn generate_signing_key() -> Result<Vec<u8>, Error> {
        let mini_secret_key = MiniSecretKey::generate();
        let secret_key: SecretKey = mini_secret_key.expand(MiniSecretKey::ED25519_MODE);
        let secret_key_array: [u8; 64] = secret_key.to_bytes();
        let sk =
            SecretKey::from_bytes(&secret_key_array).map_err(|err| Error::new(&err.to_string()))?;
        Ok(sk.to_bytes().to_vec())
    }

    /// Derives a public DH key from a static DH secret.
    /// secret_key must be 64 bytes in length or an error will be returned.
    #[wasm_bindgen(js_name = publicKeyFromSecret)]
    pub fn public_key_from_secret(secret_key: Vec<u8>) -> Result<Vec<u8>, Error> {
        let pair = sr25519_keypair_from_secret_key(secret_key)?;
        let x25519_secret = derive_static_secret(&pair);
        Ok(PublicKey::from(&x25519_secret).as_bytes().to_vec())
    }

    /// Encrypts, signs, and serializes a SignedMessage to JSON.
    #[wasm_bindgen(js_name = encryptAndSign)]
    pub fn encrypt_and_sign(
        sr25519_secret_key: Vec<u8>,
        message: Vec<u8>,
        recipient_public_x25519_key: Vec<u8>,
    ) -> Result<String, Error> {
        let recipient_pk = {
            if recipient_public_x25519_key.len() != 32 {
                return Err(Error::new("Recipient public encryption key must be 32 bytes"));
            }
            let mut raw_pk: [u8; 32] = [0; 32];
            raw_pk.copy_from_slice(&recipient_public_x25519_key[0..32]);
            PublicKey::from(raw_pk)
        };

        let message_bytes = Bytes(message);

        let pair = sr25519_keypair_from_secret_key(sr25519_secret_key)?;

        let signed_message = SignedMessage::new(&pair, &message_bytes, &recipient_pk)
            .map_err(|err| Error::new(&err.to_string()))?;

        Ok(signed_message.to_json().map_err(|err| Error::new(&err.to_string()))?)
    }

    /// Deserializes, verifies and decrypts a json encoded `SignedMessage`.
    /// Returns the plaintext.
    #[wasm_bindgen(js_name = decryptAndVerify)]
    pub fn decrypt_and_verify(secret_key: Vec<u8>, message: String) -> Result<Vec<u8>, Error> {
        let signed_message: SignedMessage =
            serde_json::from_str(message.as_str()).map_err(|err| Error::new(&err.to_string()))?;

        if !signed_message.verify() {
            return Err(Error::new("Failed to verify signature"));
        }

        let pair = sr25519_keypair_from_secret_key(secret_key)?;

        Ok(signed_message.decrypt(&pair).map_err(|err| Error::new(&err.to_string()))?)
    }
}

/// Convert a Vec<u8> to a hex encoded string
#[wasm_bindgen(js_name = toHex)]
pub fn to_hex(v: Vec<u8>) -> String {
    hex::encode(v)
}

/// Convert a hex string to a Vec<u8>, ignoring 0x prefix
#[wasm_bindgen(js_name = fromHex)]
pub fn from_hex(v: String) -> Result<Vec<u8>, Error> {
    let mut to_decode: String = v;
    if to_decode.len() >= 2 {
        let prefix = to_decode[0..2].as_bytes();
        if (prefix[0] == HEX_PREFIX[0]) && (prefix[1] == HEX_PREFIX[1]) {
            to_decode = to_decode[2..].to_string();
        }
    }
    Ok(hex::decode(to_decode).map_err(|err| Error::new(&err.to_string()))?)
}

/// Checks the equality of two equal sized byte vectors in constant time.
#[wasm_bindgen(js_name = constantTimeEq)]
pub fn constant_time_eq(a: Vec<u8>, b: Vec<u8>) -> bool {
    a.len() == b.len() && constant_time_ne(&a, &b) == 0
}

/// Constant time not-equal compare for two equal sized byte vectors.
/// Returns 0 if a == b, else 1.
fn constant_time_ne(a: &Vec<u8>, b: &Vec<u8>) -> u8 {
    assert!(a.len() == b.len());
    let mut tmp = 0;
    for i in 0..a.len() {
        tmp |= a[i] ^ b[i];
    }
    tmp
}

fn sr25519_keypair_from_secret_key(secret_key: Vec<u8>) -> Result<sr25519::Pair, Error> {
    if secret_key.len() != 64 {
        return Err(Error::new("Secret key must be 64 bytes"));
    }
    let secret = SecretKey::from_ed25519_bytes(secret_key.as_slice())
        .map_err(|err| Error::new(&err.to_string()))?;
    let public = secret.to_public();
    Ok(sr25519::Pair::from(schnorrkel::Keypair { secret, public }))
}
