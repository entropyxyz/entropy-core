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

//! HpkeMessage, but using sr25519 secret keys to generate encryption keypair

use super::{generate_key_pair, HpkeError, HpkeMessage, HpkePrivateKey, HpkePublicKey};
use blake2::{Blake2s256, Digest};
use entropy_shared::X25519PublicKey;
use serde::{Deserialize, Serialize};
use sp_core::{crypto::AccountId32, sr25519, Pair};
use zeroize::Zeroize;

/// Given a sr25519 secret signing key, derive an x25519 keypair
pub fn derive_x25519_public_key(sk: &sr25519::Pair) -> Result<X25519PublicKey, HpkeError> {
    let (_, hpke_public_key) = derive_hpke_keypair(sk)?;
    let mut x25519_public_key: [u8; 32] = [0; 32];
    x25519_public_key.copy_from_slice(hpke_public_key.as_slice());
    Ok(x25519_public_key)
}

/// Given a sr25519 secret signing key, derive an x25519 keypair
pub fn derive_hpke_keypair(
    sk: &sr25519::Pair,
) -> Result<(HpkePrivateKey, HpkePublicKey), HpkeError> {
    let mut hasher = Blake2s256::new();
    hasher.update(&sk.to_raw_vec());
    let mut hash = hasher.finalize();
    let keypair = generate_key_pair(Some(&hash))?;
    hash.zeroize();
    Ok(keypair)
}

/// Encrypted wire message
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EncryptedMessage {
    hpke_message: HpkeMessage,
    pub sender: sr25519::Public,
}

impl EncryptedMessage {
    /// New single shot message
    pub fn new(
        sender: &sr25519::Pair,
        msg: &[u8],
        recipient: X25519PublicKey,
        associated_data: &[u8],
    ) -> Result<Self, HpkeError> {
        let (sk, _pk) = derive_hpke_keypair(sender)?;
        Ok(Self {
            hpke_message: HpkeMessage::new(
                msg,
                &HpkePublicKey::new(recipient.to_vec()),
                Some(&sk),
                associated_data,
            )?,
            sender: sender.public(),
        })
    }

    /// Decrypt an incoming message
    pub fn decrypt(
        &self,
        sk: &sr25519::Pair,
        remote_public_key: X25519PublicKey,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let (sk, _pk) = derive_hpke_keypair(sk)?;
        let remote_public_key = HpkePublicKey::new(remote_public_key.to_vec());
        self.hpke_message.decrypt(&sk, Some(&remote_public_key), associated_data)
    }

    /// A new message, containing an ephemeral public key with which we want the recieve a response
    /// The ephemeral private key is returned together with the [HpkeMessage]
    pub fn new_with_receiver(
        sender: &sr25519::Pair,
        msg: &[u8],
        recipient: &X25519PublicKey,
        associated_data: &[u8],
    ) -> Result<(Self, HpkePrivateKey), HpkeError> {
        let (sk, _pk) = derive_hpke_keypair(sender)?;
        let (hpke_message, response_sk) = HpkeMessage::new_with_receiver(
            msg,
            &HpkePublicKey::new(recipient.to_vec()),
            Some(&sk),
            associated_data,
        )?;

        Ok((Self { hpke_message, sender: sender.public() }, response_sk))
    }

    /// Returns the AccountId32 of the message signer.
    pub fn account_id(&self) -> AccountId32 {
        AccountId32::new(self.sender.into())
    }
}
