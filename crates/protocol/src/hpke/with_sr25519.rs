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
use sp_core::{sr25519, Pair};
use zeroize::Zeroize;

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

pub struct HpkeUsingSr25519(HpkeMessage);

impl HpkeUsingSr25519 {
    /// New single shot message, with optional sender authentication
    pub fn new(
        msg: &[u8],
        recipient: X25519PublicKey,
        private_key_authenticated_sender: Option<&sr25519::Pair>,
        associated_data: &[u8],
    ) -> Result<Self, HpkeError> {
        let private_key_authenticated_sender = match private_key_authenticated_sender {
            Some(sk) => {
                let (sk, _pk) = derive_hpke_keypair(sk)?;
                Some(sk)
            },
            None => None,
        };
        Ok(HpkeUsingSr25519(HpkeMessage::new(
            msg,
            &HpkePublicKey::new(recipient.to_vec()),
            private_key_authenticated_sender.as_ref(),
            associated_data,
        )?))
    }

    /// Decrypt an incoming message, with optional sender authentication
    pub fn decrypt(
        &self,
        sk: &sr25519::Pair,
        public_key_authenticated_sender: Option<&X25519PublicKey>,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        let (sk, _pk) = derive_hpke_keypair(sk)?;
        self.0.decrypt(
            &sk,
            public_key_authenticated_sender.map(|pk| HpkePublicKey::new(pk.to_vec())).as_ref(),
            associated_data,
        )
    }

    /// A new message, containing an ephemeral public key with which we want the recieve a response
    /// The ephemeral private key is returned together with the [HpkeMessage]
    pub fn new_with_receiver(
        msg: &[u8],
        recipient: &X25519PublicKey,
        private_key_authenticated_sender: Option<&sr25519::Pair>,
        associated_data: &[u8],
    ) -> Result<(Self, HpkePrivateKey), HpkeError> {
        let private_key_authenticated_sender = match private_key_authenticated_sender {
            Some(sk) => {
                let (sk, _pk) = derive_hpke_keypair(sk)?;
                Some(sk)
            },
            None => None,
        };
        let (inner, response_sk) = HpkeMessage::new_with_receiver(
            msg,
            &HpkePublicKey::new(recipient.to_vec()),
            private_key_authenticated_sender.as_ref(),
            associated_data,
        )?;

        Ok((HpkeUsingSr25519(inner), response_sk))
    }
}
