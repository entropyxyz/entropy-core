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

//! Utilites relating to [crate::validator]
use bip39::{Language, Mnemonic};
use entropy_kvdb::kv_manager::KvManager;
use hkdf::Hkdf;
use sha2::Sha256;
use subxt::{
    ext::sp_core::{sr25519, Pair},
    tx::PairSigner,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{chain_api::EntropyConfig, user::UserErr};

/// Get the key derivation struct to derive secret keys from a mnemonic stored in the KVDB
async fn get_hkdf(kv: &KvManager) -> Result<Hkdf<Sha256>, UserErr> {
    let _ = kv.kv().exists("MNEMONIC").await?;
    let raw_m = kv.kv().get("MNEMONIC").await?;
    let secret = core::str::from_utf8(&raw_m)?;
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, secret)
        .map_err(|e| UserErr::Mnemonic(e.to_string()))?;

    Ok(Hkdf::<Sha256>::new(None, &mnemonic.to_seed("")))
}

/// Returns PairSigner for this nodes threshold server.
/// The PairSigner is stored as an encrypted mnemonic in the kvdb and
/// is used for PKE and to submit extrensics on chain.
pub async fn get_signer(
    kv: &KvManager,
) -> Result<PairSigner<EntropyConfig, sr25519::Pair>, UserErr> {
    let hkdf = get_hkdf(kv).await?;

    let mut sr25519_seed = [0u8; 64];
    hkdf.expand(b"sr25519-threshold-account", &mut sr25519_seed)
        .expect("Cannot get 64 byte output from sha256");
    let pair = sr25519::Pair::from_seed_slice(&sr25519_seed)?;
    sr25519_seed.zeroize();
    Ok(PairSigner::<EntropyConfig, sr25519::Pair>::new(pair))
}

/// Get the x25519 encryption keypair for this threshold server
pub async fn get_x25519_keypair(kv: &KvManager) -> Result<(StaticSecret, [u8; 32]), UserErr> {
    let hkdf = get_hkdf(kv).await?;

    let mut secret = [0u8; 32];
    hkdf.expand(b"X25519-keypair", &mut secret).expect("Cannot get 32 byte output from sha256");
    let static_secret = StaticSecret::from(secret);
    // TODO zeroize seed
    let public_key = PublicKey::from(&static_secret).to_bytes();
    Ok((static_secret, public_key))
}
