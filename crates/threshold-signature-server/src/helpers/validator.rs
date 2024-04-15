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
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::{chain_api::EntropyConfig, user::UserErr};

/// Constants used in the derivation path
const KDF_SR25519: &[u8] = b"sr25519-threshold-account";
const KDF_X25519: &[u8] = b"X25519-keypair";

/// Returns a PairSigner for this node's threshold server.
/// The PairSigner is stored as an encrypted mnemonic in the kvdb and
/// is used to sign encrypted messages and to submit extrinsics on chain.
pub async fn get_signer(
    kv: &KvManager,
) -> Result<PairSigner<EntropyConfig, sr25519::Pair>, UserErr> {
    let hkdf = get_hkdf(kv).await?;
    get_signer_from_hkdf(&hkdf)
}

/// Get the PairSigner as above, and also the x25519 encryption keypair for
/// this threshold server
pub async fn get_signer_and_x25519_secret(
    kv: &KvManager,
) -> Result<(PairSigner<EntropyConfig, sr25519::Pair>, StaticSecret), UserErr> {
    let hkdf = get_hkdf(kv).await?;
    let pair_signer = get_signer_from_hkdf(&hkdf)?;
    let static_secret = get_x25519_secret_from_hkdf(&hkdf)?;
    Ok((pair_signer, static_secret))
}

/// Get the key derivation struct to derive secret keys from a mnemonic stored in the KVDB
async fn get_hkdf(kv: &KvManager) -> Result<Hkdf<Sha256>, UserErr> {
    let _ = kv.kv().exists("MNEMONIC").await?;
    let raw_m = kv.kv().get("MNEMONIC").await?;
    let secret = core::str::from_utf8(&raw_m)?;
    get_hkdf_from_mnemonic(secret)
}

/// Given a mnemonic, setup hkdf
fn get_hkdf_from_mnemonic(mnemonic: &str) -> Result<Hkdf<Sha256>, UserErr> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| UserErr::Mnemonic(e.to_string()))?;
    Ok(Hkdf::<Sha256>::new(None, &mnemonic.to_seed("")))
}

/// Derive signing keypair
fn get_signer_from_hkdf(
    hkdf: &Hkdf<Sha256>,
) -> Result<PairSigner<EntropyConfig, sr25519::Pair>, UserErr> {
    let mut sr25519_seed = [0u8; 32];
    hkdf.expand(KDF_SR25519, &mut sr25519_seed)?;
    let pair = sr25519::Pair::from_seed(&sr25519_seed);
    sr25519_seed.zeroize();

    Ok(PairSigner::<EntropyConfig, sr25519::Pair>::new(pair))
}

/// Derive x25519 secret
fn get_x25519_secret_from_hkdf(hkdf: &Hkdf<Sha256>) -> Result<StaticSecret, UserErr> {
    let mut secret = [0u8; 32];
    hkdf.expand(KDF_X25519, &mut secret)?;
    let static_secret = StaticSecret::from(secret);
    secret.zeroize();
    Ok(static_secret)
}

/// For testing where we sometimes don't have access to the kvdb, derive directly from the mnemnic
#[cfg(test)]
pub fn get_signer_and_x25519_secret_from_mnemonic(
    mnemonic: &str,
) -> Result<(PairSigner<EntropyConfig, sr25519::Pair>, StaticSecret), UserErr> {
    let hkdf = get_hkdf_from_mnemonic(mnemonic)?;
    let pair_signer = get_signer_from_hkdf(&hkdf)?;
    let static_secret = get_x25519_secret_from_hkdf(&hkdf)?;
    Ok((pair_signer, static_secret))
}
