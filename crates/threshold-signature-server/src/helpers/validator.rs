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
use hkdf::Hkdf;
use sha2::Sha256;
use subxt::ext::sp_core::{sr25519, Pair};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::user::UserErr;

/// Constants used in the derivation path
const KDF_SR25519: &[u8] = b"sr25519-threshold-account";
const KDF_X25519: &[u8] = b"X25519-keypair";

/// Get the PairSigner as above, and also the x25519 encryption keypair for
/// this threshold server
pub fn get_signer_and_x25519_secret(
    mnemonic: &str,
) -> Result<(sr25519::Pair, StaticSecret), UserErr> {
    let hkdf = get_hkdf_from_mnemonic(mnemonic)?;
    let pair_signer = get_signer_from_hkdf(&hkdf)?;
    let static_secret = get_x25519_secret_from_hkdf(&hkdf)?;
    Ok((pair_signer, static_secret))
}

/// Given a mnemonic, setup hkdf
fn get_hkdf_from_mnemonic(mnemonic: &str) -> Result<Hkdf<Sha256>, UserErr> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| UserErr::Mnemonic(e.to_string()))?;
    Ok(Hkdf::<Sha256>::new(None, &mnemonic.to_seed("")))
}

/// Derive signing keypair
pub fn get_signer_from_hkdf(hkdf: &Hkdf<Sha256>) -> Result<sr25519::Pair, UserErr> {
    let mut sr25519_seed = [0u8; 32];
    hkdf.expand(KDF_SR25519, &mut sr25519_seed)?;
    let pair = sr25519::Pair::from_seed(&sr25519_seed);
    sr25519_seed.zeroize();

    Ok(pair)
}

/// Derive x25519 secret
fn get_x25519_secret_from_hkdf(hkdf: &Hkdf<Sha256>) -> Result<StaticSecret, UserErr> {
    let mut secret = [0u8; 32];
    hkdf.expand(KDF_X25519, &mut secret)?;
    let static_secret = StaticSecret::from(secret);
    secret.zeroize();
    Ok(static_secret)
}

/// For testing where we sometimes don't have access to the kvdb, derive directly from the mnemonic
#[cfg(any(test, feature = "test_helpers"))]
pub fn get_signer_and_x25519_secret_from_mnemonic(
    mnemonic: &str,
) -> Result<(subxt::tx::PairSigner<crate::EntropyConfig, sr25519::Pair>, StaticSecret), UserErr> {
    let hkdf = get_hkdf_from_mnemonic(mnemonic)?;
    let pair = get_signer_from_hkdf(&hkdf)?;
    let pair_signer = subxt::tx::PairSigner::new(pair);
    let static_secret = get_x25519_secret_from_hkdf(&hkdf)?;
    Ok((pair_signer, static_secret))
}
