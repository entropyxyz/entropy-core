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
use subxt::{
    ext::sp_core::{sr25519, Pair},
    tx::PairSigner,
};

use crate::{chain_api::EntropyConfig, user::UserErr};

/// Returns PairSigner for this nodes threshold server.
/// The PairSigner is stored as an encrypted mnemonic in the kvdb and
/// is used for PKE and to submit extrensics on chain.
pub async fn get_signer(
    kv: &KvManager,
) -> Result<PairSigner<EntropyConfig, sr25519::Pair>, UserErr> {
    let _ = kv.kv().exists("MNEMONIC").await?;
    let raw_m = kv.kv().get("MNEMONIC").await?;
    let secret = core::str::from_utf8(&raw_m)?;
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, secret)
        .map_err(|e| UserErr::Mnemonic(e.to_string()))?;
    let pair = <sr25519::Pair as Pair>::from_phrase(&mnemonic.to_string(), None)
        .map_err(|_| UserErr::SecretString("Secret String Error"))?;
    Ok(PairSigner::<EntropyConfig, sr25519::Pair>::new(pair.0))
}
