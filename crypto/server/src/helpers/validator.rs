use bip39::{Language, Mnemonic};
use kvdb::kv_manager::KvManager;
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
    let mnemonic = Mnemonic::from_phrase(secret, Language::English)
        .map_err(|e| UserErr::Mnemonic(e.to_string()))?;
    let pair = <sr25519::Pair as Pair>::from_phrase(mnemonic.phrase(), None)
        .map_err(|_| UserErr::SecretString("Secret String Error"))?;
    Ok(PairSigner::<EntropyConfig, sr25519::Pair>::new(pair.0))
}

pub async fn get_subxt_signer(kv: &KvManager) -> Result<subxt_signer::sr25519::Keypair, UserErr> {
    let _ = kv.kv().exists("MNEMONIC").await?;
    let raw_m = kv.kv().get("MNEMONIC").await?;
    let secret = core::str::from_utf8(&raw_m)?;
    let mnemonic = subxt_signer::bip39::Mnemonic::parse_in_normalized(
        subxt_signer::bip39::Language::English,
        secret,
    )
    .map_err(|e| UserErr::Mnemonic(e.to_string()))?;
    let pair = subxt_signer::sr25519::Keypair::from_phrase(&mnemonic, None)
        .map_err(|_| UserErr::SecretString("Secret String Error"))?;
    Ok(pair)
}
