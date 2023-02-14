use bip39::{Language, Mnemonic};
use entropy_shared::SIGNING_PARTY_SIZE;
use kvdb::kv_manager::KvManager;
use subxt::{
    ext::sp_core::{sr25519, Pair},
    tx::PairSigner,
    OnlineClient,
};

use crate::{
    chain_api::{entropy, EntropyConfig},
    user::UserErr,
};

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

/// gets the subgroup of the working validator
pub async fn get_subgroup(
    api: &OnlineClient<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<Option<u8>, UserErr> {
    let mut subgroup: Option<u8> = None;
    let threshold_address = signer.account_id();
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(threshold_address);
    let stash_address = api
        .storage()
        .fetch(&stash_address_query, None)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Stash Fetch Error"))?;
    for i in 0..SIGNING_PARTY_SIZE {
        let signing_group_addresses_query =
            entropy::storage().staking_extension().signing_groups(i as u8);
        let signing_group_addresses = api
            .storage()
            .fetch(&signing_group_addresses_query, None)
            .await?
            .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
        if signing_group_addresses.contains(&stash_address) {
            subgroup = Some(i as u8);
            break;
        }
    }
    Ok(subgroup)
}
