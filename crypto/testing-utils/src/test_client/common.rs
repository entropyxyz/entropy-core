// Things in this module are copied from `server` and should really live in a crate which is a
// dependency of both server and this crate.
use std::{sync::Arc, time::SystemTime};

use anyhow::anyhow;
use blake2::{Blake2s256, Digest};
use entropy_protocol::ValidatorInfo;
use entropy_shared::SIGNING_PARTY_SIZE;
use futures::future::join_all;
use num::{bigint::BigInt, Num, ToPrimitive};
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use subxt::OnlineClient;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::chain_api::{entropy, EntropyConfig};

/// Produces a specific hash on a given message
pub struct Hasher;

impl Hasher {
    /// Produces the Keccak256 hash on a given message.
    ///
    /// In practice, if `data` is an RLP-serialized Ethereum transaction, this should produce the
    /// corrosponding .
    pub fn keccak(data: &[u8]) -> [u8; 32] {
        use sha3::Keccak256;

        let mut keccak = Keccak256::new();
        keccak.update(data);
        keccak.finalize().into()
    }
}

// TODO we cannot use derive_static_secret from x25519_chacha20poly1305 because that is based on
// sp-core 6.0.0 - so we repeat it here
/// Given a sr25519 secret signing key, generate an x25519 secret encryption key
pub fn derive_static_secret(sk: &sr25519::Pair) -> StaticSecret {
    let mut buffer: [u8; 32] = [0; 32];
    let mut hasher = Blake2s256::new();
    hasher.update(&sk.to_raw_vec());
    let hash = hasher.finalize().to_vec();
    buffer.copy_from_slice(&hash);
    let result = StaticSecret::from(buffer);
    buffer.zeroize();
    result
}

/// A request to sign a message
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UserTransactionRequest {
    /// Hex-encoded raw data to be signed (eg. RLP-serialized Ethereum transaction)
    pub transaction_request: String,
    /// Information from the validators in signing party
    pub validators_info: Vec<ValidatorInfo>,
    /// When the message was created and signed
    pub timestamp: SystemTime,
}

/// Gets the current signing committee
/// The signing committee is composed as the validators at the index into each subgroup
/// Where the index is computed as the user's sighash as an integer modulo the number of subgroups
pub async fn get_current_subgroup_signers(
    api: &OnlineClient<EntropyConfig>,
    sig_hash: &str,
) -> anyhow::Result<Vec<ValidatorInfo>> {
    let mut subgroup_signers = vec![];
    let number = Arc::new(BigInt::from_str_radix(sig_hash, 16)?);
    let futures = (0..SIGNING_PARTY_SIZE)
        .map(|i| {
            let owned_number = Arc::clone(&number);
            async move {
                let subgroup_info_query =
                    entropy::storage().staking_extension().signing_groups(i as u8);
                let subgroup_info = api
                    .storage()
                    .at_latest()
                    .await?
                    .fetch(&subgroup_info_query)
                    .await?
                    .ok_or(anyhow!("Subgroup Fetch Error"))?;

                let index_of_signer_big = &*owned_number % subgroup_info.len();
                let index_of_signer =
                    index_of_signer_big.to_usize().ok_or(anyhow!("Usize error"))?;

                let threshold_address_query = entropy::storage()
                    .staking_extension()
                    .threshold_servers(subgroup_info[index_of_signer].clone());
                let server_info = api
                    .storage()
                    .at_latest()
                    .await?
                    .fetch(&threshold_address_query)
                    .await?
                    .ok_or(anyhow!("Stash Fetch Error"))?;
                let validator_info = ValidatorInfo {
                    x25519_public_key: server_info.x25519_public_key,
                    ip_address: std::str::from_utf8(&server_info.endpoint)?.parse()?,
                    tss_account: server_info.tss_account,
                };
                Ok::<_, anyhow::Error>(validator_info)
            }
        })
        .collect::<Vec<_>>();
    let results = join_all(futures).await;
    for result in results.into_iter() {
        subgroup_signers.push(result?);
    }
    Ok(subgroup_signers)
}
