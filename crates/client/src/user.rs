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
//! User interaction related
use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_parameters::SupportedCvmServices},
        EntropyConfig,
    },
    errors::QuoteMeasurementErr,
    substrate::{query_chain, submit_transaction_with_pair},
};
use entropy_shared::{
    attestation::{compute_quote_measurement, VerifyQuoteError},
    user::ValidatorInfo,
    BlockNumber, HashingAlgorithm,
};
use serde::{Deserialize, Serialize};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};
use tdx_quote::Quote;

pub use crate::errors::{AttestationRequestError, SubgroupGetError};

/// Represents an unparsed, transaction request coming from the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserSignatureRequest {
    /// Hex-encoded raw data to be signed (eg. hex-encoded RLP-serialized Ethereum transaction)
    pub message: String,
    /// Hex-encoded auxilary data for program evaluation, will not be signed (eg. zero-knowledge proof, serialized struct, etc)
    pub auxilary_data: Option<Vec<Option<String>>>,
    /// When the message was created and signed
    pub block_number: BlockNumber,
    /// Hashing algorithm to be used for signing
    pub hash: HashingAlgorithm,
    /// The verifying key for the signature requested
    pub signature_verifying_key: Vec<u8>,
}

/// Represents an unparsed transaction request coming from a relayer to a signer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayerSignatureRequest {
    // Request relayed from user to signer
    pub user_signature_request: UserSignatureRequest,
    /// Information for the validators in the signing party
    pub validators_info: Vec<ValidatorInfo>,
}

/// Gets a validator from chain to relay a message to the signers
/// Filters out all signers
pub async fn get_validators_not_signer_for_relay(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<ValidatorInfo>, SubgroupGetError> {
    let signer_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(api, rpc, signer_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Get all validators error"))?;

    let validators_query = entropy::storage().session().validators();
    let mut validators = query_chain(api, rpc, validators_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Error getting validators"))?;

    validators.retain(|validator| !signers.contains(validator));
    let block_hash = rpc.chain_get_block_hash(None).await?;
    let mut handles = Vec::new();

    for validator in validators {
        let handle: tokio::task::JoinHandle<Result<ValidatorInfo, SubgroupGetError>> =
            tokio::task::spawn({
                let api = api.clone();
                let rpc = rpc.clone();
                async move {
                    let threshold_address_query =
                        entropy::storage().staking_extension().threshold_servers(validator);
                    let server_info = query_chain(&api, &rpc, threshold_address_query, block_hash)
                        .await?
                        .ok_or_else(|| {
                            SubgroupGetError::ChainFetch("threshold_servers query error")
                        })?;

                    Ok(ValidatorInfo {
                        x25519_public_key: server_info.x25519_public_key,
                        ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
                        tss_account: server_info.tss_account,
                    })
                }
            });

        handles.push(handle);
    }

    let mut all_validators: Vec<ValidatorInfo> = vec![];
    for handle in handles {
        all_validators.push(handle.await??);
    }

    Ok(all_validators)
}

/// Gets all signers from chain
pub async fn get_all_signers_from_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<ValidatorInfo>, SubgroupGetError> {
    let signer_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(api, rpc, signer_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Get all validators error"))?;

    let block_hash = rpc.chain_get_block_hash(None).await?;
    let mut handles = Vec::new();

    for signer in signers {
        let handle: tokio::task::JoinHandle<Result<ValidatorInfo, SubgroupGetError>> =
            tokio::task::spawn({
                let api = api.clone();
                let rpc = rpc.clone();
                async move {
                    let threshold_address_query =
                        entropy::storage().staking_extension().threshold_servers(signer);
                    let server_info = query_chain(&api, &rpc, threshold_address_query, block_hash)
                        .await?
                        .ok_or_else(|| {
                            SubgroupGetError::ChainFetch("threshold_servers query error")
                        })?;
                    Ok(ValidatorInfo {
                        x25519_public_key: server_info.x25519_public_key,
                        ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
                        tss_account: server_info.tss_account,
                    })
                }
            });

        handles.push(handle);
    }

    let mut all_signers: Vec<ValidatorInfo> = vec![];
    for handle in handles {
        all_signers.push(handle.await??);
    }

    Ok(all_signers)
}

/// An extrinsic to indicate to the chain that it should expect an attestation from the `signer` at
/// some point in the near future.
///
/// The returned `nonce` must be used when generating a `quote` for the chain.
#[tracing::instrument(
    skip_all,
    fields(
        attestee = ?attestee.public(),
    )
)]
pub async fn request_attestation(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    attestee: &sr25519::Pair,
) -> Result<[u8; 32], AttestationRequestError> {
    tracing::debug!("{:?} is requesting an attestation.", attestee.public().to_ss58check());

    let request_attestation = entropy::tx().attestation().request_attestation();

    let result =
        submit_transaction_with_pair(api, rpc, attestee, &request_attestation, None).await?;
    let result_event = result
        .find_first::<entropy::attestation::events::AttestationIssued>()?
        .ok_or(crate::errors::SubstrateError::NoEvent)?;

    let nonce = result_event.0.try_into().map_err(|_| AttestationRequestError::BadNonce)?;

    Ok(nonce)
}

/// Check build-time measurement matches a current-supported release of entropy-tss
/// This differs slightly from the attestation pallet implementation because here we don't have direct
/// access to the parameters pallet - we need to make a query
pub async fn check_quote_measurement(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    quote: &Quote,
    cvm_service_type: SupportedCvmServices,
) -> Result<(), QuoteMeasurementErr> {
    let measurement_value = compute_quote_measurement(quote).to_vec();
    let query = entropy::storage().parameters().accepted_measurement_values(cvm_service_type);

    let accepted_measurement_values: Vec<_> = query_chain(api, rpc, query, None)
        .await?
        .ok_or(QuoteMeasurementErr::NoMeasurementValues)?
        .into_iter()
        .map(|v| v.0)
        .collect();
    if !accepted_measurement_values.contains(&measurement_value) {
        return Err(VerifyQuoteError::BadMeasurementValue.into());
    };
    Ok(())
}
