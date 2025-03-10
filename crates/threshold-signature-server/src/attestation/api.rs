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

use crate::{
    attestation::errors::{AttestationErr, QuoteMeasurementErr},
    chain_api::{entropy, get_api, get_rpc, EntropyConfig},
    helpers::{
        app_state::{BlockNumberFields, Cache},
        substrate::{query_chain, submit_transaction},
    },
    AppState, SubxtAccountId32,
};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
};
use entropy_client::user::request_attestation;
use entropy_shared::{
    attestation::{compute_quote_measurement, QuoteContext, QuoteInputData, VerifyQuoteError},
    OcwMessageAttestationRequest,
};
use parity_scale_codec::Decode;
use serde::Deserialize;
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};
use tdx_quote::Quote;
use x25519_dalek::StaticSecret;

/// HTTP POST endpoint to initiate a TDX attestation.
/// The body of the request should be a 32 byte random nonce used to show 'freshness' of the
/// quote.
///
/// The response body contains a mock TDX v4 quote serialized as described in the
/// [Index TDX DCAP Quoting Library API](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf).
pub async fn attest(
    State(app_state): State<AppState>,
    input: Bytes,
) -> Result<StatusCode, AttestationErr> {
    let attestation_requests = OcwMessageAttestationRequest::decode(&mut input.as_ref())?;

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    // We also need the current block number as input
    let block_number =
        rpc.chain_get_header(None).await?.ok_or_else(|| AttestationErr::BlockNumber)?.number;

    validate_new_attestation(block_number, &attestation_requests, &app_state.cache).await?;

    // Check whether there is an attestion request for us
    if !attestation_requests.tss_account_ids.contains(&app_state.subxt_account_id().0) {
        return Ok(StatusCode::OK);
    }

    // Get the input nonce for this attestation
    // Also acts as chain check to make sure data is on chain
    let nonce = {
        let pending_attestation_query =
            entropy::storage().attestation().pending_attestations(app_state.signer().account_id());
        query_chain(&api, &rpc, pending_attestation_query, None)
            .await?
            .ok_or_else(|| AttestationErr::Unexpected)?
    };

    // TODO (#1181): since this endpoint is currently only used in tests we don't know what the context should be
    let context = QuoteContext::Validate;

    let quote =
        create_quote(nonce, app_state.subxt_account_id(), &app_state.x25519_secret, context)
            .await?;

    // Submit the quote
    let attest_tx = entropy::tx().attestation().attest(quote.clone());
    submit_transaction(&api, &rpc, &app_state.signer(), &attest_tx, None).await?;

    Ok(StatusCode::OK)
}

/// Retrieve a quote by requesting a nonce from the chain and return the quote in the HTTP response
/// body.
///
/// This is used by node operators to get a quote for use in the `validate`, `change_endpoint`
/// and `change_tss_accounts` extrinsics.
pub async fn get_attest(
    State(app_state): State<AppState>,
    Query(context_querystring): Query<QuoteContextQuery>,
) -> Result<(StatusCode, Vec<u8>), AttestationErr> {
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    // Request attestation to get nonce
    let nonce = request_attestation(&api, &rpc, &app_state.pair).await?;

    let context = context_querystring.as_quote_context()?;

    let quote =
        create_quote(nonce, app_state.subxt_account_id(), &app_state.x25519_secret, context)
            .await?;

    Ok((StatusCode::OK, quote))
}

/// Create a mock quote for testing on non-TDX hardware
#[cfg(not(feature = "production"))]
pub async fn create_quote(
    nonce: [u8; 32],
    tss_account: SubxtAccountId32,
    x25519_secret: &StaticSecret,
    context: QuoteContext,
) -> Result<Vec<u8>, AttestationErr> {
    use rand::{rngs::StdRng, SeedableRng};
    use rand_core::OsRng;

    // In the real thing this is the key used in the quoting enclave
    let signing_key = tdx_quote::SigningKey::random(&mut OsRng);

    let public_key = x25519_dalek::PublicKey::from(x25519_secret);

    let input_data =
        QuoteInputData::new(tss_account.clone(), *public_key.as_bytes(), nonce, context);

    // This is generated deterministically from TSS account id
    let mut pck_seeder = StdRng::from_seed(tss_account.0);
    let pck = tdx_quote::SigningKey::random(&mut pck_seeder);

    let pck_encoded = tdx_quote::encode_verifying_key(pck.verifying_key())?.to_vec();
    let quote = tdx_quote::Quote::mock(signing_key.clone(), pck, input_data.0, pck_encoded)
        .as_bytes()
        .to_vec();
    Ok(quote)
}

/// Validates attest endpoint
/// Checks to make sure that attestation is not repeated or old
pub async fn validate_new_attestation(
    latest_block_number: u32,
    chain_data: &OcwMessageAttestationRequest,
    cache: &Cache,
) -> Result<(), AttestationErr> {
    let last_block_number_recorded = cache.read_from_block_numbers(&BlockNumberFields::Attest)?;
    if last_block_number_recorded >= chain_data.block_number {
        return Err(AttestationErr::RepeatedData);
    }

    // we subtract 1 as the message info is coming from the previous block
    if latest_block_number.saturating_sub(1) != chain_data.block_number {
        return Err(AttestationErr::StaleData);
    }

    cache.write_to_block_numbers(BlockNumberFields::Attest, chain_data.block_number)?;
    Ok(())
}

/// Create a TDX quote in production
#[cfg(feature = "production")]
pub async fn create_quote(
    nonce: [u8; 32],
    tss_account: SubxtAccountId32,
    x25519_secret: &StaticSecret,
    context: QuoteContext,
) -> Result<Vec<u8>, AttestationErr> {
    let public_key = x25519_dalek::PublicKey::from(x25519_secret);

    let input_data = QuoteInputData::new(tss_account, *public_key.as_bytes(), nonce, context);

    Ok(configfs_tsm::create_quote(input_data.0)
        .map_err(|e| AttestationErr::QuoteGeneration(format!("{:?}", e)))?)
}

/// Get the measurement value from this build by generating a quote.
/// This is used by the `/version` HTTP route to display measurement details of the current build.
#[cfg(feature = "production")]
pub fn get_measurement_value() -> Result<[u8; 32], AttestationErr> {
    let quote_raw = configfs_tsm::create_quote([0; 64])
        .map_err(|e| AttestationErr::QuoteGeneration(format!("{:?}", e)))?;
    let quote = Quote::from_bytes(&quote_raw)?;
    Ok(compute_quote_measurement(&quote))
}

/// Querystring for the GET `/attest` endpoint
#[derive(Deserialize)]
pub struct QuoteContextQuery {
    /// The context in which the requested quote will be used.
    ///
    /// Must be one of `validate`, `change_endpoint`, `change_threshold_accounts`.
    /// Eg: `http://127.0.0.1:3001/attest?context=validate`
    context: String,
}

impl QuoteContextQuery {
    fn as_quote_context(&self) -> Result<QuoteContext, AttestationErr> {
        match self.context.as_str() {
            "validate" => Ok(QuoteContext::Validate),
            "change_endpoint" => Ok(QuoteContext::ChangeEndpoint),
            "change_threshold_accounts" => Ok(QuoteContext::ChangeThresholdAccounts),
            _ => Err(AttestationErr::UnknownContext),
        }
    }
}

/// Check build-time measurement matches a current-supported release of entropy-tss
/// This differs slightly from the attestation pallet implementation because here we don't have direct
/// access to the parameters pallet - we need to make a query
pub async fn check_quote_measurement(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    quote: &Quote,
) -> Result<(), QuoteMeasurementErr> {
    let measurement_value = compute_quote_measurement(quote).to_vec();
    let query = entropy::storage().parameters().accepted_measurement_values();
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
