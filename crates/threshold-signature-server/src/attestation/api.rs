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
    helpers::substrate::query_chain,
    AppState, SubxtAccountId32,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use entropy_client::user::request_attestation;
use entropy_shared::{
    attestation::{compute_quote_measurement, QuoteContext, QuoteInputData, VerifyQuoteError},
    BoundedVecEncodedVerifyingKey,
};
use serde::Deserialize;
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};
use tdx_quote::Quote;
use x25519_dalek::StaticSecret;

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

/// Get our Provisioning Certification Key (PCK)
/// This generates a quote and gets the public key from it
#[cfg(feature = "production")]
pub fn get_pck(
    _tss_account: SubxtAccountId32,
) -> Result<BoundedVecEncodedVerifyingKey, AttestationErr> {
    let quote_raw = configfs_tsm::create_quote([0; 64])
        .map_err(|e| AttestationErr::QuoteGeneration(format!("{:?}", e)))?;
    let quote = Quote::from_bytes(&quote_raw).unwrap();
    let pck = quote.verify().map_err(|e| {
        AttestationErr::QuoteGeneration(format!("Could not get PCK from quote {:?}", e))
    })?;

    let pck =
        BoundedVecEncodedVerifyingKey::try_from(tdx_quote::encode_verifying_key(&pck)?.to_vec())
            .map_err(|_| AttestationErr::BadVerifyingKeyLength)?;
    Ok(pck)
}

/// Get our Provisioning Certification Key (PCK)
/// In mock mode, this is derived from the TSS account ID
#[cfg(not(feature = "production"))]
pub fn get_pck(
    tss_account: SubxtAccountId32,
) -> Result<BoundedVecEncodedVerifyingKey, AttestationErr> {
    use rand::{rngs::StdRng, SeedableRng};

    // This is generated deterministically from TSS account id
    let mut pck_seeder = StdRng::from_seed(tss_account.0);
    let pck = tdx_quote::SigningKey::random(&mut pck_seeder);

    let pck = BoundedVecEncodedVerifyingKey::try_from(
        tdx_quote::encode_verifying_key(pck.verifying_key())?.to_vec(),
    )
    .map_err(|_| AttestationErr::BadVerifyingKeyLength)?;
    Ok(pck)
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
