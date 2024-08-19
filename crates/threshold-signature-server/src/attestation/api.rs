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
    attestation::errors::AttestationErr,
    chain_api::{entropy, get_api, get_rpc, EntropyConfig},
    get_signer_and_x25519_secret,
    helpers::substrate::{query_chain, submit_transaction},
    AppState,
};
use axum::{body::Bytes, extract::State, http::StatusCode};
use entropy_shared::OcwMessageAttestationRequest;
use subxt::tx::PairSigner;
use x25519_dalek::StaticSecret;

/// HTTP POST endpoint to initiate a TDX attestation.
/// The body of the request should be a 32 byte random nonce used to show 'freshness' of the
/// quote.
/// The response body contains a mock TDX v4 quote serialized as described in the
/// [Index TDX DCAP Quoting Library API](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf).
pub async fn attest(
    State(app_state): State<AppState>,
    input: Bytes,
) -> Result<StatusCode, AttestationErr> {
    let attestaion_requests = OcwMessageAttestationRequest::decode(&mut input.as_ref())?;
    // TODO check that attestation_requests.tss_account_ids contains our account_id
    // which is signer.signer().public().0

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    let (signer, x25519_secret) = get_signer_and_x25519_secret(&app_state.kv_store).await?;

    let nonce = {
        let pending_attestation_query =
            entropy::storage().attestation().pending_attestations(signer.account_id());
        query_chain(&api, &rpc, pending_attestation_query, None)
            .await?
            .ok_or_else(|| AttestationErr::Unexpected)?
    };

    let block_number =
        rpc.chain_get_header(None).await?.ok_or_else(|| AttestationErr::BlockNumber)?.number;

    let quote = create_quote(block_number, nonce, &signer, &x25519_secret).await?;

    let attest_tx = entropy::tx().attestation().attest(quote.clone());
    submit_transaction(&api, &rpc, &signer, &attest_tx, None).await?;

    Ok(StatusCode::OK)
}

/// Create a mock quote for testing on non-TDX hardware
#[cfg(any(test, feature = "unsafe"))]
pub async fn create_quote(
    block_number: u32,
    nonce: [u8; 32],
    signer: &PairSigner<EntropyConfig, sp_core::sr25519::Pair>,
    x25519_secret: &StaticSecret,
) -> Result<Vec<u8>, AttestationErr> {
    use rand_core::OsRng;
    use sp_core::Pair;

    // In the real thing this is the hardware key used in the quoting enclave
    let signing_key = tdx_quote::SigningKey::random(&mut OsRng);

    let public_key = x25519_dalek::PublicKey::from(x25519_secret);

    let input_data = entropy_shared::QuoteInputData::new(
        signer.signer().public(),
        *public_key.as_bytes(),
        nonce,
        block_number,
    );

    let quote = tdx_quote::Quote::mock(signing_key.clone(), input_data.0).as_bytes().to_vec();
    Ok(quote)
}

/// Once implemented, this will create a TDX quote in production
#[cfg(not(any(test, feature = "unsafe")))]
pub async fn create_quote(
    _block_number: u32,
    _nonce: [u8; 32],
    _signer: &PairSigner<EntropyConfig, sp_core::sr25519::Pair>,
    _x25519_secret: &StaticSecret,
) -> Result<Vec<u8>, AttestationErr> {
    // Non-mock attestation (the real thing) will go here
    Err(AttestationErr::NotImplemented)
}
