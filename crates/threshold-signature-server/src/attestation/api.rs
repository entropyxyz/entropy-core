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

use crate::{attestation::errors::AttestationErr, AppState};
use axum::{body::Bytes, extract::State, http::StatusCode};

/// HTTP POST endpoint to initiate a TDX attestation.
/// Not yet implemented.
#[cfg(not(any(test, feature = "unsafe")))]
pub async fn attest(
    State(_app_state): State<AppState>,
    _input: Bytes,
) -> Result<StatusCode, AttestationErr> {
    // Non-mock attestation (the real thing) will go here
    Err(AttestationErr::NotImplemented)
}

/// HTTP POST endpoint to initiate a mock TDX attestation for testing on non-TDX hardware.
/// The body of the request should be a 32 byte random nonce used to show 'freshness' of the
/// quote.
/// The response body contains a mock TDX v4 quote serialized as described in the
/// [Index TDX DCAP Quoting Library API](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf).
#[cfg(any(test, feature = "unsafe"))]
pub async fn attest(
    State(app_state): State<AppState>,
    input: Bytes,
) -> Result<(StatusCode, Bytes), AttestationErr> {
    use crate::{
        chain_api::{entropy, get_api, get_rpc},
        get_signer_and_x25519_secret,
        helpers::substrate::submit_transaction,
    };
    use rand_core::OsRng;
    use sp_core::Pair;

    // TODO (#982) confirm with the chain that an attestation should be happenning
    let nonce = input.as_ref().try_into()?;

    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;

    let block_number =
        rpc.chain_get_header(None).await?.ok_or_else(|| AttestationErr::BlockNumber)?.number;

    // In the real thing this is the hardware key used in the quoting enclave
    let signing_key = tdx_quote::SigningKey::random(&mut OsRng);

    let (signer, x25519_secret) = get_signer_and_x25519_secret(&app_state.kv_store).await?;
    let public_key = x25519_dalek::PublicKey::from(&x25519_secret);

    let input_data = entropy_shared::QuoteInputData::new(
        signer.signer().public(),
        *public_key.as_bytes(),
        nonce,
        block_number,
    );

    let quote = tdx_quote::Quote::mock(signing_key.clone(), input_data.0).as_bytes().to_vec();

    let attest_tx = entropy::tx().attestation().attest(quote.clone());
    submit_transaction(&api, &rpc, &signer, &attest_tx, None).await?;

    Ok((StatusCode::OK, Bytes::from(quote)))
}
