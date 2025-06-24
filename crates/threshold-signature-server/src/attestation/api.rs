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
    chain_api::{get_api, get_rpc},
    AppState,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use entropy_client::{user::request_attestation, attestation::create_quote};
use entropy_shared::attestation::{QuoteContext, QuoteInputData};
use serde::Deserialize;
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
    let public_key = x25519_dalek::PublicKey::from(&app_state.x25519_secret);
    let quote =
        create_quote(nonce, app_state.subxt_account_id(), &public_key.to_bytes(), context)
            .await?;

    Ok((StatusCode::OK, quote))
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
