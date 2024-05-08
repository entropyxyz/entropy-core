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

//! A client interface for communicating with the Entropy blockchain
#![allow(clippy::all)]
pub use subxt::PolkadotConfig as EntropyConfig;
use subxt::{
    backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
    OnlineClient,
};

#[subxt::subxt(
    runtime_metadata_path = "entropy_metadata.scale",
    substitute_type(
        path = "entropy_shared::types::KeyVisibility",
        with = "::subxt::utils::Static<::entropy_shared::KeyVisibility>",
    ),
    substitute_type(
        path = "entropy_shared::types::ValidatorInfo",
        with = "::subxt::utils::Static<::entropy_shared::ValidatorInfo>",
    )
)]
pub mod entropy {}

/// Creates an api instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_api(url: &str) -> Result<OnlineClient<EntropyConfig>, subxt::Error> {
    // insecure url is fine since binaries are on the same machine
    let api = OnlineClient::<EntropyConfig>::from_insecure_url(url).await?;
    Ok(api)
}

/// Creates a rpc instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_rpc(url: &str) -> Result<LegacyRpcMethods<EntropyConfig>, subxt::Error> {
    // insecure url is fine since binaries are on the same machine
    let rpc_client = RpcClient::from_insecure_url(url).await?;
    let rpc_methods = LegacyRpcMethods::<EntropyConfig>::new(rpc_client);
    Ok(rpc_methods)
}

#[cfg(test)]
#[serial_test::serial]
#[tokio::test]
async fn test_get_api_rpc() {
    let insecure_url = "ws://1234:9944";
    let secure_url = "ws://localhost:9944";

    let insecure_result_rpc = get_rpc(insecure_url).await;
    assert_eq!(
        insecure_result_rpc
            .unwrap_err()
            .to_string()
            .contains("Rpc error: RPC error: Error when opening the TCP socket:"),
        true
    );

    let secure_result_rpc = get_rpc(secure_url).await;
    assert_eq!(
        secure_result_rpc
            .unwrap_err()
            .to_string()
            .contains("Rpc error: RPC error: Error when opening the TCP socket:"),
        true
    );

    let insecure_result_api = get_api(insecure_url).await;
    assert_eq!(
        insecure_result_api
            .unwrap_err()
            .to_string()
            .contains("Rpc error: RPC error: Error when opening the TCP socket:"),
        true
    );

    let secure_result_api = get_api(secure_url).await;
    assert_eq!(
        secure_result_api
            .unwrap_err()
            .to_string()
            .contains("Rpc error: RPC error: Error when opening the TCP socket:"),
        true
    );
}
