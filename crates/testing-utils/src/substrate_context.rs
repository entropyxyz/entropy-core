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

use entropy_tss::helpers::tests::ChainSpecType;
use sp_keyring::sr25519::Keyring;
use subxt::{config::substrate::SubstrateExtrinsicParams, OnlineClient};

use super::node_proc::TestNodeProcess;
use crate::chain_api::*;
/// Verifies that the Entropy node binary exists.
///
/// If a path is provided using the `ENTROPY_NODE` environment variable, that will take priority.
/// Otherwise it will search for an Entropy node binary based on the build type of the test suite.
///
/// # Panics
///
/// If no Entropy binary can be found.
fn get_path() -> Box<std::path::Path> {
    if let Ok(path) = std::env::var("ENTROPY_NODE") {
        let binary_path = std::path::Path::new(&path);
        let error_msg = format!(
            "Unable to find an Entropy binary at the path provided by `ENTROPY_NODE=\"{}\"`",
            &path
        );

        assert!(binary_path.try_exists().expect(&error_msg), "{}", error_msg);
        binary_path.into()
    } else {
        let build_type = if cfg!(debug_assertions) { "debug" } else { "release" };

        let mut binary_path =
            project_root::get_project_root().expect("Error obtaining project root.");
        binary_path.push(format!("target/{build_type}/entropy"));
        let binary_path = binary_path.as_path();

        let error_msg = format!(
         "Missing `entropy` binary, please build it in `{build_type}` mode before running test suite (e.g \
         `cargo build -p entropy [--release]`)"
        );

        assert!(binary_path.try_exists().expect(&error_msg), "{}", error_msg);
        binary_path.into()
    }
}

pub type NodeRuntimeSignedExtra = SubstrateExtrinsicParams<EntropyConfig>;

pub async fn test_node_process_with(
    key: Keyring,
    chain_type: String,
    force_authoring: bool,
    bootnode: Option<String>,
    tss_server_endpoint: Option<String>,
) -> TestNodeProcess<EntropyConfig> {
    let path = get_path();
    let path = path.to_str().expect("Path should've been checked to be valid earlier.");

    let proc = TestNodeProcess::<EntropyConfig>::build(
        path,
        chain_type,
        force_authoring,
        bootnode,
        tss_server_endpoint,
        None,
    )
    .with_authority(key)
    .scan_for_open_ports()
    .spawn::<EntropyConfig>()
    .await;
    proc.unwrap()
}

pub async fn test_node(
    key: Keyring,
    chain_type: String,
    force_authoring: bool,
    bootnode: Option<String>,
    node_key: Option<String>,
) -> TestNodeProcess<EntropyConfig> {
    let path = get_path();
    let path = path.to_str().expect("Path should've been checked to be valid earlier.");

    let proc = TestNodeProcess::<EntropyConfig>::build(
        path,
        chain_type,
        force_authoring,
        bootnode,
        None,
        node_key,
    )
    .with_authority(key)
    .spawn::<EntropyConfig>()
    .await;
    proc.unwrap()
}

pub async fn test_node_process() -> TestNodeProcess<EntropyConfig> {
    test_node_process_with(Keyring::Alice, "--dev".to_string(), false, None, None).await
}

pub async fn test_node_process_stationary() -> TestNodeProcess<EntropyConfig> {
    test_node(Keyring::Alice, "--dev".to_string(), false, None, None).await
}

pub async fn test_node_process_stationary_local() -> TestNodeProcess<EntropyConfig> {
    test_node(Keyring::Alice, "--chain=testnet-local".to_string(), false, None, None).await
}

/// Tests chain with test state in chain config.
///
/// Allowing `force_authoring` will produce blocks.
pub async fn test_node_process_testing_state(
    chain_spec_type: ChainSpecType,
    force_authoring: bool,
) -> Vec<TestNodeProcess<EntropyConfig>> {
    // boot node is generated with node key for determinisim
    let alice_bootnode = Some(
        "/ip4/127.0.0.1/tcp/30333/p2p/12D3KooWMrQiZJKkbkZrb7NfkF3u2cu1i5js3tuC3LTYYHfoVbyE"
            .to_string(),
    );
    let alice_node_key =
        Some("0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d".to_string());
    let result = test_node(
        Keyring::Alice,
        format!("--chain={chain_spec_type}"),
        force_authoring,
        None,
        alice_node_key,
    )
    .await;
    let result_bob = test_node_process_with(
        Keyring::Bob,
        format!("--chain={chain_spec_type}"),
        force_authoring,
        alice_bootnode.clone(),
        Some("http://127.0.0.1:3002".into()),
    )
    .await;
    let result_charlie = test_node_process_with(
        Keyring::Charlie,
        format!("--chain={chain_spec_type}"),
        force_authoring,
        alice_bootnode.clone(),
        Some("http://127.0.0.1:3003".into()),
    )
    .await;
    let result_dave = test_node_process_with(
        Keyring::Dave,
        format!("--chain={chain_spec_type}"),
        force_authoring,
        alice_bootnode.clone(),
        Some("http://127.0.0.1:3004".into()),
    )
    .await;

    vec![result, result_bob, result_charlie, result_dave]
}

/// Spins up Substrate node and a connected `subxt` client.
pub struct SubstrateTestingContext {
    pub node_proc: TestNodeProcess<EntropyConfig>,
    pub api: OnlineClient<EntropyConfig>,
}

impl SubstrateTestingContext {
    /// Returns a `subxt` client connected to the test Substrate node.
    pub fn client(&self) -> &OnlineClient<EntropyConfig> {
        &self.api
    }
}

/// Constructs a new testing context for when we need multiple Substrate nodes.
pub async fn testing_context() -> SubstrateTestingContext {
    let node_proc: TestNodeProcess<EntropyConfig> = test_node_process().await;
    let api = node_proc.client().clone();
    SubstrateTestingContext { node_proc, api }
}

/// Construct a new testing context for when we only need one Substrate node.
pub async fn test_context_stationary() -> SubstrateTestingContext {
    let node_proc: TestNodeProcess<EntropyConfig> = test_node_process_stationary().await;
    let api = node_proc.client().clone();
    SubstrateTestingContext { node_proc, api }
}
