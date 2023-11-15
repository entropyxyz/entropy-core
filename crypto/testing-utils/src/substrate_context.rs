use sp_keyring::AccountKeyring;
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
        binary_path.push(format!("target/{}/entropy", build_type));
        let binary_path = binary_path.as_path();

        let error_msg = format!(
         "Missing `entropy` binary, please build it in `{}` mode before running test suite (e.g \
         `cargo build -p entropy [--release]`)",
          build_type
        );

        assert!(binary_path.try_exists().expect(&error_msg), "{}", error_msg);
        binary_path.into()
    }
}

pub type NodeRuntimeSignedExtra = SubstrateExtrinsicParams<EntropyConfig>;

pub async fn test_node_process_with(
    key: AccountKeyring,
    chain_type: String,
    force_authoring: bool,
) -> TestNodeProcess<EntropyConfig> {
    let path = get_path();
    let path = path.to_str().expect("Path should've been checked to be valid earlier.");

    let proc = TestNodeProcess::<EntropyConfig>::build(path, chain_type, force_authoring)
        .with_authority(key)
        .scan_for_open_ports()
        .spawn::<EntropyConfig>()
        .await;
    proc.unwrap()
}

pub async fn test_node(
    key: AccountKeyring,
    chain_type: String,
    force_authoring: bool,
) -> TestNodeProcess<EntropyConfig> {
    let path = get_path();
    let path = path.to_str().expect("Path should've been checked to be valid earlier.");

    let proc = TestNodeProcess::<EntropyConfig>::build(path, chain_type, force_authoring)
        .with_authority(key)
        .spawn::<EntropyConfig>()
        .await;
    proc.unwrap()
}

pub async fn test_node_process() -> TestNodeProcess<EntropyConfig> {
    test_node_process_with(AccountKeyring::Alice, "--dev".to_string(), false).await
}

pub async fn test_node_process_stationary() -> TestNodeProcess<EntropyConfig> {
    test_node(AccountKeyring::Alice, "--dev".to_string(), false).await
}

/// Tests chain with test state in chain config
///
/// Allowing `force_authoring` will produce blocks.
pub async fn test_node_process_testing_state(
    force_authoring: bool,
) -> TestNodeProcess<EntropyConfig> {
    test_node(AccountKeyring::Alice, "--chain=test".to_string(), force_authoring).await
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
