use sp_keyring::AccountKeyring;
use subxt::{config::substrate::SubstrateExtrinsicParams, OnlineClient};

use super::node_proc::TestNodeProcess;
use crate::chain_api::*;

/// substrate node should be installed
fn get_path() -> String {
    format!(
        "{}/target/release/entropy",
        project_root::get_project_root().unwrap().to_string_lossy()
    )
}

pub type NodeRuntimeSignedExtra = SubstrateExtrinsicParams<EntropyConfig>;

pub async fn test_node_process_with(
    key: AccountKeyring,
    chain_type: String,
) -> TestNodeProcess<EntropyConfig> {
    let path = get_path();

    let proc = TestNodeProcess::<EntropyConfig>::build(path.as_str(), chain_type)
        .with_authority(key)
        .scan_for_open_ports()
        .spawn::<EntropyConfig>()
        .await;
    proc.unwrap()
}

pub async fn test_node(key: AccountKeyring, chain_type: String) -> TestNodeProcess<EntropyConfig> {
    let path = get_path();

    let proc = TestNodeProcess::<EntropyConfig>::build(path.as_str(), chain_type)
        .with_authority(key)
        .spawn::<EntropyConfig>()
        .await;
    proc.unwrap()
}

pub async fn test_node_process() -> TestNodeProcess<EntropyConfig> {
    test_node_process_with(AccountKeyring::Alice, "--dev".to_string()).await
}

pub async fn test_node_process_stationary() -> TestNodeProcess<EntropyConfig> {
    test_node(AccountKeyring::Alice, "--dev".to_string()).await
}

pub async fn test_node_process_testing_state() -> TestNodeProcess<EntropyConfig> {
    test_node(AccountKeyring::Alice, "--chain=test".to_string()).await
}

/// Spins up Substrate node and a connected `subxt` client.
pub struct SubstrateTestingContext {
    pub node_proc: TestNodeProcess<EntropyConfig>,
    pub api: OnlineClient<EntropyConfig>,
}

impl SubstrateTestingContext {
    /// Returns a `subxt` client connected to the test Substrate node.
    pub fn client(&self) -> &OnlineClient<EntropyConfig> { &self.api }
}

/// Constructs a new testing context for when we need multiple Substrate nodes.
pub async fn testing_context() -> SubstrateTestingContext {
    env_logger::try_init().ok();
    let node_proc: TestNodeProcess<EntropyConfig> = test_node_process().await;
    let api = node_proc.client().clone();
    SubstrateTestingContext { node_proc, api }
}

/// Construct a new testing context for when we only need one Substrate node.
pub async fn test_context_stationary() -> SubstrateTestingContext {
    env_logger::try_init().ok();
    let node_proc: TestNodeProcess<EntropyConfig> = test_node_process_stationary().await;
    let api = node_proc.client().clone();
    SubstrateTestingContext { node_proc, api }
}
