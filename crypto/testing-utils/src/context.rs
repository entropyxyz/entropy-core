use sp_keyring::AccountKeyring;
use subxt::{
    ext::sp_core::Pair,
    tx::{PairSigner, SubstrateExtrinsicParams},
    OnlineClient,
};

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

pub async fn test_node_process_with(key: AccountKeyring) -> TestNodeProcess<EntropyConfig> {
    let path = get_path();

    let proc = TestNodeProcess::<EntropyConfig>::build(path.as_str())
        .with_authority(key)
        .scan_for_open_ports()
        .spawn::<EntropyConfig>()
        .await;
    proc.unwrap()
}

pub async fn test_node(key: AccountKeyring) -> TestNodeProcess<EntropyConfig> {
    let path = get_path();

    let proc = TestNodeProcess::<EntropyConfig>::build(path.as_str())
        .with_authority(key)
        .spawn::<EntropyConfig>()
        .await;
    proc.unwrap()
}

pub async fn test_node_process() -> TestNodeProcess<EntropyConfig> {
    test_node_process_with(AccountKeyring::Alice).await
}

pub async fn test_node_process_stationary() -> TestNodeProcess<EntropyConfig> {
    test_node(AccountKeyring::Alice).await
}

pub struct TestContext {
    pub node_proc: TestNodeProcess<EntropyConfig>,
    pub api: OnlineClient<EntropyConfig>,
}

impl TestContext {
    pub fn client(&self) -> &OnlineClient<EntropyConfig> { &self.api }
}

pub async fn test_context() -> TestContext {
    env_logger::try_init().ok();
    let node_proc: TestNodeProcess<EntropyConfig> = test_node_process().await;
    let api = node_proc.client().clone();
    TestContext { node_proc, api }
}

pub async fn test_context_stationary() -> TestContext {
    env_logger::try_init().ok();
    let node_proc: TestNodeProcess<EntropyConfig> = test_node_process_stationary().await;
    let api = node_proc.client().clone();
    TestContext { node_proc, api }
}
