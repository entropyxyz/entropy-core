use sp_core::Pair;
use sp_keyring::AccountKeyring;
use subxt::{config::PolkadotConfig, tx::PairSigner, tx::SubstrateExtrinsicParams, OnlineClient};

use super::node_proc::TestNodeProcess;

/// substrate node should be installed
fn get_path() -> String {
    format!(
        "{}/target/release/entropy",
        project_root::get_project_root().unwrap().to_string_lossy()
    )
}

pub type NodeRuntimeSignedExtra = SubstrateExtrinsicParams<PolkadotConfig>;

pub async fn test_node_process_with(key: AccountKeyring) -> TestNodeProcess<PolkadotConfig> {
    let path = get_path();

    let proc = TestNodeProcess::<PolkadotConfig>::build(path.as_str())
        .with_authority(key)
        .scan_for_open_ports()
        .spawn::<PolkadotConfig>()
        .await;
    proc.unwrap()
}

pub async fn test_node(key: AccountKeyring) -> TestNodeProcess<PolkadotConfig> {
    let path = get_path();

    let proc = TestNodeProcess::<PolkadotConfig>::build(path.as_str())
        .with_authority(key)
        .spawn::<PolkadotConfig>()
        .await;
    proc.unwrap()
}

pub async fn test_node_process() -> TestNodeProcess<PolkadotConfig> {
    test_node_process_with(AccountKeyring::Alice).await
}

pub async fn test_node_process_stationary() -> TestNodeProcess<PolkadotConfig> {
    test_node(AccountKeyring::Alice).await
}

#[subxt::subxt(runtime_metadata_path = "../server/entropy_metadata.scale")]
pub mod entropy {}

pub struct TestContext {
    pub node_proc: TestNodeProcess<PolkadotConfig>,
    pub api: entropy::RuntimeApi<PolkadotConfig, SubstrateExtrinsicParams<PolkadotConfig>>,
}

impl TestContext {
    pub fn client(&self) -> &OnlineClient<PolkadotConfig> {
        &self.api.client
    }
}

pub async fn test_context() -> TestContext {
    env_logger::try_init().ok();
    let node_proc: TestNodeProcess<PolkadotConfig> = test_node_process().await;
    let api = node_proc.client().clone().to_runtime_api();
    TestContext { node_proc, api }
}

pub async fn test_context_stationary() -> TestContext {
    env_logger::try_init().ok();
    let node_proc: TestNodeProcess<PolkadotConfig> = test_node_process_stationary().await;
    let api = node_proc.client().clone().to_runtime_api();
    TestContext { node_proc, api }
}

pub fn pair_signer(pair: Pair) -> PairSigner<PolkadotConfig, Pair> {
    PairSigner::new(pair)
}
