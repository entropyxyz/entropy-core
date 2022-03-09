use super::node_proc::TestNodeProcess;
use sp_core::sr25519::Pair;
use sp_keyring::AccountKeyring;
use subxt::{
	extrinsic::ChargeAssetTxPayment, Client, DefaultConfig, DefaultExtraWithTxPayment, PairSigner,
};

/// substrate node should be installed
fn get_path() -> String {
	let root = project_root::get_project_root();
	let extension: &str = "/target/release/entropy";

	let mut file_path: String = root.unwrap().as_path().display().to_string().to_owned();
	file_path.push_str(extension);
	file_path
}

pub type NodeRuntimeSignedExtra =
	DefaultExtraWithTxPayment<DefaultConfig, ChargeAssetTxPayment<DefaultConfig>>;

pub async fn test_node_process_with(key: AccountKeyring) -> TestNodeProcess<DefaultConfig> {
	let path = get_path();

	let proc = TestNodeProcess::<DefaultConfig>::build(path.as_str())
		.with_authority(key)
		.scan_for_open_ports()
		.spawn::<DefaultConfig>()
		.await;
	proc.unwrap()
}

pub async fn test_node_process() -> TestNodeProcess<DefaultConfig> {
	test_node_process_with(AccountKeyring::Alice).await
}

#[subxt::subxt(runtime_metadata_path = "src/entropy_metadata.scale")]
pub mod entropy {}

pub struct TestContext {
	pub node_proc: TestNodeProcess<DefaultConfig>,
	pub api: entropy::RuntimeApi<DefaultConfig, NodeRuntimeSignedExtra>,
}

impl TestContext {
	pub fn client(&self) -> &Client<DefaultConfig> {
		&self.api.client
	}
}

pub async fn test_context() -> TestContext {
	env_logger::try_init().ok();
	let node_proc: TestNodeProcess<DefaultConfig> =
		test_node_process_with(AccountKeyring::Alice).await;
	let api = node_proc.client().clone().to_runtime_api();
	TestContext { node_proc, api }
}

pub fn pair_signer(pair: Pair) -> PairSigner<DefaultConfig, NodeRuntimeSignedExtra, Pair> {
	PairSigner::new(pair)
}
