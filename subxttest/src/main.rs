use sp_keyring::AccountKeyring;
use subxt::{OnlineClient, DefaultConfig, DefaultExtra, PairSigner};

#[subxt::subxt(runtime_metadata_path = "src/entropy_metadata.scale")]
pub mod entropy {}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let signer = PairSigner::new(AccountKeyring::Alice.pair());
	let dest = AccountKeyring::Bob.to_account_id().into();

	//TODO replace accept weak inclusion
	let api = OnlineClient::new()
		.set_url("ws://localhost:9944")
		.build()
		.await?
		.to_runtime_api::<entropy::RuntimeApi<DefaultConfig, DefaultExtra<_>>>();

	let result = api
		.tx()
		.balances()
		.transfer(dest, 10_000)
		.sign_and_submit_then_watch(&signer)
		.await?
		.wait_for_finalized_success()
		.await?;

	if let Some(event) = result.find_first_event::<entropy::balances::events::Transfer>()? {
		println!("Balance transfer success: value: {:?}", event.2);
	} else {
		println!("Failed to find Balances::Transfer Event");
	}
	Ok(())
}
