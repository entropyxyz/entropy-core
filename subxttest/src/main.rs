use sp_keyring::AccountKeyring;
use subxt::{OnlineClient, PolkadotConfig, DefaultExtra, tx::PairSigner};
use chain_api::EntropyConfig;

#[subxt::subxt(runtime_metadata_path = "src/entropy_metadata.scale")]
pub mod entropy {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EntropyConfig;
impl Config for EntropyConfig {
    type AccountId = <SubstrateConfig as Config>::AccountId;
    type Address = <SubstrateConfig as Config>::Address;
    type BlockNumber = <SubstrateConfig as Config>::BlockNumber;
    type Extrinsic = <SubstrateConfig as Config>::Extrinsic;
    // ExtrinsicParams makes use of the index type, so we need to adjust it
    // too to align with our modified index type, above:
    type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
    type Hash = <SubstrateConfig as Config>::Hash;
    type Hashing = <SubstrateConfig as Config>::Hashing;
    type Header = <SubstrateConfig as Config>::Header;
    // This is different from the default `u32`.
    //
    // *Note* that in this example it does differ from the actual `Index` type in the
    // polkadot runtime used, so some operations will fail. Normally when using a custom `Config`
    // impl types MUST match exactly those used in the actual runtime.
    type Index = u64;
    type Signature = <SubstrateConfig as Config>::Signature;
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let signer = PairSigner::new(AccountKeyring::Alice.pair());
	let dest = AccountKeyring::Bob.to_account_id().into();

	//TODO replace accept weak inclusion
	let api = OnlineClient::<EntropyConfig>::new().await?;

	let balance_transfer_tx = entropy::tx().balances().transfer(dest, 10_000);
	
	let balance_transfer = api
		.tx()
		.sign_and_submit_then_watch_default(&balance_transfer_tx, &signer)
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
