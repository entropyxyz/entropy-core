
use std::panic::take_hook;

use async_trait::async_trait;
use sp_keyring::AccountKeyring;
use subxt::{ClientBuilder, DefaultConfig, DefaultExtra, PairSigner};

// load entropy metadata so that subxt knows what types can be handled by the entropy network
#[subxt::subxt(runtime_metadata_path = "src/entropy_metadata.scale")]
pub mod entropy {}

/// Alice, who generates the key shares (for now)
pub struct User {
	// key_share: PrivateKey
}

impl User {
	/// User generates
	fn new() -> Self {
		// todo: generate shares
		// todo: distribute shares
		Self {}
	}
	/// Submit tx to network
	fn send_tx() {
		todo!();
	}

	/// User sends an extrinsic requesting the endpoints of the signer nodes to generate a signature
	/// User expects a reply
	/// This reply contains the endpoint of the current signer-node or an error message. Or read the endpoints on-chain??
	// Todo: how can the signer node endpoints passed to the user in the reply?
	// Todo: handle the result message and forward the Signer's endpoint	
	async fn request_sig_gen(&self) -> Result<(), Box<dyn std::error::Error>> {

		println!("register is called");
		let signer = PairSigner::new(AccountKeyring::Alice.pair());

		let api = ClientBuilder::new()
			.set_url("ws://localhost:9944")
			.build()
			.await?
			.to_runtime_api::<entropy::RuntimeApi<DefaultConfig, DefaultExtra<_>>>();

		// send extrinsic
		let result = api
				.tx()
				.relayer()
				.prep_transaction(
					entropy::runtime_types::common::common::SigRequest{
						hash_msg: 123, 
						test: 369
					}
				)
				.sign_and_submit_then_watch(&signer) 
				.await?;
		
		// ToDo: handle result
		println!("result: {:?}", result);

		Ok(())
	}

	/// Remove funds from network and delete account
	fn delete_account() {
		todo!();
	}
}
