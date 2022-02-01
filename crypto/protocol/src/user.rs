
use std::panic::take_hook;

use async_trait::async_trait;
use sp_keyring::AccountKeyring;
use subxt::{ClientBuilder, PairSigner, sp_runtime::PerThing};

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
	// fn send_tx() {
	// 	todo!();
	// }
	async fn send_tx(&self) -> Result<(), Box<dyn std::error::Error   >> {

		println!("register is called");
		let signer = PairSigner::new(AccountKeyring::Alice.pair());

		let api = ClientBuilder::new()
			.set_url("ws://localhost:9944")
			.accept_weak_inclusion()
			.build()
			.await?
			.to_runtime_api::<entropy::RuntimeApi<entropy::DefaultConfig>>();

		// User sends the registration-message to any node.
		// User expects a reply
		// This reply contains the endpoint of the current signer-node or an error message
		// Todo: handle the result message and forward the Signer's endpoint
		let result = api
				.tx()
				.relayer()
				.account_registration(
					entropy::runtime_types::protocol::common::RequestSigBody{
						//user_public_key:&self, 
						keyshards: 123, 
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
