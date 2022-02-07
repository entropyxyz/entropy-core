//! Alice generates the keys
use super::user::User;
#[allow(unused_imports)]
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;

use async_trait::async_trait;
use sp_keyring::AccountKeyring;
use subxt::{ClientBuilder, DefaultConfig, DefaultExtra, PairSigner};

// load entropy metadata so that subxt knows what types can be handled by the entropy network
#[subxt::subxt(runtime_metadata_path = "src/entropy_metadata.scale")]
pub mod entropy {}

impl User {
	pub fn keygen() {
		todo!();
	}

	/// User sends an extrinsic requesting account creation
	async fn send_registration(&self) -> Result<(), Box<dyn std::error::Error>> {

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
				.register(
					entropy::runtime_types::common::common::RegistrationMessage{
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

}
