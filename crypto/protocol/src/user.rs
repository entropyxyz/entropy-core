#![allow(unused_imports)]
use std::panic::take_hook;
use async_trait::async_trait;
use sp_keyring::AccountKeyring;
use subxt::{ClientBuilder, DefaultConfig, DefaultExtra, PairSigner};
use anyhow::{anyhow, Context, Result};

// load entropy metadata so that subxt knows what types can be handled by the entropy network
#[subxt::subxt(runtime_metadata_path = "src/entropy_metadata.scale")]
pub mod entropy {}

// ToDo: DF pull type SigRequest from entropy's runtime_metadata; see below
// for this we need to change code in pallet::relayer such that relayer adds SigRequest to runtime_metadata
// type SigRequest =  entropy::relayer::SigRequest;

/// Alice, who generates the key shares (for now)
pub struct User {
	// key_share: PrivateKey
}

impl User {
	pub fn sign_message(&self, msg:u16) -> Result<()> {
		let sig_req = self.get_sig_req(&msg).context("Unable to compute SigRequest")?;
		// let sig_res = self.request_sig_gen(sig_req);
		let sig_res = self.request_sig_gen();
		Ok(())
	}

	fn get_sig_req(&self, msg:&u16) -> Result<entropy::runtime_types::common::common::SigRequest> {
		Ok(entropy::runtime_types::common::common::SigRequest{
			sig_id: 123, 
			nonce: 369,
			signature: 1
		})
	}

	/// User sends an extrinsic requesting the endpoints of the signer nodes to generate a signature
	/// User expects a reply
	/// This reply contains the endpoint of the current signer-node or an error message. Or read the
	/// endpoints on-chain??
	// Todo: how can the signer node endpoints passed to the user in the reply?
	// Todo: handle the result message and forward the Signer's endpoint	
	pub async fn request_sig_gen(&self) -> Result<common::SigResponse> { // } , Box<dyn std::error::Error>> {

		println!("request_sig_gen is called");
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
						sig_id: 123, 
						nonce: 369,
						signature: 1
					}
				)
				.sign_and_submit_then_watch(&signer) 
				.await?
				.wait_for_finalized_success()
				.await?;

		let responding_node = result.find_first_event::<entropy::relayer::events::TransactionPropagated>()?
		.context("request_sig_gen no result received")?.0;
		let sig_response = result.find_first_event::<entropy::relayer::events::TransactionPropagated>()?
		.context("request_sig_gen no result received")?.1;

		// ToDo: DF implement the following hack properly!
		// i.e. define SigResponse in pallet::relayer so that it shows up in entropy's runtime_metadata and then use that type here
		// maybe this way all/many structs in crypto/common can be migrated into the substrate codebase
		// maybe this can help: https://github.com/paritytech/subxt/tree/55f04c20a78c5cb1b26584802f562a0cc8f9eb12/test-runtime
		let sr = common::SigResponse {
			signing_nodes: sig_response.signing_nodes, 
			com_manager: sig_response.com_manager
		}; 
		// Ok(sr)

		println!("sr {}", sr.signing_nodes);
		// Ok(())
		Ok(sr)
	}

	/// User sends an extrinsic requesting account creation
	#[allow(dead_code)]
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

#[async_std::main]
async fn main() -> Result<(),Box<dyn std::error::Error>> {
	println!("test_sign");
	let user = User{};
	user.request_sig_gen().await?;
	Ok(())

}

#[cfg(test)]
mod tests {
	use super::*;
    #[tokio::test]
    async fn abctest() -> Result<()> {
        println!("test_sign");
		let user = User{};
		user.request_sig_gen().await?;
		Ok(())
    }
}