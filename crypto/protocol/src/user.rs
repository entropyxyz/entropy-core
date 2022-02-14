#![allow(unused_imports)]
use std::panic::take_hook;
use async_trait::async_trait;
use sp_keyring::AccountKeyring;
use subxt::{ClientBuilder, DefaultConfig, DefaultExtra, PairSigner};
use anyhow::{anyhow, Context, Result};

use crate::sign::{sign, SignCli};

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
	pub async fn sign_message(&self, msg:u16) -> Result<()> {
		let (sig_id, sig_req) = self.get_sig_req(&msg).context("Unable to compute SigRequest")?;
		let sig_res = self.request_sig_gen(sig_req).await?;
		println!("received SigRes");
		let sign_cli = SignCli{
			address: surf::Url::parse("http://localhost:3001/")?,
			// room: sig_req.sig_id.into(), 
			// room: sig_req.sig_id.parse::<u16>().unwrap(), 
			// ToDo: DF: use the proper sigID and convert it to String 
			room: String::from("sig_id"), // String::from_utf8(sig_id.clone()).unwrap(),
			index: 1,
			parties: sig_res.signing_nodes, 
			data_to_sign: String::from("entropy rocks!!"),
		};
		let signature = sign(sign_cli).await;
		Ok(())
	}

	fn get_sig_req(&self, msg:&u16) -> Result<(
			u16, // u16 to Vec<u16> codec::alloc::vec::Vec<u8>, 
			entropy::runtime_types::common::common::SigRequest
		)> {
		Ok((
			// ToDo: DF undo this hack!!
			// creating sig_id here and again below; to avoid ownership trouble
			// possible solution: add lifetime to sig_req in request_sig_gen()
			123, // vec![123],
			entropy::runtime_types::common::common::SigRequest{
				// sig_id is a hash of the message
				sig_id: 123, // vec![123], 
				nonce: 369,
				signature: 1
		}))
	}

	/// User sends an extrinsic requesting the endpoints of the signer nodes to generate a signature
	/// User expects a reply
	/// This reply contains the endpoint of the current signer-node or an error message. Or read the
	/// endpoints on-chain??
	// Todo: how can the signer node endpoints passed to the user in the reply?
	// Todo: handle the result message and forward the Signer's endpoint	
	pub async fn request_sig_gen(&self, sig_req: entropy::runtime_types::common::common::SigRequest) -> Result<common::SigResponse> { // } , Box<dyn std::error::Error>> {
	//pub async fn request_sig_gen(&self) -> Result<common::SigResponse> { // } , Box<dyn std::error::Error>> {

		println!("request_sig_gen is called");
		let signer = PairSigner::new(AccountKeyring::Alice.pair());

		let api = ClientBuilder::new()
			.set_url("ws://localhost:9944")
			.build()
			.await?
			.to_runtime_api::<entropy::RuntimeApi<DefaultConfig, DefaultExtra<_>>>();

		println!("about to send xt with sig_id: {:?}",&sig_req.sig_id);

		// send extrinsic
		let result = api
			.tx()
			.relayer()
			.prep_transaction(
				// entropy::runtime_types::common::common::SigRequest{
				// 	sig_id: 123, 
				// 	nonce: 369,
				// 	signature: 1
				// }
				sig_req
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

		println!("sr {:?}", sr.signing_nodes);
		// Ok(())
		Ok(sr)
	}

	/// User sends an extrinsic requesting account creation
	#[allow(dead_code)]
	pub async fn send_registration_request(&self) -> Result<common::RegistrationResponse> {
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
			.await?
			.wait_for_finalized_success()
			.await?;

		let responding_node = result.find_first_event::<entropy::relayer::events::AccountRegistered>()?
		.context("send_registration_request no result received")?.0;
		let reg_response = result.find_first_event::<entropy::relayer::events::AccountRegistered>()?
		.context("send_registration_request no result received")?.1;

		// let reg_response = result.find_first_event::<entropy::relayer::events::AccountRegistered>()?
		// .context("request_sig_gen no result received")?.1;
		
		// println!{"reg_response {:?}", reg_response};
		let regres = common::RegistrationResponse {
			signing_nodes: reg_response.signing_nodes, 
		};

		Ok(regres)
	}	
}

// #[async_std::main]
// async fn main() -> Result<(),Box<dyn std::error::Error>> {
// 	println!("test_sign");
// 	let user = User{};
// 	user.request_sig_gen().await?;
// 	Ok(())
// }
