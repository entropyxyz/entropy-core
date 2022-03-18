//! The Node requests the client to take part in a signature generation.

use common::SigRequest;
use parity_scale_codec::{Decode, Encode};
// load entropy metadata so that subxt knows what types can be handled by the entropy network
#[subxt::subxt(runtime_metadata_path = "../protocol/src/entropy_metadata.scale")]
pub mod entropy {}

// ToDo: Should we move declaration of structs to /crypto/common/ ?
//       If those types are necessary for the node's OCW, then maybe we should

/// This is the data transmitted in the signature generation request.
#[derive(Debug, Encode, Decode, FromForm)]
pub struct ProvideSignatureReq {
	/// temporary dummy, delete this later
	pub demo: u8,
	/* message
	 * nonce
	 * communication manager
	 * IDs of other signing nodes (necessary for Lagrange-polynomials) */
}

/// Response of the signing node
#[derive(Debug, Encode)]
struct SignRes {
	pub demo: u8,
}

/// Response to the node if the signature was created.
/// i.e. a signature that the data was stored successfully or Error Code.
#[derive(Responder)]
#[response(status = 200, content_type = "application/x-parity-scale-codec")]
pub struct ProvideSignatureRes(Vec<u8>);

//ToDo: receive keyshare and store locally
#[post("/sign", format = "application/x-parity-scale-codec", data = "<encoded_data>")]
pub async fn provide_share(encoded_data: Vec<u8>) -> ProvideSignatureRes {
	println!("encoded_data {:?}", encoded_data);

	// ToDo: JA rename
	type Thing = Vec<common::OCWMessageDecode>;
	let data = Thing::decode(&mut encoded_data.as_ref());
	let data = match data {
		Ok(x) => x,
		Err(err) => panic!("failed to decode input {}", err),
	};

	println!("data: {:?}", &data);

	for task in data {
		println!("task: {:?}", task);
		// ToDo: JA hardcoding
		let sign_cli = protocol::sign::SignCli {
			//ToDo: handle the unwrap... how do I use Result<> as a return type in a HTTP-route?
			address: surf::Url::parse("http://localhost:3001/").unwrap(),
			// ToDo: DF: use the proper sigID and convert it to String
			room: String::from("sig_id"), // String::from_utf8(sig_id.clone()).unwrap(),
			index: 2,
			// parties: sig_res.signing_nodes, // ToDo: DF is this correct??
			parties: vec![2, 1], // ToDo: DF is this correct??
			data_to_sign: String::from("entropy rocks!!"),
		};
		println!("Bob starts signing...");
		// ToDo: JA handle error
		let signature = protocol::sign::sign(sign_cli).await;
		println!("signature: {:?}", signature);
	}
	//todo!();
	// Ok(ProvideSignatureRes(SignRes { demo: 1 }.encode()))
	// ToDO: JA fix
	ProvideSignatureRes(SignRes { demo: 1 }.encode())
}
