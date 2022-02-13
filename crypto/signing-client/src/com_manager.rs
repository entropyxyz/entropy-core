//! The Node requests the client to open a communication manager in order to
//! manage communication between the signing parties.

use parity_scale_codec::{Decode, Encode};

// ToDo: Should we move declaration of structs to /crypto/common/ ?
//       If those types are necessary for the node's OCW, then maybe we should

/// This is the data transmitted in the signature generation request.
#[derive(Debug, Encode, Decode, FromForm)]
pub struct ComManagerReq {
	/// temporary dummy, delete this later
	pub demo: u8,
	/* hmmmm, what data does the Communication Manager need to know??
	 * do we want to limit ports or whatever?? */
}

/// Response of the Communication Manager
#[derive(Debug, Encode)]
struct UnencodedComManagerRes {
	pub demo: u8,
	// what is the ComManager's response??
}

/// Response to the node if the signature was created.
/// i.e. a signature that the data was stored successfully or Error Code.
#[derive(Responder)]
#[response(status = 200, content_type = "application/x-parity-scale-codec")]
pub struct ComManagerRes(Vec<u8>);

//ToDo: receive keyshare and store locally
#[post("/com_manager", format = "application/x-parity-scale-codec", data = "<encoded_data>")]
pub fn start_com_manager(encoded_data: Vec<u8>) -> ComManagerRes {
	let _data = ComManagerReq::decode(&mut encoded_data.as_ref()).ok().unwrap();
	todo!();
	ComManagerRes(UnencodedComManagerRes { demo: 1 }.encode());
}
