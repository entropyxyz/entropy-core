//! The Node requests the client to take part in a signature generation. 

use parity_scale_codec::{Encode, Decode}; 

// ToDo: Should we move declaration of structs to /crypto/common/ ?
//       If those types are necessary for the node's OCW, then maybe we should

/// This is the data transmitted in the signature generation request. 
#[derive(Debug, Encode, Decode, FromForm)]
pub struct ProvideSignatureReq {
	/// temporary dummy, delete this later
    pub demo: u8,
	// message
	// nonce
	// communication manager
	// IDs of other signing nodes (necessary for Lagrange-polynomials) 
}

/// Response of the signing node
#[derive(Debug, Encode)]
struct SignRes {
    pub demo: u8,
}

/// Response to the node if the signature was created. 
/// i.e. a signature that the data was stored successfully or Error Code. 
#[derive(Responder)]
#[response(
    status = 200,
    content_type = "application/x-parity-scale-codec"
)]
pub struct ProvideSignatureRes(Vec<u8>);

//ToDo: receive keyshare and store locally
#[post(
    "/sign",
    format = "application/x-parity-scale-codec",
    data = "<encoded_data>"
)]
pub fn provide_share(encoded_data: Vec<u8>) -> ProvideSignatureRes {
    let _data = ProvideSignatureReq::decode(&mut encoded_data.as_ref()).ok().unwrap();
	todo!();
    ProvideSignatureRes(SignRes { demo: 1 }.encode());
}