//! The User requests the Signature-client to store a keyshare localy. 

use parity_scale_codec::{Encode, Decode}; 

// ToDo: Should we move declaration of structs to /crypto/common/ ?
//       If those types are necessary for the node's OCW, then maybe we should

/// Keyshare send to the node from the User during the registration process. 
#[derive(Debug, Encode, Decode, FromForm)]
pub struct StoreKeyshareReq {
    pub demo: u8,
	// hmmmm, what data is needed to store a keyshare??  
}

/// Response of the key storing
#[derive(Debug, Encode)]
struct StoreRes {
    pub demo: u8,
}

/// Response to request to store keyshares
/// i.e. a signature that the data was stored successfully
#[derive(Responder)]
#[response(
    status = 200,
    content_type = "application/x-parity-scale-codec"
)]
pub struct StoreKeyshareRes(Vec<u8>);

//ToDo: receive keyshare and store locally
#[post(
    "/store_keyshare",
    format = "application/x-parity-scale-codec",
    data = "<encoded_data>"
)]
pub fn store_keyshare(encoded_data: Vec<u8>) -> StoreKeyshareRes {
    let _data = StoreKeyshareReq::decode(&mut encoded_data.as_ref()).ok().unwrap();
    todo!();
    StoreKeyshareRes(StoreRes { demo: 1 }.encode())
}