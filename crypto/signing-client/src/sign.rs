//! The Node requests the client to take part in a signature generation. 

use parity_scale_codec::{Encode, Decode}; 
use common::SigRequest;
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


type thing = Vec<common::OCWMessage>;

//ToDo: receive keyshare and store locally
#[post(
    "/sign",
    format = "application/x-parity-scale-codec",
    data = "<encoded_data>"
)]
pub fn provide_share(encoded_data: Vec<u8>) -> ProvideSignatureRes {
    println!("provide keyshare!");

    //let _data = ProvideSignatureReq::decode(&mut encoded_data.as_ref()).ok().unwrap();
    // let _data = entropy::runtime_types::pallet_relayer::pallet::Message::decode(&mut encoded_data.as_ref()).ok().unwrap();
//    let data = entropy::runtime_types::pallet_relayer::pallet::Message::decode(&mut encoded_data.as_ref())
    //.ok().unwrap();
    // .or_else(entropy::runtime_types::pallet_relayer::pallet::Message { 
	// 	// sig_request: common::SigRequest{hash_msg:1, test:1}
	// 	sig_request: SigRequest{hash_msg:1, test:1}
    // } );

    println!("encoded_data {:?}", encoded_data);


    //let data = common::OCWMessage::decode(&mut encoded_data.as_ref());
////////////////////


    type Thing = Vec<common::OCWMessage>;
    let data = Thing::decode(&mut encoded_data.as_ref());
    // println!("thing_dec: {:?}", thing_dec);
////////////////////
    //let data = thing::decode(&mut encoded_data.as_ref());
    let data = match data {
        Ok(x) => x,
        Err(err) => panic!("{}",err),
    };
    //let data = entropy::runtime_types::pallet_relayer::pallet::Message::decode(&mut encoded_data.as_ref())
    //.or_else(common::OCWMessage{sig_request:SigRequest{ hash_msg:1, test:2} });

      //.or_else(common::SigRequest{hash_msg:1, test:1});
    println!("data: {:?}", &data);//.sig_request.test);
// println!("keyshards: {}", data.sig_request.hash_msg);
	//todo!();
    ProvideSignatureRes(SignRes { demo: 1 }.encode())
}