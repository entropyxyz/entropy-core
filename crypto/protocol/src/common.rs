/// common structs etc, shared among the substrate-blockchain-code and the crypto-code
/// 
/// 

use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// body of a signature generation request by the user to the entropy network
#[derive(Clone, Encode, Decode, Debug, PartialEq, TypeInfo)] 
pub struct RequestSigBody {
    // TypeInfo marco lets parity-scale-codec .encode() the fields in this struct
	// only works for basic types out of the box. 
    // Out of the box it does not work for types like SecretKey or PublicKey
    // TypeInfo needs to be implemented for these types. 
    // see https://github.com/Entropyxyz/entropy-core/issues/29
	//
	// dummy-content
	pub keyshards: u128, 
	// dummy-content
	pub test: u128,

}