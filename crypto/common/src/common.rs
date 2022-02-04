


use codec::{Decode, Encode};
use scale_info::TypeInfo;

/// RegistrationMessage holds the information sent by the User to the extropy-network during account-registration
#[derive(Clone, Encode, Decode, Debug, PartialEq, TypeInfo)] 
pub struct RegistrationMessage {
    // ToDo: TypeInfo marco only works for basic types out of the box. 
    // Out of the box it does not work for types like SecretKey or PublicKey
    // TypeInfo needs to be implemented for these types. 
    // see https://github.com/Entropyxyz/entropy-core/issues/29

	// /// Session ID/nonce. Check that this ID has not beed used before
	// /// This will be 0 for account creation. 
	// sid: u32, 
	// // PublicKey of the account of the user
	//pub pub_group_key: PublicKey, 
	// // PublicKey of the user's secret keyshare
	//pub user_public_key: PublicKey,
	// // ConstraintSet: alternativeley, a default ConstraintSet will always be loaded at account creation
	pub keyshards: u128, /* this will be Vec<FieldElements>, where FieldElements are BigInt mod
	                      * Order, i.e. \mathbb{Z_q} */
	pub test: u128,
}

/// body of a signature generation request by the user to the entropy network
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)] 
pub struct SigRequest {
    // TypeInfo marco lets parity-scale-codec .encode() the fields in this struct
	// only works for basic types out of the box. 
    // Out of the box it does not work for types like SecretKey or PublicKey
    // TypeInfo needs to be implemented for these types. 
    // see https://github.com/Entropyxyz/entropy-core/issues/29
	//
	// hash of message to be signed
	pub hash_msg: u128, 
	// dummy-content
	pub test: u128,
	// /// Session ID/nonce. Check that this ID has not beed used before
	// sid: u32, 	
	// /// signature to authenticate the user
	// sig: u32,
}