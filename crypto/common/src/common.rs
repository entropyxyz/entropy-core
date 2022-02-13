/// common structs etc, shared among the substrate-blockchain-code and the crypto-code
/// 
/// 

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
	// /// PublicKey of the user's master-key
	//pub pub_group_key: PublicKey, 
	// /// PublicKey of the user's secret keyshare
	//pub user_public_key: PublicKey,
	// /// ToDo testnet: polynomial commitments of the polynomial that created the keyshares
	// /// These are necessary so that nodes can verify their keyshare
	// poly_commitments: u16;
	// // ToDo testnet: ConstraintSet: alternativeley, a default ConstraintSet will always be loaded at account creation
	pub keyshards: u128, /* this will be Vec<FieldElements>, where FieldElements are BigInt mod
	                      * Order, i.e. \mathbb{Z_q} */
	pub test: u128,
}

/// The response message that a node sends to the User in response to calling the relayer::register() extrinsic.
pub struct RegistrationResponse {
	// ToDo_DF: what Data goes into here?
	/// list of endpoints of all nodes that the user sends the keyshares to. 
	// ToDo: make this a vec<(endpoint, encryption-key)> etc. 
	signing_nodes: u16,
	comm_manager: u16,
}

/// body of a signature generation request by the user to the entropy network
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)] 
pub struct SigRequest {
    // TypeInfo marco lets parity-scale-codec .encode() the fields in this struct
	// only works for basic types out of the box. 
    // Out of the box it does not work for types like SecretKey or PublicKey
    // TypeInfo needs to be implemented for these types. 
    // see https://github.com/Entropyxyz/entropy-core/issues/29
	
	/// Signature_ID. this is a hash of the message to be signed
	pub sig_id: u128, 
	/// Session ID/nonce. Check that this ID has not beed used before
	nonce: u32, 	
	/// signature to authenticate the user
	signature: u32,
}

#[derive(Clone, Encode, Debug, Decode, Eq, PartialEq, TypeInfo)] 
pub struct SigResponse {
	/// the randomly chosen signing-nodes that take part in the sig-generation
	/// possible identifiers: endpoint address or some PublicKey (which one?)
	pub signing_nodes: u16,
	/// endpoint of the Communication manager
	pub com_manager: u16, 
}

/// The message sent from pallets::propagation::post() to the signing-client. 
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)] 
pub struct OCWMessage {
	// pub thing: u128,
	pub sig_request: SigRequest,
	// ToDo_DF: 
	// /// block_author
	// block_author	
}