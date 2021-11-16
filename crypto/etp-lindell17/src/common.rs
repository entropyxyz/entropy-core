// Code that is shared by party_one and party_two
// i.e. messages sent from one to the other and structs contained in those messages

pub type SecretKey = k256::SecretKey;
pub type PublicKey = k256::PublicKey;

#[derive(Clone, Debug)] // , PartialEq
pub struct RegistrationMessage {
    pub pub_group_key: PublicKey, // needs new type... k256::PublicKey
    pub keyshards: u128,           // this will be Vec<FieldElements>, where FieldElements are BigInt mod Order, i.e. \mathbb{Z_q}
    pub test: u128,
    // ConstraintSet: alternativeley, a default ConstraintSet will always be loaded at account creation
}