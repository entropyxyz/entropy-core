use crate::{SecretKey, PublicKey};

// Code that is shared by party_one and party_two
// i.e. messages sent from one to the other and structs contained in those messages
pub struct RegistrationMessage{
    pub pub_group_key: PublicKey, // needs new type... k256::PublicKey
    pub keyshards: SecretKey, 
    pub test: u128,
    // ConstraintSet: alternativeley, a default ConstraintSet will always be loaded at account creation
}