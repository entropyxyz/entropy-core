mod common;
pub mod cryptoerror;
pub mod party_one;
pub mod party_two;

/// secp256k1 (K-256) secret key.
pub type SecretKey = party_one::SecretKey;
//pub type SecretKey = k256::SecretKey;


// pub type SecretKey = elliptic_curve::SecretKey<Secp256k1>;

// fn main() {
//     party_one::main();

// }
