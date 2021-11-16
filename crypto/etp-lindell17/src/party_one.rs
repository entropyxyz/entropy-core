//use k256::arithmetic::scalar::Scalar; // arithmetic is non-public module
// use k256::ecdsa::SigningKey;
pub use k256::{self, Scalar};
use crate::{cryptoerror}; //::{self, CryptoError}; // SecretKey
use crate::common::SecretKey;



// enum _ByokError {
//     ArithmeticError,
// }

fn random_one_third_scalar() -> k256::Scalar {
    // generate a random key
    let rng = rand::thread_rng();
    let sk = k256::SecretKey::random(rng);

    // Right now, sk is in \mathbb{z_p}, p being the order of the curve secp256k.
    // For Paillier encryption to work, we want sk to be in  \mathbb{z_{p/3}}, however.
    // To do that, we convert it to bytes and divide the first u8 by 4 (doing a right-shift)
    // The result is in {0..2^254-1} \subset \mathbb{z_{p/3}}

    // RustCryto GenericArray<> uses Big-Endians!
    let mut sk_bytes = sk.to_bytes();
      
    sk_bytes[0] = sk_bytes[0] >> 2;   

    //we convert the GenericArray into a Scalar, so that we can do arithmetic computations with it
    let sk_scalar = k256::Scalar::from_bytes_reduced(&sk_bytes);

    // check if sk_scalar is zero. if it is, run BYOK again to generate a new randomly generated key.
    // is_zero returns Subtle::Choice, so convert to boolean
    if sk_scalar.is_zero().into() {
        return random_one_third_scalar();
    }
    sk_scalar
}

// split Bob's share into shards 
fn split_keyshare(share: SecretKey) -> cryptoerror::Result<SecretKey> {
    // ToDo: later add Shamir's Secret Sharing or something similar
    Ok(share)
}


pub trait EtpCrypto {
    fn split_keyshare(&self) -> cryptoerror::Result<SecretKey>;
    fn byok_share_generation( &self // master_key: &SecretKey,
         ) -> cryptoerror::Result<(SecretKey, SecretKey)>;
}

//Besser:   //ToDo
impl EtpCrypto for SecretKey {
    fn split_keyshare(&self) -> cryptoerror::Result<SecretKey> {
        // ToDo: later add Shamir's Secret Sharing or something similar

        let rng = rand::thread_rng();
        let sk = k256::SecretKey::random(rng);        
        Ok(sk)
    }


fn byok_share_generation(
    &self
    //master_key: &SecretKey,
//) -> k256::elliptic_curve::Result<(SecretKey, SecretKey)> {
 ) -> cryptoerror::Result<(SecretKey, SecretKey)>{
    //fn BYOK_generation(master_key: SecretKey) -> CryptoError::Result<u32>{

    // Generate a random key in Range [1..2^253] \subset [1..ORDER/3]
    // This constraint is required by the Paillier Encryption System in order to keep 
    // the Paillier keys only be 5 times the length of the order of the elliptic curve 
    // group (and not 8 times). 
    // This greatly increases computation time, see https://eprint.iacr.org/2017/552 page 14. 
    let alice_scalar = random_one_third_scalar();

    let alice_inverse = alice_scalar.invert();
    // ToDo: how can we unwrap the CtOption in a nice way?
    if alice_inverse.is_none().into() {
        // if the inversion did not work ( this will be the case if alice_scalar == k256::Scalar::zero() ),
        //then run BYOK again to create a new key.
        //return byok_share_generation(master_key);
        return self.byok_share_generation();
    }
    // unwrap() is OK, because we checked the CtOption above.
    let alice_inverse = alice_inverse.unwrap();
    
    // convert master_key to Scalar so we can do arithmetic computation on it
    let master_scalar = Scalar::from_bytes_reduced(&self.to_bytes());

    // construct Bob's SecretKey-Share as in https://www.notion.so/entropyxyz/BYOK-7b066c532d184460b1dd80dea3157006
    // construct Bob's SecretKey-Share as in the Entropy-PinkPaper
    let bob_scalar = master_scalar.mul(&alice_inverse);

    // convert Scalars to SecretKey
    let alice = SecretKey::from_bytes(alice_scalar.to_bytes())?;
    let bob = SecretKey::from_bytes(bob_scalar.to_bytes())?;

    // split Bob's share into shards 
	let bob = split_keyshare(bob)?;

    Ok((alice, bob))
}

}
// for testing
// fn main() -> k256::elliptic_curve::Result<()> {
//     let master_key = SecretKey::random(rand::thread_rng());
//     let (alice, bob) = byok_share_generation(&master_key)?;
//     println!("alice: {:?}", alice);
//     println!("bob: {:?}", bob);
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;

    // test alice * bob = master
    #[test]
    fn test_byok_mul() {
        // generate random SecretKey
        let master_key = SecretKey::random(rand::thread_rng());

        // do BYOK-keygeneration to receive Alice's and Bob's SecretKey-Shares
        let (alice, bob) = master_key.byok_share_generation().unwrap();
        println!("alice: {:?}", &alice.to_bytes());
        println!("bob: {:?}", &bob.to_bytes());

        // convert alice's and bob's SecretKey to Scalar so that we can do arithmetics
        // then multiply them
        let product = alice.to_secret_scalar().mul(&bob.to_secret_scalar());

        // compare product to the master SecretKey
        assert_eq!(
            k256::Scalar::from_bytes_reduced(&master_key.to_bytes()),
            product
        );
    }

    // test alice < ORDER/3
    #[test]
    fn test_byok_keysize() {}
}
