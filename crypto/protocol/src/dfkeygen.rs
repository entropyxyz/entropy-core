use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys,
};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{SecretShares, VerifiableSS};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};


pub fn dfkeygen() {

	// define parameters
	let t = 1;
	let n = 5; 

	// // Proof of Concept: create one key!
	// // /////////////////////////////////
	// // create key; this creates paillier-keys, etc. 
	// let mut party_keys = Keys::create(1 as usize);
	// let secret = Scalar::<Secp256k1>::random();
	// let pk = Point::generator() * &secret;

	// // swap vss-keyshares into the party_keys
	// party_keys.u_i = secret.clone();
	// party_keys.y_i = pk;

	
	// create a set of keys!
	// /////////////////////
	let secret = Scalar::<Secp256k1>::random();
	let (vss_scheme, secret_shares) =
            // VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
            VerifiableSS::share(t, n, &secret);

	// let mut party_keys_vec:Vec<Keys>; // error: use of possibly uninitialized variable
	let mut party_keys_vec: Vec<Keys> = Vec::with_capacity(n.into());

	// let x = secret_shares.shares;
	// let x = ops::deref(secret_shares.shares);
	for (i, share) in secret_shares.shares.into_iter().enumerate() {
		println!("i, share: {} {:?}", i, share);
		let mut party_keys = Keys::create(i);
		let pk = Point::generator() * &share;

		party_keys.u_i = share;
		party_keys.y_i = pk;
		party_keys_vec.push(party_keys);
		println!("party_keys: {} {:?} {:?} {:?}", i, &party_keys_vec[i].party_index, &party_keys_vec[i].u_i, &party_keys_vec[i].y_i);
		
	}
	

	// .deref()
}

pub trait Entropy<E: curv::elliptic::curves::Curve> {
		fn get_share(&self) -> &Vec<Scalar<E>>;
}
impl <E: Curve> Entropy<E> for SecretShares<E> {
	fn get_share(&self) -> &Vec<Scalar<E>> {
		&self.shares		
	}
}