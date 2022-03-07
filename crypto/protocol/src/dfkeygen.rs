// use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
// use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
//     KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys,
// };
// use curv::cryptographic_primitives::secret_sharing::feldman_vss::{SecretShares, VerifiableSS};
// use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};


// pub fn dfkeygen() {

// 	// define parameters
// 	let t = 1u16;
// 	let n = 5u16; 
// 	// trying_secret_sharing(t,n);

// 	let master_key = Scalar::<Secp256k1>::random();
// 	let u = split_masterkey_into_summands(&master_key, n.into());
// 	assert_eq!(master_key, u.iter().sum());
// 	println!("assertion ok");
// 	println!("master_key: {:?}", &master_key);
// 	let x: Scalar::<Secp256k1> = u.iter().sum();
// 	println!(" u: {:?}", x);
// 	assert_eq!(master_key, x);

// 	// u.iter().sum::Scalar::<Secp256k1>()
// }

// /// takes a scalar master_key and returns a Vec<Scalar> vec such that 
// /// vec.iter().sum() == master_key
// fn split_masterkey_into_summands(master_key: &Scalar::<Secp256k1>, n: usize) -> Vec<Scalar::<Secp256k1>> {
// 	let mut u: Vec<Scalar::<Secp256k1>> = Vec::with_capacity(n);

// 	let mut u_0 = master_key.clone();
// 	for i in 1..n {
// 		let tmp = Scalar::<Secp256k1>::random();
// 		if tmp == Scalar::<Secp256k1>::zero() { //zero
// 			// start all over again
// 			return split_masterkey_into_summands(master_key, n);
// 		}
// 		u_0 = u_0 - &tmp;
// 		// u[i] = tmp;
// 		u.push(tmp);
// 	}
// 	if u_0 == Scalar::<Secp256k1>::zero() {  //zero
// 		// start all over again
// 		return split_masterkey_into_summands(master_key, n);
// 	} 
// 	// u[0] = u_0;
// 	u.push(u_0);
// 	u
// }

// fn sum_vec_scalar(v:Vec<Scalar::<Secp256k1>>) -> Scalar::<Secp256k1> {
// 	// let mut sum Scalar::<Secp256k1>::zero()
// 	v.iter().sum()
// }

// fn trying_secret_sharing(t:u16,n:u16) {
// 	// // Proof of Concept: create one key!
// 	// // /////////////////////////////////
// 	// // create key; this creates paillier-keys, etc. 
// 	// let mut party_keys = Keys::create(1 as usize);
// 	// let secret = Scalar::<Secp256k1>::random();
// 	// let pk = Point::generator() * &secret;

// 	// // swap vss-keyshares into the party_keys
// 	// party_keys.u_i = secret.clone();
// 	// party_keys.y_i = pk;

// 	// create a set of keys!
// 	// /////////////////////
// 	let secret = Scalar::<Secp256k1>::random();
// 	let (vss_scheme, secret_shares) =
//             // VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
//             VerifiableSS::share(t, n, &secret);

// 	// let mut party_keys_vec:Vec<Keys>; // error: use of possibly uninitialized variable
// 	let mut party_keys_vec: Vec<Keys> = Vec::with_capacity(n.into());

// 	// let x = secret_shares.shares;
// 	// let x = ops::deref(secret_shares.shares);
// 	for (i, share) in secret_shares.shares.into_iter().enumerate() {
// 		println!("i, share: {} {:?}", i, share);
// 		let mut party_keys = Keys::create(i);
// 		let pk = Point::generator() * &share;

// 		party_keys.u_i = share;
// 		party_keys.y_i = pk;
// 		party_keys_vec.push(party_keys);
// 		println!("party_keys: {} {:?} {:?} {:?}", i, &party_keys_vec[i].party_index, &party_keys_vec[i].u_i, &party_keys_vec[i].y_i);
// 	}
// }
// pub trait Entropy<E: curv::elliptic::curves::Curve> {
// 		fn get_share(&self) -> &Vec<Scalar<E>>;
// }
// impl <E: Curve> Entropy<E> for SecretShares<E> {
// 	fn get_share(&self) -> &Vec<Scalar<E>> {
// 		&self.shares		
// 	}
// }