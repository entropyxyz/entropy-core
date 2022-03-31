use anyhow::{anyhow, Result};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{Keygen, LocalKey};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    generate_h1_h2_N_tilde, KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, SharedKeys
};
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{SecretShares, VerifiableSS};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};
use zk_paillier::zkproofs::DLogStatement;

use std::{
	fs::{create_dir_all, File},
	io::{BufWriter, Write},
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum KeygenError {
	/// SecretKey equals Zero
	#[error("SecretKey equals Zero")]
	SecretKeyEqualsZero,
	#[error("Invalid parameter n: {n:?}")]
	InvalidParameterNumParties{n: usize},
}


pub fn centralized_keygen() -> Result<()> {
	// ToDo: 
	// - u16 -> usize?? max_element_usize might be larger than the order of our curve?? 

	// define parameters
	let t = 1u16;
	let n = 3u16; 

	// in BYOK master_key could be an input parameter
	let master_key = Scalar::<Secp256k1>::random();

	// create n random Scalars such that sum(Scalars) = master_key
	let u = split_masterkey_into_summands(&master_key, n.into())?;
	assert_eq!(master_key, u.iter().sum());

	// vss-share each summand and add the results element-wise
	let (vss_vec, x) = share_summands_and_add_elementwise(u,t.into(), n.into())?;
	// for (i,ele) in x.iter().enumerate() {
	// 	println!("x: {} {:?}", i, ele);
	// }

	// objects to collect and reorganize data
	let mut localkeys: Vec<LocalKey<Secp256k1>> = Vec::with_capacity(n.into());
	let mut paillier_key_vec: Vec<EncryptionKey> = Vec::with_capacity(n.into());
	let mut paillier_dk_vec: Vec<DecryptionKey> = Vec::with_capacity(n.into());
	let mut pk_vec: Vec<Point<Secp256k1>> = Vec::with_capacity(n.into());
	let mut h1_h2_n_tilde_vec: Vec<DLogStatement> = Vec::with_capacity(n.into());
	
	// assemble components of the LocalKey's that are the same for all parties: 
	// ToDo: use .izip()
	for i in 0..usize::from(n) {
		// paillier
		// ToDo: use safe primes in production!
		// this takes about 20*n seconds
        // let (ek, dk) = Paillier::keypair_safe_primes().keys();
        let (ek, dk) = Paillier::keypair().keys();
		paillier_key_vec.push(ek);
		paillier_dk_vec.push(dk);

		// pk_vec
		pk_vec.push(Point::generator() * &x[i]);

		// h1_h2_n_tilde
		h1_h2_n_tilde_vec.push(get_d_log_statement());
	}

	
	let y = Point::generator() * &master_key;
	// assemble components that are unique for each party and then fill LocalKey
	for i in 0usize..usize::from(n) {
		let keys_linear = SharedKeys {y: y.clone(), x_i: x[i].clone()};

		//let num = usize::from(n);
		localkeys.push(LocalKey{
			paillier_dk: paillier_dk_vec[i].clone(),
			pk_vec: pk_vec.clone(), 
			keys_linear,
			paillier_key_vec: paillier_key_vec.clone(), 
			y_sum_s: y.clone(),
			h1_h2_n_tilde_vec: h1_h2_n_tilde_vec.clone(),
			vss_scheme: vss_vec[i].clone(), 
			// i: std::convert::TryFrom::try_from(i+1).map_err(KeygenError::InvalidParameterNumParties{n: num})?,
			// ToDo DF: map error to KeygenError::InvalidParameterNumParties{n}
			i: std::convert::TryFrom::try_from(i+1)?,
			t,
			n,
		});
	}	

	localkeys.print_to_file("new_keys")?;
	Ok(())
}

fn get_d_log_statement() -> DLogStatement {
	let (N_tilde, h1, h2, _xhi, _xhi_inv) = generate_h1_h2_N_tilde();
	DLogStatement {
		N: N_tilde,
		g: h1,
		ni: h2,
	}
}

trait PrintToFile {
	fn print_to_file(&self, path: &str) -> Result<()>;
}

impl PrintToFile for Vec<LocalKey<Secp256k1>> {
	/// writes Vec<LocalKey<Secp256k1>> to files. 
	/// takes:
	/// - path: folder that the LocalKeys will be stored in. 
	///   path = "new_keys/" will create ./new_keys/local-share1.json, ./new_keys/local-share2.json, etc. 
	fn print_to_file(&self, path: &str) -> Result<()> {
		for (i, localkey) in self.iter().enumerate() {
			let file = format!("{}/local-share{}.json",&path, i+1);
			std::fs::create_dir_all(path)?;
			let file = File::create(&file)?;
			let mut writer = BufWriter::new(&file);
			serde_json::to_writer(&mut writer, localkey)?;
			writer.flush()?;
			println!("LocalKey stored: {:?}", &file);

		}	
	Ok(())

	}
}

// struct Summands {
// 	Vec<Scalar::<Secp256k1>>
// };

// impl mytrait for Vec<Scalar::<Secp256k1>> {
	/// each summand is vss-shared and the shares are added element-wise over all summands
	fn share_summands_and_add_elementwise(key_summands: Vec<Scalar::<Secp256k1>> ,t: u16, n: u16 ) 
	-> Result<(Vec<VerifiableSS<Secp256k1>>, Vec<Scalar::<Secp256k1>>), KeygenError> {

		if n < 1 {
			let num:usize = n.into();
			return Err(KeygenError::InvalidParameterNumParties{n: num});
		}	
		//let mut res = Vec::with_capacity(n.into()); 

		// create vector with n elements, each element is zero
		let mut x: Vec<Scalar::<Secp256k1>> = Vec::with_capacity(n.into());
		let mut vss_vec: Vec<VerifiableSS<Secp256k1>> = Vec::with_capacity(n.into());
		for _i in 0..n {
			x.push(Scalar::<Secp256k1>::zero());
		}

		// vss-share each summand 
		for summand in key_summands {
			let (vss_scheme, secret_shares) =
			VerifiableSS::share(t, n, &summand);

			//ToDo DF: add vectors element-wise without clone
			// create copy of x, because ownership is preventing me from element-wise-adding x with secret_shares.shares
			// i.e. x[i] = x[i] + secret_shares.shares[i]
			let x_clone = x.clone();

			for (i, xval) in x_clone.into_iter().enumerate() {
				x[i] = xval + &secret_shares.shares[i];
			}
			vss_vec.push(vss_scheme);
		}
		Ok((vss_vec, x))
	}
// }

/// takes a scalar master_key and returns a Vec<Scalar> vec such that 
/// vec.iter().sum() == master_key
pub(crate) fn split_masterkey_into_summands(master_key: &Scalar::<Secp256k1>, n: usize) -> Result<Vec<Scalar::<Secp256k1>>, KeygenError> {
	if n < 1 {
		return Err(KeygenError::InvalidParameterNumParties{n});
	}
	if master_key == &Scalar::<Secp256k1>::zero() {
		return Err(KeygenError::SecretKeyEqualsZero);
	}
	let mut u: Vec<Scalar::<Secp256k1>> = Vec::with_capacity(n);

	let mut u_0 = master_key.clone();
	// create n-1 random Scalar::<Secp256k1>
	// the n-th is equal to master_key.minus(sum_of_n-1_Scalars)
	for _i in 1..n {
		let tmp = Scalar::<Secp256k1>::random();
		if tmp == Scalar::<Secp256k1>::zero() {
			// Invalid value. Start all over again
			return split_masterkey_into_summands(master_key, n);
		}
		u_0 = u_0 - &tmp;
		u.push(tmp);
	}
	if u_0 == Scalar::<Secp256k1>::zero() {
			// Invalid value. Start all over again
		return split_masterkey_into_summands(master_key, n);
	} 
	u.push(u_0);
	Ok(u)
}

// this fn can be deleted later
fn _secret_sharing_proof_of_concept(t:u16,n:u16) {
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
	let (_vss_scheme, secret_shares) =
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
}

// pub trait Entropy<E: curv::elliptic::curves::Curve> {
// 		fn get_share(&self) -> &Vec<Scalar<E>>;
// }
// impl <E: Curve> Entropy<E> for SecretShares<E> {
// 	fn get_share(&self) -> &Vec<Scalar<E>> {
// 		&self.shares		
// 	}
// }