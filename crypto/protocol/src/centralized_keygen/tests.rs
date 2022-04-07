use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use anyhow::anyhow;

use super::keygen::*;

/// testing if split_masterkey_into_summands() returns a vector u such that 
/// - u.len() equals n
/// - u.iter().sum equals master_key
#[test]
fn test_split_masterkey_into_summands() {
	for n in 1..=5 {
		let master_key = Scalar::<Secp256k1>::random();
		let u = split_masterkey_into_summands(&master_key, n).unwrap();
		assert_eq!(master_key, u.iter().sum());
		assert_eq!(u.len(), n);
	}
}

/// Testing if n=0 returns Err
#[test]
fn test_split_masterkey_into_summands_wrong_n() {
	let master_key = Scalar::<Secp256k1>::random();
	let result = split_masterkey_into_summands(&master_key, 0);
	let expected = Err(KeygenError::InvalidParameterNumParties{n:0});
	assert_eq!(result, expected);
}

/// testing if input of master_key = zero() returns Err
#[test]
fn test_split_masterkey_into_summands_taking_zero() {
	let n = 5u16; 
	let master_key = Scalar::<Secp256k1>::zero();
	let result = split_masterkey_into_summands(&master_key, n.into()).map_err(|e| e);
	let expected = Err(KeygenError::SecretKeyEqualsZero);
	assert_eq!(expected, result);
}

// delete this later during cleanup
#[test]
fn dummy() {
	let y_vec = vec![1,20,300,4000];
	let (head, tail) = y_vec.split_at(1);
	let y = tail.iter().fold(head[0].clone(), |acc, x| acc + x);
	println!("y_vec {:?}", y_vec);
	println!("y     {:?}", y);
}

#[test]
fn test_verify_local_keys_correctness() {
	// ToDo: 
	// check if g*masterkey = y = product(y_i) = g*(sum(ui)) = sum(y_vec) = sum(y_i)  

}