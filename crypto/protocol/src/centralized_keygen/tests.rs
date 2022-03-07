use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use anyhow::anyhow;

use super::keygen::*;

#[test]
fn test_split_masterkey_into_summands() {
	let n = 5u16; 
	let master_key = Scalar::<Secp256k1>::random();
	let u = split_masterkey_into_summands(&master_key, n.into()).unwrap();
	assert_eq!(master_key, u.iter().sum());
}

#[test]
fn test_split_masterkey_into_summands_taking_zero() {
	let n = 5u16; 
	let master_key = Scalar::<Secp256k1>::zero();
	let result = split_masterkey_into_summands(&master_key, n.into()).map_err(|e| e);
	let expected = Err(KeygenError::SecretKeyEqualsZero);
	assert_eq!(expected, result);
}