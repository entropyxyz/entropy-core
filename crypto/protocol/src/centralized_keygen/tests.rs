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


// #[test]
// fn test_split_masterkey_into_summands_take_zero() {
// 	let n = 5u16; 
// 	let master_key = Scalar::<Secp256k1>::random();
// 	let result = split_masterkey_into_summands(&master_key, n.into()).map_err(|e| e);
// 	println!("result: {:?}", result);
// 	// let expected = Err::<Result<Vec<Scalar::<Secp256k1>>, anyhow::Error>>(anyhow!("master_key is zero"));
// 	let expected = Err::<Vec<Scalar::<Secp256k1>>, anyhow::Error>(anyhow!("master_key is zero"));
// 	assert_eq!(expected, result);
// }