//! [sled_bindings] tests

use super::{
	error::InnerKvError::LogicalErr,
	sled_bindings::{handle_exists, handle_get, handle_put, handle_reserve},
	types::{KeyReservation, DEFAULT_RESERVE},
};
use crate::encrypted_sled;
use serial_test::serial;
use std::fs;
// testdir creates a test directory at $TMPDIR.
// Mac: /var/folders/v4/x_j3jj7d6ql4gjdf7b7jvjhm0000gn/T/testdir-of-$(USER)
// Linux: /tmp
// Windows: /data/local/tmp
// https://doc.rust-lang.org/std/env/fn.temp_dir.html#unix
use tofn::sdk::api::deserialize;

fn clean_up(kv: encrypted_sled::Db) {
	assert!(kv.flush().is_ok());
	std::fs::remove_dir_all(get_db_path()).unwrap();
}

pub fn open_with_test_password() -> encrypted_sled::Result<encrypted_sled::Db> {
	encrypted_sled::Db::open(get_db_path(), encrypted_sled::get_test_password())
}

#[test]
#[serial]
fn reserve_success() {
	let kv = open_with_test_password().unwrap();
	let kv_name = get_db_path();
	let key: String = "key".to_string();
	assert_eq!(handle_reserve(&kv, key.clone()).unwrap(), KeyReservation { key: key.clone() });

	// check if default value was stored
	// get bytes
	let default_reserv = kv.get(&key).unwrap().unwrap();
	// convert to value type
	assert!(default_reserv == DEFAULT_RESERVE);

	clean_up(kv);
}

#[test]
#[serial]
fn reserve_failure() {
	let kv = open_with_test_password().unwrap();
	let kv_name = get_db_path();

	let key: String = "key".to_string();
	handle_reserve(&kv, key.clone()).unwrap();
	// try reserving twice
	let err = handle_reserve(&kv, key).err().unwrap();
	assert!(matches!(err, LogicalErr(_)));
	clean_up(kv);
}

#[test]
#[serial]
fn put_success() {
	let kv = open_with_test_password().unwrap();
	let kv_name = get_db_path();

	let key: String = "key".to_string();
	handle_reserve(&kv, key.clone()).unwrap();

	let value: String = "value".to_string();
	assert!(handle_put(&kv, KeyReservation { key }, value).is_ok());

	clean_up(kv);
}

#[test]
#[serial]
fn put_failure_no_reservation() {
	let kv = open_with_test_password().unwrap();
	let kv_name = get_db_path();

	let key: String = "key".to_string();

	let value: String = "value".to_string();
	// try to add put a key without reservation and get an error
	let err = handle_put(&kv, KeyReservation { key: key.clone() }, value).err().unwrap();
	assert!(matches!(err, LogicalErr(_)));
	// check if key was inserted
	assert!(!kv.contains_key(&key).unwrap());

	clean_up(kv);
}

#[test]
#[serial]
fn put_failure_put_twice() {
	let kv = open_with_test_password().unwrap();
	let kv_name = get_db_path();

	let key: String = "key".to_string();
	let value = "value".to_string();
	let value2 = "value2".to_string();

	handle_reserve(&kv, key.clone()).unwrap();
	handle_put(&kv, KeyReservation { key: key.clone() }, value.clone()).unwrap();

	let err = handle_put(&kv, KeyReservation { key: key.clone() }, value2).err().unwrap();
	assert!(matches!(err, LogicalErr(_)));

	// check if value was changed
	// get bytes
	let bytes = kv.get(&key).unwrap().unwrap();
	// convert to value type
	let v: String = deserialize(&bytes).unwrap();
	// check current value with first assigned value
	assert!(v == value);

	clean_up(kv);
}

#[test]
#[serial]
fn get_success() {
	let kv = open_with_test_password().unwrap();
	let kv_name = get_db_path();

	let key: String = "key".to_string();
	let value = "value";
	handle_reserve(&kv, key.clone()).unwrap();
	handle_put(&kv, KeyReservation { key: key.clone() }, value).unwrap();
	let res = handle_get::<String>(&kv, key);
	assert!(res.is_ok());
	let res = res.unwrap();
	assert_eq!(res, value);

	clean_up(kv);
}

#[test]
#[serial]
fn get_failure() {
	let kv = open_with_test_password().unwrap();
	let kv_name = get_db_path();

	let key: String = "key".to_string();
	let err = handle_get::<String>(&kv, key).err().unwrap();
	assert!(matches!(err, LogicalErr(_)));

	clean_up(kv);
}

#[test]
#[serial]
fn test_exists() {
	let kv = open_with_test_password().unwrap();
	let kv_name = get_db_path();

	let key: String = "key".to_string();
	let value: String = "value".to_string();

	// exists should fail
	let exists = handle_exists(&kv, &key);
	assert!(exists.is_ok());
	assert!(!exists.unwrap()); // assert that the result is false

	// reserve key
	let reservation = handle_reserve(&kv, key.clone()).unwrap();

	// exists should succeed
	let exists = handle_exists(&kv, &key);
	assert!(exists.is_ok());
	assert!(exists.unwrap()); // check that the result is true

	// put key
	handle_put(&kv, reservation, value).unwrap();

	// exists should succeed
	let exists = handle_exists(&kv, &key);
	assert!(exists.is_ok());
	assert!(exists.unwrap()); // check that the result is true

	// remove key
	let remove = kv.remove(key.clone());
	assert!(remove.is_ok());

	// exists should succeed
	let exists = handle_exists(&kv, &key);
	assert!(exists.is_ok());
	assert!(!exists.unwrap()); // check that the result is false
}

pub fn get_db_path() -> String {
	let root = project_root::get_project_root().unwrap();
	format!("test_db/{}", root.to_string_lossy())
}
