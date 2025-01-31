// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use serial_test::serial;

use super::kv::EncryptedDb;
use crate::{clean_tests, encrypted_sled::Db, get_db_path};

fn setup_db(key: [u8; 32]) -> Db {
    EncryptedDb::open(get_db_path(true), key).unwrap()
}

#[test]
#[serial]
fn test_encrypted_sled() {
    let db = setup_db([1; 32]);

    // insert <key: value> -> returns None
    let res = db.insert("key", "value").unwrap();
    assert!(res.is_none());

    // get <key> -> returns <value>
    let res = db.get("key").unwrap();
    assert_eq!(res, Some(sled::IVec::from("value")));

    // insert <key: value2> -> returns old value <value>
    let res = db.insert("key", "value2").unwrap();
    assert!(res.is_some());

    // get <key: value2> -> returns new value <value2>
    let res = db.get("key").unwrap();
    assert_eq!(res, Some(sled::IVec::from("value2")));

    // get <key1: value2> -> returns None because key1 does not exist
    let res = db.get("key1").unwrap();
    assert!(res.is_none());

    // contains <key> -> returns Some(true) because key exists
    let res = db.contains_key("key").unwrap();
    assert!(res);

    // contains <key1> -> returns None because key1 does not exist
    let res = db.contains_key("key1").unwrap();
    assert!(!res);

    // remove <key> -> returns <value2> because key exists
    let res = db.remove("key").unwrap();
    assert_eq!(res, Some(sled::IVec::from("value2")));

    // remove <key> again -> returns None because key does not exist
    let res = db.remove("key").unwrap();
    assert_eq!(res, None);
    clean_tests();
}

#[test]
#[serial]
fn test_use_existing_key() {
    let db = setup_db([1; 32]);
    let db_path = get_db_path(true);
    drop(db);
    // open existing db
    assert!(EncryptedDb::open(db_path, [1; 32]).is_ok());
    clean_tests();
}

#[test]
#[serial]
fn test_key() {
    let db = setup_db([1; 32]);
    let db_path = get_db_path(true);

    drop(db);

    // try to open the kv store using a different key
    let db = EncryptedDb::open(db_path, [2; 32]);
    assert!(matches!(db, Err(super::result::EncryptedDbError::WrongPassword)));
    clean_tests();
}

#[test]
#[serial]
fn test_large_input() {
    let db = setup_db([1; 32]);

    let large_value = vec![0; 100000];
    let res = db.insert("key", large_value.clone()).unwrap();
    assert!(res.is_none());

    let res = db.get("key").unwrap();
    assert_eq!(res, Some(sled::IVec::from(large_value)));
    clean_tests();
}

#[test]
#[serial]
fn test_import_export_db() {
    let db = setup_db([1; 32]);

    let db_kvs = vec![("key1", "value1"), ("key2", "value2"), ("key3", "value3")];

    for (key, value) in db_kvs.clone() {
        db.insert(key, value).unwrap();
    }

    let db_dump = db.export_encrypted_db();

    // Remove the old db from disk
    clean_tests();
    let new_db = setup_db([1; 32]);

    new_db.import_encrypted_db(db_dump.clone()).unwrap();

    let new_db_dump = db.export_encrypted_db();

    // Check that old and new database dumps are identical
    assert_eq!(db_dump, new_db_dump);

    // Check that original key-value pairs exist in new db
    for (key, value) in db_kvs.clone() {
        assert_eq!(Some(sled::IVec::from(value)), new_db.get(key).unwrap());
    }

    // Now try that again with the wrong encryption key to show that the backup is encrypted
    clean_tests();
    let different_db = setup_db([2; 32]);

    different_db.import_encrypted_db(db_dump.clone()).unwrap();

    // Check that original key-value pairs do not exist in new db
    for (key, _value) in db_kvs {
        assert!(different_db.get(key).is_err());
    }
    clean_tests();
}
