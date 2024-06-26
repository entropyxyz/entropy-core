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

use super::{kv::EncryptedDb, Password};
use crate::{clean_tests, encrypted_sled::Db, get_db_path};

fn setup_db(require_password: bool) -> Db {
    let db = if !require_password {
        EncryptedDb::open(get_db_path(true), get_test_password())
    } else {
        EncryptedDb::open(get_db_path(true), Password::from("super-secret password."))
    };
    assert!(db.is_ok());
    db.unwrap()
}

#[test]
#[serial]
fn test_encrypted_sled() {
    let db = setup_db(false);

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
fn test_use_existing_salt() {
    let db = setup_db(false);
    let db_path = get_db_path(true);
    drop(db);
    // open existing db
    assert!(EncryptedDb::open(db_path, get_test_password()).is_ok());
    clean_tests();
}

#[test]
#[serial]
fn test_password() {
    let db = setup_db(true);
    let db_path = get_db_path(true);

    drop(db);

    // try to open the kv store using a different password
    let db = EncryptedDb::open(
        db_path,
        Password::from("super-secret password!"), // replace '.' with '!'
    );
    assert!(matches!(db, Err(super::result::EncryptedDbError::WrongPassword)));
    clean_tests();
}

#[test]
#[serial]
fn test_large_input() {
    let db = setup_db(false);

    let large_value = vec![0; 100000];
    let res = db.insert("key", large_value.clone()).unwrap();
    assert!(res.is_none());

    let res = db.get("key").unwrap();
    assert_eq!(res, Some(sled::IVec::from(large_value)));
    clean_tests();
}

pub fn get_test_password() -> Password {
    crate::encrypted_sled::PasswordMethod::NoPassword.execute().unwrap()
}
