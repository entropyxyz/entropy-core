pub mod encrypted_sled;
pub mod kv_manager;
use std::{fs, path::PathBuf};

pub fn get_db_path(testing: bool) -> String {
    let mut root: PathBuf = std::env::current_dir().expect("could not get home directory");
    root.push(".entropy");
    if testing {
        root.push("testing");
    } else {
        root.push("production");
    }
    root.push("db");
    let result: String = root.clone().display().to_string();
    fs::create_dir_all(root)
        .unwrap_or_else(|_| panic!("could not create database path at: {}", result.clone()));
    result
}

pub fn clean_tests() {
    let _result = std::fs::remove_dir_all(get_db_path(true));
}
