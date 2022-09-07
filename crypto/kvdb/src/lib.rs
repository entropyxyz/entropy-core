pub mod encrypted_sled;
pub mod kv_manager;

pub fn get_db_path() -> String { "test_db".to_string() }

pub fn clean_tests() {
  let result = std::fs::remove_dir_all(get_db_path());
  //   assert!(result.is_ok());
}
