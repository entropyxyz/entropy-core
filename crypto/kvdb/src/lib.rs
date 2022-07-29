pub mod encrypted_sled;
pub mod kv_manager;

pub fn get_db_path() -> String {
	let root = project_root::get_project_root().unwrap();
	format!("test_db/{}", root.to_string_lossy())
}

pub fn clean_tests() {
	let result = std::fs::remove_dir_all(get_db_path());
	assert_eq!(result.is_ok(), true);
}
