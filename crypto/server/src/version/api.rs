/// Returns the version and commit data
pub async fn version() -> String {
    format!("{}, {}", env!("VERGEN_GIT_DESCRIBE"), env!("VERGEN_GIT_SHA"))
}
