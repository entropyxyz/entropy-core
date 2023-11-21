/// Returns the version and commit data
pub async fn version() -> String {
    format!("{}-{}", env!("VERGEN_RUSTC_SEMVER"), env!("VERGEN_GIT_DESCRIBE"))
}
