/// Returns the version and commit data
#[tracing::instrument]
pub async fn version() -> String {
    format!("{}-{}", env!("VERGEN_RUSTC_SEMVER"), env!("VERGEN_GIT_DESCRIBE"))
}
