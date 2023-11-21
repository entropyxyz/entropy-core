pub mod version {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}

/// Returns the version and commit data
pub async fn version() -> String {
    format!("{}, {}", version::commit_date(), version::semver())
}
