use axum::http::StatusCode;

pub mod version {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}
/// For checking the health of the TSS
pub async fn healthz() -> StatusCode {
    StatusCode::OK
}
/// Returns the version and commit data
pub async fn version() -> String {
    format!("{}, {}", version::commit_date(), version::semver())
}