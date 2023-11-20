use axum::http::StatusCode;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn healthz() -> StatusCode {
    StatusCode::OK
}

pub async fn version() -> String {
    VERSION.to_string()
}