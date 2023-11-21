use axum::http::StatusCode;

/// For checking the health of the TSS
pub async fn healthz() -> StatusCode {
    StatusCode::OK
}
