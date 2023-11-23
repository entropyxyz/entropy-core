use axum::http::StatusCode;

/// For checking the health of the TSS
#[tracing::instrument]
pub async fn healthz() -> StatusCode {
    StatusCode::OK
}
