use axum::http::StatusCode;

/// For checking the health of the TSS
#[tracing::instrument]
pub async fn healthz() -> StatusCode {
    tracing::info!("Sucesfully performed health check");
    StatusCode::OK
}
