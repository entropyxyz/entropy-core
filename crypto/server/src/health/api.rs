use axum::http::StatusCode;

#[tracing::instrument]
pub async fn healthz() -> StatusCode {
    tracing::info!("Sucesfully performed health check");
    StatusCode::OK
}
