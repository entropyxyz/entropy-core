use axum::http::StatusCode;
use serial_test::serial;
use super::api::VERSION;

use crate::helpers::tests::{initialize_test_logger, setup_client};

#[tokio::test]
#[serial]
async fn health() {
    initialize_test_logger();
    setup_client().await;

    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:3001/healthz").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}


#[tokio::test]
#[serial]
async fn version() {
    initialize_test_logger();
    setup_client().await;
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:3001/version").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), VERSION.to_string());
}
