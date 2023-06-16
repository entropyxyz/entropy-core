use axum::http::StatusCode;
use kvdb::clean_tests;
use serial_test::serial;

use crate::helpers::tests::setup_client;
#[tokio::test]
#[serial]
async fn health() {
    clean_tests();
    setup_client().await;
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:3001/healthz").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    clean_tests();
}
