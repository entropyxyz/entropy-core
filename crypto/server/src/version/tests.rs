use super::api::VERSION;
use crate::helpers::tests::{initialize_test_logger, setup_client};
use kvdb::clean_tests;
use serial_test::serial;
#[tokio::test]
#[serial]
async fn version() {
    initialize_test_logger();
    clean_tests();
    setup_client().await;

    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:3001/version").send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), VERSION.to_string());

    clean_tests();
}
