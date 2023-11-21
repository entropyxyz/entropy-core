use serial_test::serial;

use crate::helpers::tests::{initialize_test_logger, setup_client};

#[tokio::test]
#[serial]
async fn version_test() {
    initialize_test_logger();
    setup_client().await;
    let client = reqwest::Client::new();
    let response = client.get("http://127.0.0.1:3001/version").send().await.unwrap();
    assert_eq!(
        response.text().await.unwrap(),
        format!("{}, {}", env!("VERGEN_GIT_DESCRIBE"), env!("VERGEN_GIT_SHA"))
    );
}
