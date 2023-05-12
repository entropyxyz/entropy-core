use kvdb::clean_tests;
use rocket::http::Status;
use serial_test::serial;

use crate::helpers::tests::setup_client;
#[rocket::async_test]
#[serial]
async fn health() {
    clean_tests();
    let client = setup_client().await;
    let response = client.get("/healthz/live").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    clean_tests();
}
