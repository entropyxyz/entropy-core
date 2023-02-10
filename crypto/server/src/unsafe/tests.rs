use hex_literal::hex as h;
use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
};
use serial_test::serial;
use testing_utils::context::test_context_stationary;

use super::api::UnsafeQuery;

pub async fn setup_client() -> rocket::local::asynchronous::Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_unsafe_get_endpoint() {
    let cxt = test_context_stationary().await;
    let client = setup_client().await;
    let get_query = UnsafeQuery::new("MNEMONIC".to_string(), "foo".to_string()).to_json();

    // Test that the get endpoint works
    let response = client
        .post("/unsafe/get")
        .header(ContentType::JSON)
        .body(get_query.clone())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    let response_mnemonic = response.into_string().await.unwrap();
    assert!(!response_mnemonic.is_empty());

    // Update the mnemonic, testing the put endpoint works
    let put_response = client
        .post("/unsafe/put")
        .header(ContentType::JSON)
        .body(get_query.clone())
        .dispatch()
        .await;

    assert_eq!(put_response.status(), Status::Ok);

    // Check the updated mnemonic is the new value
    let get_response =
        client.post("/unsafe/get").header(ContentType::JSON).body(get_query).dispatch().await;

    assert_eq!(get_response.status(), Status::Ok);
    let updated_response_mnemonic = get_response.into_string().await.unwrap();
    assert_eq!(updated_response_mnemonic, "foo".to_string());

    clean_tests();
}
