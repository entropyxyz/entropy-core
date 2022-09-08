use std::env;

use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
};
use serial_test::serial;

use super::ParsedUserInputPartyInfo;
use crate::communication_manager::{get_path, setup_client};

#[rocket::async_test]
#[serial]
async fn test_store_share() {
    let key = "14ffvYx6uFkqr3jXvYc5Joeczvnq8oqCiABdNA3a1M9R16F2".to_string();
    let value = vec![10];

    let client = setup_client().await;

    let user_input = ParsedUserInputPartyInfo { key: key.clone(), value: value.clone() };

    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user_input.clone()).unwrap())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.into_string().await, None);
    // fails to add already added share
    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&user_input).unwrap())
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::InternalServerError);

    clean_tests();
}

#[ignore]
#[rocket::async_test]
#[serial]
async fn test_store_share_fail_wrong_data() {
    // Construct a client to use for dispatching requests.
    let client = setup_client().await;

    let response = client
        .post("/user/new")
        .header(ContentType::JSON)
        .body(
            r##"{
		"name": "John Doe",
		"email": "j.doe@m.com",
		"password": "123456"
	}"##,
        )
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::UnprocessableEntity);
    clean_tests();
}
