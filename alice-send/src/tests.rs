use httpmock::prelude::*;
use crate::send;

#[tokio::test]
async fn test_user_sending_keyshare() -> Result<(), Box<dyn std::error::Error>>{
	// create new server and define this server's methods and responses
	let server1 = MockServer::start();
	let receiving_mock = server1.mock(|when, then| {
		when.path("/store_keyshare")
			.method(POST)
			.header("Content-Type", "application/json")
			;
		then.status(200)
			.body("stuff");
	});

	let response = send(server1.url("/store_keyshare"), String::from("./local-share2.json")).await?;
	println!("response: {:?}",&response);

	// the response should look like this: 
	// Response { url: Url { scheme: "http", cannot_be_a_base: false, username: "", password: None, host: Some(Ipv4(127.0.0.1)), port: Some(3002), path: "/store_keyshare", query: None, fragment: None }, status: 200, headers: {"server": "Rocket", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "permissions-policy": "interest-cohort=()", "content-length": "0", "date": "Wed, 02 Mar 2022 15:15:18 GMT"} }

	// assert that the server was contacted
	receiving_mock.assert();
	
	// assert that the response is correct
	// ToDo: additional checks
	assert_eq!(response.status(),200);
	Ok(())
}