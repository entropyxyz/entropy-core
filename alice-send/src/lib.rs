use curv::elliptic::curves::secp256_k1::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use reqwest;

// mod main;

pub async fn send() -> Result<(), Box<dyn std::error::Error>> {
	println!("sending keyshare...");

	// let file1 = tokio::fs::read("./alice-send/local-share1.json").await?;
	let file2 = tokio::fs::read("./alice-send/local-share2.json").await?;
	// let json1: LocalKey<Secp256k1> = serde_json::from_slice(&file1).unwrap();
	let json2: LocalKey<Secp256k1> = serde_json::from_slice(&file2).unwrap();

	let client = reqwest::Client::new();
	// // send to Bob
	// let res = client
	//     .post("http://127.0.0.1:3001/store_keyshare")
	//     .header("Content-Type", "application/json")
	//     .json(&json1)
	//     .send()
	//     .await?;
	// println!("{:?}", res);

	// send to Charlie
	let res2 = client
		.post("http://127.0.0.1:3002/store_keyshare")
		.header("Content-Type", "application/json")
		.json(&json2)
		.send()
		.await?;
	println!("{:?}", res2);
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use httpmock::prelude::*;
	use isahc::config::RedirectPolicy;
	use isahc::prelude::*;
	use isahc::HttpClientBuilder;

	#[test]
	fn test_dummy(){
		assert_eq!(1+1,2);
	}

	#[test]
	fn test_user_sending_keyshare(){
		assert_eq!(1+1,2);

		// create new server and define this server's methods
		let server1 = MockServer::start();
		let receiving_mock = server1.mock(|when, then| {
			when.path("/store_keyshare");
			then.status(200)
				.body("stuff");
		});

		let http_client = HttpClientBuilder::new()
			.redirect_policy(RedirectPolicy::Follow)
			.build()
			.unwrap();

		let response = http_client.get(server1.url("/store_keyshare")).unwrap();
		// the response should look like this: 
		// Response { url: Url { scheme: "http", cannot_be_a_base: false, username: "", password: None, host: Some(Ipv4(127.0.0.1)), port: Some(3002), path: "/store_keyshare", query: None, fragment: None }, status: 200, headers: {"server": "Rocket", "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN", "permissions-policy": "interest-cohort=()", "content-length": "0", "date": "Wed, 02 Mar 2022 15:15:18 GMT"} }

		// assert that the server was contacted
		receiving_mock.assert();
		
		// assert that the response is correct
		// ToDo: additional checks
		assert_eq!(response.status(),200);
	

	}
}