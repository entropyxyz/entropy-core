use curv::elliptic::curves::secp256_k1::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use reqwest;

#[cfg(test)]
mod test;

pub async fn send(url: String, path: String) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
	println!("sending keyshare...");

	// let file1 = tokio::fs::read("./alice-send/local-share1.json").await?;
	let file2 = tokio::fs::read(path).await?;

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
		.post(url)
		.header("Content-Type", "application/json")
		.json(&json2)
		.send()
		.await?;
	
	Ok(res2)
}