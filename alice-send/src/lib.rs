use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use curv::elliptic::curves::{secp256_k1::Secp256k1};
use reqwest;

mod main;



pub async fn send() -> Result<(), Box<dyn std::error::Error>> {
    // let file1 = tokio::fs::read("local-share1.json").await?;
    let file2 = tokio::fs::read("local-share2.json").await?;
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