//! signing client
use dotenv::dotenv;
use entropy_grpc as proto;
use lazy_static::lazy_static;
use log::{info};
use proto::{entropy_client::EntropyClient, GetPartyRequest};
use std::{env::var, error::Error};
use tonic::Request;

lazy_static! {
    // todo: localhost is temp
    static ref SERVER_URI: String=
        format!("{}:{}","http://localhost",var("GRPC_SERVER_PORT").unwrap())
    ;
    static ref ALICE_URI: String =
        format!("{}:{}","http://localhost",var("ALICE_PORT").unwrap())
    ;
}

async fn create_grpc_client(
) -> Result<EntropyClient<tonic::transport::Channel>, Box<dyn std::error::Error>> {
    info!(
        "✨ Client: initiating at URI: {:?} ...",
        ALICE_URI.to_string()
    );
    // Won't accept: 127.0.0.1:1313 // Will accept: http://localhost:1313/
    let channel = tonic::transport::Channel::from_static(&SERVER_URI)
        .connect()
        .await?;
    Ok(EntropyClient::new(channel))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    env_logger::init();
    let mut client = create_grpc_client().await?;
    let request = Request::new(GetPartyRequest {
        address: SERVER_URI.to_string(),
    });
    let mut stream = client.get_party(request).await?.into_inner();
    let addresses = stream.message().await?.expect("weird response");

    info!("🎉 Client: got addresses: {:?}", addresses);
    Ok(())
}
