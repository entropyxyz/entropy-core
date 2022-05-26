use crate::*;
use tonic::transport::{Server, Endpoint};
use std::time::Duration;
use tokio::sync::oneshot;
use futures_util::FutureExt;
use proto::{entropy_client::EntropyClient};

#[tokio::test]
async fn test_receive_ip_address() {
	let mut entropy_service = EntropyServer::new(EntropyService::default());
	let (tx, rx) = oneshot::channel::<()>();

	let test_server = tokio::spawn(async move {
        Server::builder()
            .add_service(entropy_service)
            .serve_with_shutdown("127.0.0.1:1400".parse().unwrap(), rx.map(drop))
            .await
            .unwrap();
    });


    tokio::time::sleep(Duration::from_millis(100)).await;

    let channel = Endpoint::from_static("http://127.0.0.1:1400")
        .connect()
        .await
        .unwrap();

    let mut client = EntropyClient::new(channel);
	let request = Request::new(IpAddress {
        address: "test".to_string(),
    });
	let reply = client.receive_ip_address(request).await;
	println!("{:?}", reply);
}
