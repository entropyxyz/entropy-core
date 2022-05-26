use crate::*;


#[tokio::test]
async fn test_receive_ip_address() {
	let mut entropy_service = EntropyServer::new(EntropyService::default());
	// Server::builder().add_service(service).serve(socket).await?;
	// entropy_service.receive_ip_address("test".to_string());
}
