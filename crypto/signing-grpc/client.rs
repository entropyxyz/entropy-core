use ::get_party::GetParty;
use signing_client::SayRequest;
mod signing_client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
// creating a channel ie connection to server
    let channel = tonic::transport::Channel::from_static("http://[::1]:50051")
    .connect()
    .await?;
// creating gRPC client from channel
    let mut client = GetParty::new(channel);
// creating a new Request
    let request = tonic::Request::new(
        SayRequest {
           name:String::from("")
        },
    );