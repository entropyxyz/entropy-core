use protocol::user::User;

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("test_sign");
	let user = User {};
	user.sign_message(1).await?;
	Ok(())
}
