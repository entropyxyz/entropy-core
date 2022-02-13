use protocol::user::User;

#[async_std::main]
async fn main() -> Result<(),Box<dyn std::error::Error>> {
	println!("test_register");
	let user = User{};
	user.send_registration().await?;
	Ok(())
}
