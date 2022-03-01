use protocol::user::User;

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("test_register");
	let user = User {};
	let _reg_res = user.send_registration_request().await?;
	println!("test_register");
	//ToDo:
	// send key to bob
	alice_send::send().await;
	println!("test_register: sent keyshare!");

	Ok(())
}
