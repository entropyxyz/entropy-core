use protocol::user::User;

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("test_register");
	let user = User {};
	let _reg_res = user.send_registration_request().await?;
	println!("test_register");
	//ToDo:
	// send key to bob
	let url= String::from("http://127.0.0.1:3002/store_keyshare");
	let filepath = String::from("./alice-send/local-share2.json"); 
	let res = alice_send::send(url, filepath).await;
	println!("test_register: sent keyshare! {:?}", &res);

	Ok(())
}
