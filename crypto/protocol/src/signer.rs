// use zengo-multi-::any;
pub struct Node {
	//
}
/// Subcommittee Signing Node
pub trait SigningNode {}
/// Leader Signing Node
pub trait LeaderNode {}

struct Signer {
	private_key: PrivateKey,
}
impl Node for Signer {}
