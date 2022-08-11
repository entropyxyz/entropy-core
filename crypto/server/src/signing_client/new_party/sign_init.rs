use serde::{Deserialize, Serialize};
// use kvdb::kv_manager::value::PartyInfo;
// use tokio::sync::mpsc;
// use tracing::{info, instrument};

// use super::{SignerState, SigningProtocolError, SubscribeError};

// CLAIM(TK): The saniziting check required by the tofnd library is only required for a protocol
// execution where this node could hold a multiple secret key shares.
// https://github.com/axelarnetwork/tofnd/blob/cb311ac39e505bdc451d33dcb0228902a80caffe/src/gg20/sign/init.rs#L80
//
/// Information passed from the CommunicationManager to all nodes.
/// corresponds to https://github.com/axelarnetwork/grpc-protobuf/blob/21698133e2f025d706f1dffec19637216d968692/grpc.proto#L120
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignInit {
  /// Unique id of this signature (may be repeated if this party fails)
  pub sig_uid:      String,
  /// Unique id of user's key (for retreival from kv-store)
  pub key_uid:      String,
  /// Unique id of this signing party
  pub party_uid:    String,
  /// IP addresses of each node in the party. This is not an unordered list! Each node is
  /// expected to be at the index it will use for the signing protocol.
  pub ip_addresses: Vec<String>,
  /// Hash of the message to sign
  pub msg:          String,
}

impl SignInit {
  pub fn new(
    party_uid: String,
    ip_addresses: Vec<String>,
    key_uid: String,
    msg: String,
    repeated_sig_uid: Option<String>,
  ) -> Self {
    // let sig_uid = if let Some(uid) = repeated_sig_uid { uid } else { Uuid::new_v4() };
    let sig_uid = if let Some(uid) = repeated_sig_uid { uid } else { "".to_string() };
    Self { party_uid, ip_addresses, sig_uid, key_uid, msg }
  }
}

// impl StoredInfo {
// 	/// Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
// 	/// Also needed in recovery
// 	pub fn get_party_info(
// 		secret_key_shares: Vec<SecretKeyShare>,
// 		uids: Vec<String>,
// 		share_counts: Vec<usize>,
// 		tofnd_index: usize,
// 	) -> Self {
// 		// grap the first share to acquire common data
// 		let common = secret_key_shares[0].group().clone();

// 		// aggregate share data into a vector
// 		let shares = secret_key_shares.into_iter().map(|share| share.share().clone()).collect();

// 		// add tofnd data
// 		let tofnd = TofndInfo { party_uids: uids, share_counts, index: tofnd_index };

// 		PartyInfo { common, shares, tofnd }
// 	}
// }
