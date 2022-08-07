use crate::PartyUid;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Information passed from the CommunicationManager to all nodes.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CMInfoUnchecked {
	/// Unique id of this signature (may be repeated if this party fails)
	pub sig_uid: Uuid,
	/// Unique id of user's key (for retreival from kv-store)
	pub key_uid: Uuid,
	/// Unique id of this signing party
	pub party_uid: PartyUid,
	/// IP addresses of each node in the party. This is not an unordered list! Each node is
	/// expected to be at the index it will use for the signing protocol.
	pub ip_addresses: Vec<String>,
	/// Hash of the message to sign
	pub msg: String,
}

impl CMInfoUnchecked {
	pub fn new(
		party_uid: PartyUid,
		ip_addresses: Vec<String>,
		key_uid: Uuid,
		msg: String,
		repeated_sig_uid: Option<Uuid>,
	) -> Self {
		let sig_uid = if let Some(uid) = repeated_sig_uid { uid } else { Uuid::new_v4() };
		Self { party_uid, ip_addresses, sig_uid, key_uid, msg }
	}

	// todo: check kv info against self
	#[allow(unused_variables)]
	pub fn check(self, kv_keyshare_info: &KvKeyshareInfo) -> anyhow::Result<CMInfo> {
		// check that my ip_address is at the correct index
		// if let Err(e) = checked {
		// 	return anyhow!("pathological Communication Manager");
		// }
		Ok(CMInfo {
			sig_uid: self.sig_uid,
			key_uid: self.key_uid,
			party_uid: self.party_uid,
			ip_addresses: self.ip_addresses,
			msg: self.msg,
		})
	}
}

/// return after a sanity check
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CMInfo {
	pub sig_uid: Uuid,
	pub key_uid: Uuid,
	pub party_uid: PartyUid,
	pub ip_addresses: Vec<String>,
	pub msg: String,
}

/// Key Share records (todo)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvKeyshareInfo {
	// pub common: GroupPublicInfo,
	// pub shares: Vec<ShareSecretInfo>,
	// pub tofnd: TofndInfo,
}

impl TryFrom<Vec<u8>> for KvKeyshareInfo {
	type Error = ();

	#[allow(unused_variables)]
	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		todo!()
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
