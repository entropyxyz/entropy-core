// `KeyShareKv` record
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct StoredInfo {
// pub(crate) common: GroupPublicInfo,
// pub(crate) shares: Vec<ShareSecretInfo>,
// pub(crate) tofnd: TofndInfo,
// }

// impl TryFrom<Vec<u8>> for StoredInfo {
// 	type Error = ();

// 	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
// 		todo!()
// 	}
// }

// impl StoredInfo {
// 	/// Get GroupPublicInfo and ShareSecretInfo from tofn to create PartyInfo
// 	/// Also needed in recovery
// 	pub(crate) fn get_party_info(
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
