pub fn is_on_whitelist(addresses: Vec<Vec<u8>>, address: &Vec<u8>) -> bool {
	if addresses.len() == 0 {
		return true
	}

	addresses.contains(address)
}
