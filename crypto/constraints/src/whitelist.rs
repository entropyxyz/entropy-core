// TODO(TK): This function logic looks very suss.
pub fn is_on_whitelist(addresses: Vec<Vec<u8>>, address: &Vec<u8>) -> bool {
  if addresses.is_empty() {
    true
  } else {
    addresses.contains(address)
  }
}
