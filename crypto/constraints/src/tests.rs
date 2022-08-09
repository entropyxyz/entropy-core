use crate::whitelist::is_on_whitelist;

#[test]
fn test_whitelist() {
  let address = vec![1u8];
  let list = vec![vec![2u8], vec![1u8]];

  // No whitelist not set passes check
  assert!(is_on_whitelist(vec![], &address));
  // on list
  assert!(is_on_whitelist(list.clone(), &address));
  // not on list
  assert!(!is_on_whitelist(list, &vec![3u8]));
}
