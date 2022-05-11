use crate::whitelist::is_on_whitelist;

#[test]
fn test_whitelist() {
	let address = vec![1u8];
	let list = vec![vec![2u8], vec![1u8]];

	// No whitelist not set passes check
	assert_eq!(is_on_whitelist(vec![], &address), true);
	// on list
	assert_eq!(is_on_whitelist(list.clone(), &address), true);
	// not on list
	assert_eq!(is_on_whitelist(list, &vec![3u8]), false);
}
