use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};

// adds whitelist and checks max whitelist and already whitelisted
#[test]
fn whitelist_address() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			Constraints::add_whitelist_address(Origin::signed(1), [2, 3, 4, 5].to_vec()),
			Error::<Test>::MaxWhitelist
		);
		assert_ok!(Constraints::add_whitelist_address(Origin::signed(1), [2, 3].to_vec()));
		assert_eq!(Constraints::address_whitelist(1), [2, 3]);
		assert_noop!(
			Constraints::add_whitelist_address(Origin::signed(1), [2].to_vec()),
			Error::<Test>::AlreadyWhitelisted
		);
		assert_ok!(Constraints::add_whitelist_address(Origin::signed(1), [4].to_vec()));
		assert_eq!(Constraints::address_whitelist(1), [2, 3, 4]);
		assert_noop!(
			Constraints::add_whitelist_address(Origin::signed(1), [5].to_vec()),
			Error::<Test>::MaxWhitelist
		);
	});
}
