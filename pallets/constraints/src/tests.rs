use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};

// adds whitelist and checks max whitelist and already whitelisted
#[test]
fn whitelist_address() {
	new_test_ext().execute_with(|| {
		assert_ok!(Constraints::add_whitelist_address(Origin::signed(1), 2));
		assert_eq!(Constraints::address_whitelist(1), [2]);
		assert_noop!(
			Constraints::add_whitelist_address(Origin::signed(1), 2),
			Error::<Test>::AlreadyWhitelisted
		);
		assert_ok!(Constraints::add_whitelist_address(Origin::signed(1), 3));
		assert_eq!(Constraints::address_whitelist(1), [2, 3]);
		assert_noop!(
			Constraints::add_whitelist_address(Origin::signed(1), 4),
			Error::<Test>::MaxWhitelist
		);
	});
}
