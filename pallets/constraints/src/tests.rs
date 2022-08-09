use frame_support::{assert_noop, assert_ok};

use crate::{mock::*, Error};

// adds whitelist and checks max whitelist and already whitelisted
#[test]
fn whitelist_address() {
  new_test_ext().execute_with(|| {
    let address_2 = [2].to_vec();
    let address_3 = [3].to_vec();
    let address_4 = [4].to_vec();
    let address_5 = [5].to_vec();

    assert_noop!(
      Constraints::add_whitelist_address(
        Origin::signed(1),
        [address_2.clone(), address_3.clone(), address_4.clone(), address_5.clone()].to_vec()
      ),
      Error::<Test>::MaxWhitelist
    );
    assert_ok!(Constraints::add_whitelist_address(
      Origin::signed(1),
      [address_2.clone(), address_3.clone()].to_vec()
    ));
    assert_eq!(Constraints::address_whitelist(1), [address_2.clone(), address_3.clone()]);
    assert_noop!(
      Constraints::add_whitelist_address(Origin::signed(1), [address_2.clone()].to_vec()),
      Error::<Test>::AlreadyWhitelisted
    );
    assert_ok!(Constraints::add_whitelist_address(Origin::signed(1), [address_4.clone()].to_vec()));
    assert_eq!(Constraints::address_whitelist(1), [address_2, address_3, address_4]);
    assert_noop!(
      Constraints::add_whitelist_address(Origin::signed(1), [address_5].to_vec()),
      Error::<Test>::MaxWhitelist
    );
    assert_noop!(
      Constraints::add_whitelist_address(Origin::signed(1), [[1, 12, 21].to_vec()].to_vec()),
      Error::<Test>::AddressTooLong
    );
  });
}
