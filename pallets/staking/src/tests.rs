use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};

#[test]
fn it_takes_in_an_endpoint() {
	new_test_ext().execute_with(|| {
		assert_ok!(Staking::bond(
			Origin::signed(2),
			1,
			100u64,
			pallet_staking::RewardDestination::Account(1),
			vec![20]
		));
		assert_eq!(Staking::endpoint_register(1), vec![20]);
		assert_noop!(
			Staking::bond(
				Origin::signed(4),
				3,
				100u64,
				pallet_staking::RewardDestination::Account(1),
				vec![20, 20, 20, 20]
			),
			Error::<Test>::EndpointTooLong
		);
	});
}

#[test]
fn it_changes_endpoint() {
	new_test_ext().execute_with(|| {
		assert_ok!(Staking::bond(
			Origin::signed(2),
			1,
			100u64,
			pallet_staking::RewardDestination::Account(1),
			vec![20]
		));

		assert_ok!(Staking::change_endpoint(Origin::signed(1), vec![30]));
		assert_eq!(Staking::endpoint_register(1), vec![30]);

		assert_noop!(Staking::change_endpoint(Origin::signed(3), vec![30]), Error::<Test>::NoBond);

	})
}


