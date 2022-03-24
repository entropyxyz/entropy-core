use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};

#[test]
fn basic_setup_works() {
	new_test_ext().execute_with(|| {
		assert_eq!(Staking::endpoint_register(5).unwrap(), vec![20]);
		assert_eq!(Staking::endpoint_register(6).unwrap(), vec![40]);
	});
}

#[test]
fn it_takes_in_an_endpoint() {
	new_test_ext().execute_with(|| {
		assert_ok!(FrameStaking::bond(
			Origin::signed(2),
			1,
			100u64,
			pallet_staking::RewardDestination::Account(1),
		));
		assert_ok!(Staking::validate(
			Origin::signed(1),
			pallet_staking::ValidatorPrefs::default(),
			vec![20]
		));
		assert_eq!(Staking::endpoint_register(1).unwrap(), vec![20]);
		assert_noop!(
			Staking::validate(
				Origin::signed(4),
				pallet_staking::ValidatorPrefs::default(),
				vec![20, 20, 20, 20]
			),
			Error::<Test>::EndpointTooLong
		);
	});
}

#[test]
fn it_changes_endpoint() {
	new_test_ext().execute_with(|| {
		assert_ok!(FrameStaking::bond(
			Origin::signed(2),
			1,
			100u64,
			pallet_staking::RewardDestination::Account(1),
		));
		assert_ok!(Staking::validate(
			Origin::signed(1),
			pallet_staking::ValidatorPrefs::default(),
			vec![20]
		));

		assert_ok!(Staking::change_endpoint(Origin::signed(1), vec![30]));
		assert_eq!(Staking::endpoint_register(1).unwrap(), vec![30]);

		assert_noop!(Staking::change_endpoint(Origin::signed(3), vec![30]), Error::<Test>::NoBond);
	});
}

#[test]
fn it_deletes_when_no_bond_left() {
	new_test_ext().execute_with(|| {
		start_active_era(1);
		assert_ok!(FrameStaking::bond(
			Origin::signed(2),
			1,
			100u64,
			pallet_staking::RewardDestination::Account(1),
		));
		assert_ok!(Staking::validate(
			Origin::signed(1),
			pallet_staking::ValidatorPrefs::default(),
			vec![20]
		));

		assert_eq!(Staking::endpoint_register(1).unwrap(), vec![20]);
		let mut lock = Balances::locks(2);
		assert_eq!(lock[0].amount, 100);
		assert_eq!(lock.len(), 1);

		assert_ok!(FrameStaking::unbond(Origin::signed(1), 50u64,));

		lock = Balances::locks(2);
		assert_eq!(lock[0].amount, 100);
		assert_eq!(lock.len(), 1);
		println!(":{:?}", FrameStaking::ledger(1));

		assert_ok!(Staking::withdraw_unbonded(Origin::signed(1), 0,));

		lock = Balances::locks(2);
		assert_eq!(lock[0].amount, 50);
		assert_eq!(lock.len(), 1);

		assert_eq!(Staking::endpoint_register(1).unwrap(), vec![20]);

		assert_ok!(FrameStaking::unbond(Origin::signed(1), 50u64,));

		assert_ok!(Staking::withdraw_unbonded(Origin::signed(1), 0,));
		lock = Balances::locks(2);
		assert_eq!(lock.len(), 0);
		assert_eq!(Staking::endpoint_register(1), None);
	});
}
