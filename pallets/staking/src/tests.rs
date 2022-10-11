use frame_support::{assert_noop, assert_ok, traits::OnInitialize};
use sp_runtime::testing::UintAuthorityId;

use crate::{mock::*, Error};

const NULL_ARR: [u8; 32] = [0; 32];

fn initialize_block(block: u64) {
    SESSION_CHANGED.with(|l| *l.borrow_mut() = false);
    System::set_block_number(block);
    Session::on_initialize(block);
}

#[test]
fn basic_setup_works() {
    new_test_ext().execute_with(|| {
        assert_eq!(Staking::endpoint_register(5).unwrap(), vec![20]);
        assert_eq!(Staking::endpoint_register(6).unwrap(), vec![40]);
        assert_eq!(Staking::threshold_account(5).unwrap().0, 7);
        assert_eq!(Staking::threshold_account(6).unwrap().0, 8);
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![2]);
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
            vec![20],
            3,
            NULL_ARR
        ));
        assert_eq!(Staking::endpoint_register(1).unwrap(), vec![20]);
        assert_eq!(Staking::threshold_account(2).unwrap().0, 3);
        assert_noop!(
            Staking::validate(
                Origin::signed(4),
                pallet_staking::ValidatorPrefs::default(),
                vec![20, 20, 20, 20],
                3,
                NULL_ARR
            ),
            Error::<Test>::EndpointTooLong
        );
        assert_noop!(
            Staking::validate(
                Origin::signed(4),
                pallet_staking::ValidatorPrefs::default(),
                vec![20, 20],
                3,
                NULL_ARR
            ),
            Error::<Test>::NotController
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
            vec![20],
            3,
            NULL_ARR
        ));

        assert_ok!(Staking::change_endpoint(Origin::signed(1), vec![30]));
        assert_eq!(Staking::endpoint_register(1).unwrap(), vec![30]);

        assert_noop!(Staking::change_endpoint(Origin::signed(3), vec![30]), Error::<Test>::NoBond);
    });
}

#[test]
fn it_changes_threshold_account() {
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
            vec![20],
            3,
            NULL_ARR
        ));

        assert_ok!(Staking::change_threshold_accounts(Origin::signed(1), 4, NULL_ARR));
        assert_eq!(Staking::threshold_account(2).unwrap().0, 4);

        assert_noop!(
            Staking::change_threshold_accounts(Origin::signed(4), 5, NULL_ARR),
            Error::<Test>::NotController
        );
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
            vec![20],
            3,
            NULL_ARR
        ));

        assert_eq!(Staking::endpoint_register(1).unwrap(), vec![20]);
        assert_eq!(Staking::threshold_account(2).unwrap().0, 3);

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
        assert_eq!(Staking::threshold_account(2).unwrap().0, 3);

        assert_ok!(FrameStaking::unbond(Origin::signed(1), 50u64,));

        assert_ok!(Staking::withdraw_unbonded(Origin::signed(1), 0,));
        lock = Balances::locks(2);
        assert_eq!(lock.len(), 0);
        assert_eq!(Staking::endpoint_register(1), None);
        assert_eq!(Staking::threshold_account(2), None);
    });
}

#[test]
fn it_tests_on_new_session() {
    new_test_ext().execute_with(|| {
        let authority_1 = (&1u64, UintAuthorityId::from(1));
        let authority_2 = (&2u64, UintAuthorityId::from(2));
        let authority_3 = (&3u64, UintAuthorityId::from(3));
        let authority_4 = (&4u64, UintAuthorityId::from(4));


        // situation 1 - changed is false no changes should be made
        Staking::on_new_session(
            false,
            vec![authority_1.clone()].into_iter(),
            vec![authority_1.clone()].into_iter(),
        );
		// nothing is changed
		assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![2]);

        // situation 2 - authority 2 leaves authority 3 enters
        Staking::on_new_session(
            true,
            vec![authority_1.clone(), authority_2.clone()].into_iter(),
            vec![authority_1.clone(), authority_3.clone()].into_iter(),
        );

		// authority 3 replaces authority 2
		assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![3]);

		 // situation 3 - authority 2 leaves not replaces
		 Staking::on_new_session(
            true,
            vec![authority_1.clone(), authority_2.clone()].into_iter(),
            vec![authority_1.clone()].into_iter(),
        );

		// authority 2 left sig group 1 has no one in signing group
		assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1), None);

		 // situation 4 - authority 2 enters a new group
		 Staking::on_new_session(
            true,
            vec![authority_1.clone()].into_iter(),
            vec![authority_1.clone(), authority_2.clone()].into_iter(),
        );

		assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![2]);


		 // situation 5 - same number but both authorities change
		 Staking::on_new_session(
            true,
            vec![authority_1.clone(), authority_2.clone()].into_iter(),
            vec![authority_3.clone(), authority_4.clone()].into_iter(),
        );
		// auth 3 and 4 are now the signing groups
		assert_eq!(Staking::signing_groups(0).unwrap(), vec![3]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![4]);



		 // situation 6 - both validators leave one replaces both
		 Staking::on_new_session(
            true,
            vec![authority_3.clone(), authority_4.clone()].into_iter(),
            vec![authority_1.clone()].into_iter(),
        );

		// Just authority_1 is left
		assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
		assert_eq!(Staking::signing_groups(1), None);
    });
}
