use frame_support::{assert_noop, assert_ok, traits::OnInitialize};
use pallet_session::SessionManager;
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
        assert_eq!(Staking::threshold_to_stash(7).unwrap(), 5);
        assert_eq!(Staking::threshold_to_stash(8).unwrap(), 6);
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![2]);
    });
}

#[test]
fn it_takes_in_an_endpoint() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            1,
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            vec![20],
            3,
            NULL_ARR
        ));
        assert_eq!(Staking::endpoint_register(1).unwrap(), vec![20]);
        assert_eq!(Staking::threshold_account(2).unwrap().0, 3);
        assert_eq!(Staking::threshold_to_stash(3).unwrap(), 2);
        assert_noop!(
            Staking::validate(
                RuntimeOrigin::signed(4),
                pallet_staking::ValidatorPrefs::default(),
                vec![20, 20, 20, 20],
                3,
                NULL_ARR
            ),
            Error::<Test>::EndpointTooLong
        );
        assert_noop!(
            Staking::validate(
                RuntimeOrigin::signed(4),
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
            RuntimeOrigin::signed(2),
            1,
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            vec![20],
            3,
            NULL_ARR
        ));

        assert_ok!(Staking::change_endpoint(RuntimeOrigin::signed(1), vec![30]));
        assert_eq!(Staking::endpoint_register(1).unwrap(), vec![30]);

        assert_noop!(
            Staking::change_endpoint(RuntimeOrigin::signed(3), vec![30]),
            Error::<Test>::NoBond
        );
    });
}

#[test]
fn it_changes_threshold_account() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            1,
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            vec![20],
            3,
            NULL_ARR
        ));

        assert_ok!(Staking::change_threshold_accounts(RuntimeOrigin::signed(1), 4, NULL_ARR));
        assert_eq!(Staking::threshold_account(2).unwrap().0, 4);
        assert_eq!(Staking::threshold_to_stash(4).unwrap(), 2);

        assert_noop!(
            Staking::change_threshold_accounts(RuntimeOrigin::signed(4), 5, NULL_ARR),
            Error::<Test>::NotController
        );
    });
}

#[test]
fn it_deletes_when_no_bond_left() {
    new_test_ext().execute_with(|| {
        start_active_era(1);
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            1,
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            vec![20],
            3,
            NULL_ARR
        ));

        assert_eq!(Staking::endpoint_register(1).unwrap(), vec![20]);
        assert_eq!(Staking::threshold_account(2).unwrap().0, 3);
        assert_eq!(Staking::threshold_to_stash(3).unwrap(), 2);

        let mut lock = Balances::locks(2);
        assert_eq!(lock[0].amount, 100);
        assert_eq!(lock.len(), 1);

        assert_ok!(FrameStaking::unbond(RuntimeOrigin::signed(1), 50u64,));

        lock = Balances::locks(2);
        assert_eq!(lock[0].amount, 100);
        assert_eq!(lock.len(), 1);
        println!(":{:?}", FrameStaking::ledger(1));
        MockSessionManager::new_session(0);

        assert_ok!(Staking::withdraw_unbonded(RuntimeOrigin::signed(1), 0,));

        lock = Balances::locks(2);
        assert_eq!(lock[0].amount, 50);
        assert_eq!(lock.len(), 1);

        assert_eq!(Staking::endpoint_register(1).unwrap(), vec![20]);
        assert_eq!(Staking::threshold_account(2).unwrap().0, 3);
        assert_eq!(Staking::threshold_to_stash(3).unwrap(), 2);

        assert_ok!(FrameStaking::unbond(RuntimeOrigin::signed(1), 50u64,));

        assert_ok!(Staking::withdraw_unbonded(RuntimeOrigin::signed(1), 0,));
        lock = Balances::locks(2);
        assert_eq!(lock.len(), 0);
        assert_eq!(Staking::endpoint_register(1), None);
        assert_eq!(Staking::threshold_account(2), None);
        assert_eq!(Staking::threshold_to_stash(3), None);
    });
}

#[test]
fn it_tests_on_new_session() {
    new_test_ext().execute_with(|| {
        // // situation 1 - changed is false no changes should be made
        MockSessionManager::new_session(0);
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![2]);

        // catches out of order validators
        MockSessionManager::new_session(1);

        // nothing is changed
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![2]);

        // // situation 2 - authority 2 leaves authority 3 enters
        MockSessionManager::new_session(2);
        // authority 3 replaces authority 2
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![3]);
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);

        // situation 3 - authority 2 leaves not replaces
        MockSessionManager::new_session(3);

        // authority 2 left sig group 1 has no one in signing group
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1), Some(vec![]));

        //  // situation 4 - same number but both authorities change
        MockSessionManager::new_session(4);
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![4]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![3]);

        // situation 5/6 = odd number of validators
        MockSessionManager::new_session(5);
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![2, 1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![3]);

        MockSessionManager::new_session(6);
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![1, 2, 4]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![3, 5]);
    });
}
