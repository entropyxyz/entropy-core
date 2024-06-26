// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::{mock::*, tests::RuntimeEvent, Error, IsValidatorSynced, ServerInfo, ThresholdToStash};
use frame_support::{assert_noop, assert_ok};
use frame_system::{EventRecord, Phase};
use pallet_session::SessionManager;

const NULL_ARR: [u8; 32] = [0; 32];

#[test]
fn basic_setup_works() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            Staking::threshold_server(5).unwrap(),
            ServerInfo { tss_account: 7, x25519_public_key: NULL_ARR, endpoint: vec![20] }
        );
        assert_eq!(
            Staking::threshold_server(6).unwrap(),
            ServerInfo { tss_account: 8, x25519_public_key: NULL_ARR, endpoint: vec![40] }
        );
        assert_eq!(Staking::threshold_to_stash(7).unwrap(), 5);
        assert_eq!(Staking::threshold_to_stash(8).unwrap(), 6);
        assert_eq!(Staking::signing_groups(0).unwrap(), vec![1]);
        assert_eq!(Staking::signing_groups(1).unwrap(), vec![2]);
        assert!(Staking::is_validator_synced(1));
        assert!(Staking::is_validator_synced(2));
    });
}

#[test]
fn it_takes_in_an_endpoint() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let server_info =
            ServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            server_info,
        ));

        let ServerInfo { tss_account, endpoint, .. } = Staking::threshold_server(1).unwrap();
        assert_eq!(endpoint, vec![20]);
        assert_eq!(tss_account, 3);
        assert_eq!(Staking::threshold_to_stash(3).unwrap(), 1);

        let server_info = ServerInfo {
            tss_account: 3,
            x25519_public_key: NULL_ARR,
            endpoint: vec![20, 20, 20, 20],
        };
        assert_noop!(
            Staking::validate(
                RuntimeOrigin::signed(4),
                pallet_staking::ValidatorPrefs::default(),
                server_info,
            ),
            Error::<Test>::EndpointTooLong
        );

        let server_info =
            ServerInfo { tss_account: 5, x25519_public_key: NULL_ARR, endpoint: vec![20, 20] };
        assert_noop!(
            Staking::validate(
                RuntimeOrigin::signed(4),
                pallet_staking::ValidatorPrefs::default(),
                server_info
            ),
            pallet_staking::Error::<Test>::NotController
        );
    });
}

#[test]
fn it_will_not_allow_validator_to_use_existing_tss_account() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let server_info =
            ServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            server_info.clone(),
        ));

        // Attempt to call validate with a TSS account which already exists
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            100u64,
            pallet_staking::RewardDestination::Account(2),
        ));
        assert_noop!(
            Staking::validate(
                RuntimeOrigin::signed(2),
                pallet_staking::ValidatorPrefs::default(),
                server_info,
            ),
            Error::<Test>::TssAccountAlreadyExists
        );
    });
}

#[test]
fn it_changes_endpoint() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let server_info =
            ServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            server_info,
        ));

        assert_ok!(Staking::change_endpoint(RuntimeOrigin::signed(1), vec![30]));
        assert_eq!(Staking::threshold_server(1).unwrap().endpoint, vec![30]);

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
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let server_info =
            ServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            server_info,
        ));

        assert_ok!(Staking::change_threshold_accounts(RuntimeOrigin::signed(1), 4, NULL_ARR));
        assert_eq!(Staking::threshold_server(1).unwrap().tss_account, 4);
        assert_eq!(Staking::threshold_to_stash(4).unwrap(), 1);

        assert_noop!(
            Staking::change_threshold_accounts(RuntimeOrigin::signed(4), 5, NULL_ARR),
            Error::<Test>::NotController
        );

        // Check that we cannot change to a TSS account which already exists
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            100u64,
            pallet_staking::RewardDestination::Account(2),
        ));

        let server_info =
            ServerInfo { tss_account: 5, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(2),
            pallet_staking::ValidatorPrefs::default(),
            server_info,
        ));

        assert_noop!(
            Staking::change_threshold_accounts(RuntimeOrigin::signed(1), 5, NULL_ARR),
            Error::<Test>::TssAccountAlreadyExists
        );
    });
}

#[test]
fn it_will_not_allow_existing_tss_account_when_changing_threshold_account() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let server_info =
            ServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            server_info,
        ));

        // Check that we cannot change to a TSS account which already exists
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            100u64,
            pallet_staking::RewardDestination::Account(2),
        ));

        let server_info =
            ServerInfo { tss_account: 5, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(2),
            pallet_staking::ValidatorPrefs::default(),
            server_info,
        ));

        assert_noop!(
            Staking::change_threshold_accounts(RuntimeOrigin::signed(1), 5, NULL_ARR),
            Error::<Test>::TssAccountAlreadyExists
        );
    });
}

#[test]
fn it_deletes_when_no_bond_left() {
    new_test_ext().execute_with(|| {
        start_active_era(1);
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let server_info =
            ServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(2),
            pallet_staking::ValidatorPrefs::default(),
            server_info,
        ));
        IsValidatorSynced::<Test>::insert(2, true);

        let ServerInfo { tss_account, endpoint, .. } = Staking::threshold_server(2).unwrap();
        assert_eq!(endpoint, vec![20]);
        assert_eq!(tss_account, 3);
        assert_eq!(Staking::threshold_to_stash(3).unwrap(), 2);

        let mut lock = Balances::locks(2);
        assert_eq!(lock[0].amount, 100);
        assert_eq!(lock.len(), 1);

        assert_ok!(FrameStaking::unbond(RuntimeOrigin::signed(2), 50u64,));

        lock = Balances::locks(2);
        assert_eq!(lock[0].amount, 100);
        assert_eq!(lock.len(), 1);
        println!(":{:?}", FrameStaking::ledger(1.into()));
        MockSessionManager::new_session(0);

        assert_ok!(Staking::withdraw_unbonded(RuntimeOrigin::signed(2), 0,));
        // make sure event does not fire when node info not removed
        let event = RuntimeEvent::Staking(crate::Event::NodeInfoRemoved(2));
        let record = EventRecord { phase: Phase::Initialization, event, topics: vec![] };

        assert!(!System::events().contains(&record));
        // make sure the frame staking pallet emits the right event
        System::assert_last_event(RuntimeEvent::FrameStaking(pallet_staking::Event::Withdrawn {
            stash: 2,
            amount: 50,
        }));

        lock = Balances::locks(2);
        assert_eq!(lock[0].amount, 50);
        assert_eq!(lock.len(), 1);
        // validator still synced
        assert_eq!(Staking::is_validator_synced(2), true);

        let ServerInfo { tss_account, endpoint, .. } = Staking::threshold_server(2).unwrap();
        assert_eq!(endpoint, vec![20]);
        assert_eq!(tss_account, 3);
        assert_eq!(Staking::threshold_to_stash(3).unwrap(), 2);

        assert_ok!(FrameStaking::unbond(RuntimeOrigin::signed(2), 50u64,));

        assert_ok!(Staking::withdraw_unbonded(RuntimeOrigin::signed(2), 0,));
        // make sure node info removed event happens
        System::assert_last_event(RuntimeEvent::Staking(crate::Event::NodeInfoRemoved(2)));

        lock = Balances::locks(2);
        assert_eq!(lock.len(), 0);
        assert_eq!(Staking::threshold_server(2), None);
        assert_eq!(Staking::threshold_to_stash(3), None);
        // validator no longer synced
        assert_eq!(Staking::is_validator_synced(2), false);
    });
}

#[test]
fn it_declares_synced() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Staking::declare_synced(RuntimeOrigin::signed(5), true),
            Error::<Test>::NoThresholdKey
        );

        ThresholdToStash::<Test>::insert(5, 5);

        assert!(!Staking::is_validator_synced(5));
        assert_ok!(Staking::declare_synced(RuntimeOrigin::signed(5), true));
        assert!(Staking::is_validator_synced(5));
    });
}

#[test]
fn tests_new_session_handler() {
    new_test_ext().execute_with(|| {
        let first_signing_group = || Staking::signing_groups(0).unwrap();
        let second_signing_group = || Staking::signing_groups(1).unwrap();

        // In our mock genesis we have Validator 1 and 2 in two different signing groups
        assert_eq!(first_signing_group(), vec![1]);
        assert_eq!(second_signing_group(), vec![2]);

        // If we set validators 1 and 2 in a new session, we expect them to be assigned to two
        // different signing groups
        assert_ok!(Staking::new_session_handler(&[1, 2]));
        assert_eq!(first_signing_group(), vec![1]);
        assert_eq!(second_signing_group(), vec![2]);

        // If we set validators 1 and 2 in a new session, in a different order as before, we expect
        // them to be assigned to the same signing group
        assert_ok!(Staking::new_session_handler(&[2, 1]));
        assert_eq!(first_signing_group(), vec![1]);
        assert_eq!(second_signing_group(), vec![2]);

        // If we have a session with a single validator, we expect to have an empty signing group
        assert_ok!(Staking::new_session_handler(&[1]));
        assert_eq!(first_signing_group(), vec![1]);
        assert_eq!(Staking::signing_groups(1), Some(vec![]));

        // If we have a session with more validators than signing groups, we expect that they will
        // be assigned across the different signing groups
        assert_ok!(Staking::new_session_handler(&[1, 2, 3]));
        assert_eq!(first_signing_group(), vec![1, 2]);
        assert_eq!(second_signing_group(), vec![3]);

        // If we have a session with more validators than signing groups, we expect that they will
        // be assigned across the different signing groups
        assert_ok!(Staking::new_session_handler(&[1, 2, 3, 4, 5]));
        assert_eq!(first_signing_group(), vec![1, 2, 4]);
        assert_eq!(second_signing_group(), vec![3, 5]);
    });
}

#[test]
fn validator_to_subgroup_is_populated_correctly() {
    new_test_ext().execute_with(|| {
        let (alice, bob, charlie) = (1, 2, 3);

        // At genesis, we have Alice and Bob in subgroups 1 and 2, respectively, so we expect them
        // to each be assigned into a different subgroup
        let subgroup = Staking::validator_to_subgroup(alice);
        assert!(subgroup == Some(0));

        let subgroup = Staking::validator_to_subgroup(bob);
        assert!(subgroup == Some(1));

        // We're going to add a new authority in our next session, we expect that our new validator
        // will also be in the expected subgroup
        assert_ok!(Staking::new_session_handler(&[alice, bob, charlie]));
        let subgroup = Staking::validator_to_subgroup(alice);
        assert!(subgroup == Some(0));

        let subgroup = Staking::validator_to_subgroup(bob);
        assert!(subgroup == Some(1));

        let subgroup = Staking::validator_to_subgroup(charlie);
        assert!(subgroup == Some(0));

        // If we remove an existing validator on a session change, we expect their subgroup info to
        // be cleared.
        //
        // Note that Charlie doesn't get moved from their subgroup to rebalance since they were
        // previously in the validator set.
        assert_ok!(Staking::new_session_handler(&[alice, charlie]));
        let subgroup = Staking::validator_to_subgroup(alice);
        assert!(subgroup == Some(0));

        let subgroup = Staking::validator_to_subgroup(bob);
        assert!(subgroup == None);

        let subgroup = Staking::validator_to_subgroup(charlie);
        assert!(subgroup == Some(0));
    })
}

#[test]
fn validator_to_subgroup_does_not_populate_candidates() {
    new_test_ext().execute_with(|| {
        let (alice, _bob, charlie) = (1, 2, 3);

        let endpoint = vec![0];
        let tss_account = alice;
        let x25519_public_key = NULL_ARR;
        let server_info = ServerInfo { tss_account, x25519_public_key, endpoint };

        // We use `charlie` here since they are not a validator at genesis
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(charlie),
            100,
            pallet_staking::RewardDestination::Account(charlie),
        ));

        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(charlie),
            pallet_staking::ValidatorPrefs::default(),
            server_info,
        ));

        // We expect that validator candidates will be included in the list of threshold servers
        assert!(matches!(Staking::threshold_server(charlie), Some(_)));

        // We don't expect candidates to be assigned a subgroup
        assert!(matches!(Staking::validator_to_subgroup(charlie), None));
    })
}
