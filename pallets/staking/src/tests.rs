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
        assert!(Staking::is_validator_synced(5));
        assert!(Staking::is_validator_synced(6));
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

        assert_ok!(Staking::declare_synced(RuntimeOrigin::signed(5), true));
        assert!(Staking::is_validator_synced(5));
    });
}
