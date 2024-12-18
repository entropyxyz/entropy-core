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

use crate::{
    mock::*, tests::RuntimeEvent, Error, JoiningServerInfo, NextSignerInfo, NextSigners,
    ServerInfo, Signers,
};
use codec::Encode;
use frame_support::{assert_noop, assert_ok};
use frame_system::{EventRecord, Phase};
use pallet_parameters::SignersSize;
use pallet_session::SessionManager;
use sp_runtime::BoundedVec;

const NULL_ARR: [u8; 32] = [0; 32];

#[test]
fn basic_setup_works() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            Staking::threshold_server(5).unwrap(),
            ServerInfo {
                tss_account: 7,
                x25519_public_key: NULL_ARR,
                endpoint: vec![20],
                provisioning_certification_key: BoundedVec::with_max_capacity()
            }
        );
        assert_eq!(
            Staking::threshold_server(6).unwrap(),
            ServerInfo {
                tss_account: 8,
                x25519_public_key: NULL_ARR,
                endpoint: vec![40],
                provisioning_certification_key: BoundedVec::with_max_capacity()
            }
        );
        assert_eq!(Staking::threshold_to_stash(7).unwrap(), 5);
        assert_eq!(Staking::threshold_to_stash(8).unwrap(), 6);
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

        let joining_server_info =
            JoiningServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

        let ServerInfo { tss_account, endpoint, .. } = Staking::threshold_server(1).unwrap();
        assert_eq!(endpoint, vec![20]);
        assert_eq!(tss_account, 3);
        assert_eq!(Staking::threshold_to_stash(3).unwrap(), 1);

        let joining_server_info = JoiningServerInfo {
            tss_account: 3,
            x25519_public_key: NULL_ARR,
            endpoint: [20; (crate::tests::MaxEndpointLength::get() + 1) as usize].to_vec(),
        };
        assert_noop!(
            Staking::validate(
                RuntimeOrigin::signed(4),
                pallet_staking::ValidatorPrefs::default(),
                joining_server_info,
                VALID_QUOTE.to_vec(),
            ),
            Error::<Test>::EndpointTooLong
        );

        let joining_server_info = JoiningServerInfo {
            tss_account: 5,
            x25519_public_key: NULL_ARR,
            endpoint: vec![20, 20],
        };
        assert_noop!(
            Staking::validate(
                RuntimeOrigin::signed(4),
                pallet_staking::ValidatorPrefs::default(),
                joining_server_info,
                VALID_QUOTE.to_vec(),
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

        let joining_server_info =
            JoiningServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
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
                joining_server_info,
                VALID_QUOTE.to_vec(),
            ),
            Error::<Test>::TssAccountAlreadyExists
        );
    });
}

#[test]
fn it_changes_endpoint() {
    new_test_ext().execute_with(|| {
        let endpoint = b"http://localhost:3001".to_vec();

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let joining_server_info = JoiningServerInfo {
            tss_account: 3,
            x25519_public_key: NULL_ARR,
            endpoint: endpoint.clone(),
        };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

        assert_ok!(Staking::change_endpoint(
            RuntimeOrigin::signed(1),
            endpoint.clone(),
            VALID_QUOTE.to_vec()
        ));
        assert_eq!(Staking::threshold_server(1).unwrap().endpoint, endpoint);

        assert_noop!(
            Staking::change_endpoint(RuntimeOrigin::signed(3), endpoint, VALID_QUOTE.to_vec()),
            Error::<Test>::NoBond
        );
    });
}

#[test]
fn it_doesnt_change_endpoint_with_invalid_quote() {
    new_test_ext().execute_with(|| {
        let endpoint = b"http://localhost:3001".to_vec();

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let joining_server_info = JoiningServerInfo {
            tss_account: 3,
            x25519_public_key: NULL_ARR,
            endpoint: endpoint.clone(),
        };

        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

        assert_noop!(
            Staking::change_endpoint(RuntimeOrigin::signed(1), endpoint, INVALID_QUOTE.to_vec()),
            Error::<Test>::BadQuote
        );
    })
}

#[test]
fn it_changes_threshold_account() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let joining_server_info =
            JoiningServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

        assert_ok!(Staking::change_threshold_accounts(
            RuntimeOrigin::signed(1),
            4,
            NULL_ARR,
            VALID_QUOTE.to_vec()
        ));
        assert_eq!(Staking::threshold_server(1).unwrap().tss_account, 4);
        assert_eq!(Staking::threshold_to_stash(4).unwrap(), 1);

        assert_noop!(
            Staking::change_threshold_accounts(
                RuntimeOrigin::signed(4),
                5,
                NULL_ARR,
                VALID_QUOTE.to_vec()
            ),
            Error::<Test>::NotController
        );

        // Check that we cannot change to a TSS account which already exists
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            100u64,
            pallet_staking::RewardDestination::Account(2),
        ));

        let joining_server_info =
            JoiningServerInfo { tss_account: 5, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(2),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

        assert_noop!(
            Staking::change_threshold_accounts(
                RuntimeOrigin::signed(1),
                5,
                NULL_ARR,
                VALID_QUOTE.to_vec()
            ),
            Error::<Test>::TssAccountAlreadyExists
        );

        Signers::<Test>::put(vec![1]);
        assert_noop!(
            Staking::change_threshold_accounts(
                RuntimeOrigin::signed(1),
                9,
                NULL_ARR,
                VALID_QUOTE.to_vec()
            ),
            Error::<Test>::NoChangingThresholdAccountWhenSigner
        );
    });
}

#[test]
fn it_doesnt_allow_changing_threshold_account_with_invalid_quote() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let joining_server_info =
            JoiningServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

        assert_noop!(
            Staking::change_threshold_accounts(
                RuntimeOrigin::signed(1),
                4,
                NULL_ARR,
                INVALID_QUOTE.to_vec()
            ),
            Error::<Test>::BadQuote
        );
    })
}

#[test]
fn it_will_not_allow_existing_tss_account_when_changing_threshold_account() {
    new_test_ext().execute_with(|| {
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(1),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let joining_server_info =
            JoiningServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(1),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info,
            VALID_QUOTE.to_vec(),
        ));

        // Check that we cannot change to a TSS account which already exists
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            100u64,
            pallet_staking::RewardDestination::Account(2),
        ));

        let joining_server_info =
            JoiningServerInfo { tss_account: 5, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(2),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

        assert_noop!(
            Staking::change_threshold_accounts(
                RuntimeOrigin::signed(1),
                5,
                NULL_ARR,
                VALID_QUOTE.to_vec()
            ),
            Error::<Test>::TssAccountAlreadyExists
        );
    });
}

#[test]
fn it_deletes_when_no_bond_left() {
    new_test_ext().execute_with(|| {
        Signers::<Test>::put(vec![5, 6, 7]);
        start_active_era(1);

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(2),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        let joining_server_info =
            JoiningServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![20] };
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(2),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

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

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(7),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        assert_noop!(
            Staking::withdraw_unbonded(RuntimeOrigin::signed(7), 0),
            Error::<Test>::NoUnbondingWhenSigner
        );

        // test nominating flow
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(9),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));
        assert_ok!(FrameStaking::nominate(RuntimeOrigin::signed(9), vec![7]));
        assert_noop!(
            Staking::withdraw_unbonded(RuntimeOrigin::signed(9), 0),
            Error::<Test>::NoUnnominatingWhenSigner
        );

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(8),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        NextSigners::<Test>::put(NextSignerInfo { next_signers: vec![8], confirmations: vec![] });

        assert_noop!(
            Staking::withdraw_unbonded(RuntimeOrigin::signed(8), 0),
            Error::<Test>::NoUnbondingWhenNextSigner
        );

        // test nominating flow
        assert_ok!(FrameStaking::nominate(RuntimeOrigin::signed(9), vec![8]));
        assert_noop!(
            Staking::withdraw_unbonded(RuntimeOrigin::signed(9), 0),
            Error::<Test>::NoUnnominatingWhenNextSigner
        );
    });
}

#[test]
fn it_doesnt_panic_when_no_signers() {
    new_test_ext().execute_with(|| {
        assert_ok!(Staking::new_session_handler(&[1, 2, 3]));
    });
}

#[test]
fn it_tests_new_session_handler() {
    new_test_ext().execute_with(|| {
        // Start with current validators as 5 and 6 based off the Mock `GenesisConfig`.
        Signers::<Test>::put(vec![5, 6]);
        // no next signers at start
        assert_eq!(Staking::next_signers(), None);
        assert_eq!(Staking::reshare_data().block_number, 0, "Check reshare block start at zero");
        assert_eq!(
            Staking::jump_start_progress().parent_key_threshold,
            0,
            "parent key threhsold start at zero"
        );

        System::set_block_number(100);

        pallet_parameters::SignersInfo::<Test>::put(SignersSize {
            total_signers: 2,
            threshold: 2,
            last_session_change: 0,
        });

        assert_ok!(Staking::new_session_handler(&[1, 5, 6]));
        // takes signers original (5,6) pops off one and adds in new validator
        assert_eq!(Staking::next_signers().unwrap().next_signers, vec![6, 1]);
        assert_eq!(Staking::reshare_data().block_number, 99, "Check reshare block start at 99 + 1");
        assert_eq!(
            Staking::reshare_data().new_signers,
            vec![1u64.encode()],
            "Check reshare next signer up is 3"
        );
        assert_eq!(
            Staking::jump_start_progress().parent_key_threshold,
            2,
            "parent key threhsold updated"
        );

        assert_ok!(Staking::new_session_handler(&[6, 5, 3]));
        // takes 3 and leaves 5 and 6 since already in signer group
        assert_eq!(Staking::next_signers().unwrap().next_signers, vec![6, 3]);

        assert_ok!(Staking::new_session_handler(&[1]));
        // does nothing as not enough validators
        assert_eq!(Staking::next_signers().unwrap().next_signers, vec![6, 3]);

        // reduce threshold to make sure next signers does not drop > then threshold of current signers
        pallet_parameters::SignersInfo::<Test>::put(SignersSize {
            total_signers: 2,
            threshold: 1,
            last_session_change: 0,
        });

        assert_ok!(Staking::new_session_handler(&[1, 2, 3]));
        assert_eq!(Staking::next_signers().unwrap().next_signers, vec![5, 1]);
    });
}

#[test]
fn it_tests_new_session_handler_truncating() {
    new_test_ext().execute_with(|| {
        // Start with current validators as 7 and 8 based off the Mock `GenesisConfig`.
        Signers::<Test>::put(vec![7, 8]);
        System::set_block_number(100);
        pallet_parameters::SignersInfo::<Test>::put(SignersSize {
            total_signers: 2,
            threshold: 2,
            last_session_change: 0,
        });
        // test truncates none if t and n = 0
        assert_ok!(Staking::new_session_handler(&[1, 2, 3]));
        assert_eq!(Staking::next_signers().unwrap().next_signers, vec![7, 8]);

        pallet_parameters::SignersInfo::<Test>::put(SignersSize {
            total_signers: 2,
            threshold: 1,
            last_session_change: 0,
        });
        // test truncates 1 if n - t = 1
        assert_ok!(Staking::new_session_handler(&[1, 2, 3]));
        assert_eq!(Staking::next_signers().unwrap().next_signers, vec![7, 1]);
    });
}

#[test]
fn it_tests_new_session_handler_signer_size_changes() {
    new_test_ext().execute_with(|| {
        // Start with current validators as 5 and 6 based off the Mock `GenesisConfig`.
        Signers::<Test>::put(vec![5, 6]);

        assert_ok!(Staking::new_session_handler(&[6, 5, 3, 4]));
        // Signer size increased is reflected as 5 is not removed from vec
        assert_eq!(Staking::next_signers().unwrap().next_signers, vec![5, 6, 3]);

        pallet_parameters::SignersInfo::<Test>::put(SignersSize {
            total_signers: 2,
            threshold: 2,
            last_session_change: 0,
        });
        assert_ok!(Staking::new_session_handler(&[6, 5, 3, 4]));
        // Signer size decrease is reflected as 5 is removed and 4 is not added
        assert_eq!(Staking::next_signers().unwrap().next_signers, vec![6, 3]);
    });
}

#[test]
fn it_confirms_keyshare() {
    new_test_ext().execute_with(|| {
        Signers::<Test>::put(vec![5, 6]);
        assert_noop!(
            Staking::confirm_key_reshare(RuntimeOrigin::signed(10)),
            Error::<Test>::NoThresholdKey
        );

        assert_noop!(
            Staking::confirm_key_reshare(RuntimeOrigin::signed(7)),
            Error::<Test>::ReshareNotInProgress
        );

        NextSigners::<Test>::put(NextSignerInfo {
            next_signers: vec![7, 5],
            confirmations: vec![5],
        });

        assert_noop!(
            Staking::confirm_key_reshare(RuntimeOrigin::signed(8)),
            Error::<Test>::NotNextSigner
        );

        assert_noop!(
            Staking::confirm_key_reshare(RuntimeOrigin::signed(7)),
            Error::<Test>::AlreadyConfirmed
        );

        NextSigners::<Test>::put(NextSignerInfo {
            next_signers: vec![6, 5],
            confirmations: vec![],
        });

        let mock_next_signer_info =
            NextSignerInfo { next_signers: vec![6, 5], confirmations: vec![5] };

        assert_ok!(Staking::confirm_key_reshare(RuntimeOrigin::signed(7)));
        assert_eq!(Staking::next_signers().unwrap(), mock_next_signer_info, "Confirmation added");
        assert_eq!(Staking::signers(), [5, 6], "check current signers so we can see it changed");

        assert_ok!(Staking::confirm_key_reshare(RuntimeOrigin::signed(8)));
        assert_eq!(Staking::next_signers(), None, "Next Signers cleared");
        assert_eq!(Staking::signers(), [6, 5], "next signers rotated into current signers");
    });
}

#[test]
fn it_requires_attestation_before_validate_is_succesful() {
    new_test_ext().execute_with(|| {
        let (alice, bob) = (1, 2);

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(alice),
            100u64,
            pallet_staking::RewardDestination::Account(alice),
        ));

        let joining_server_info =
            JoiningServerInfo { tss_account: bob, x25519_public_key: NULL_ARR, endpoint: vec![20] };

        // First we test that an invalid attestation doesn't allow us to submit our candidacy.
        assert_noop!(
            Staking::validate(
                RuntimeOrigin::signed(alice),
                pallet_staking::ValidatorPrefs::default(),
                joining_server_info.clone(),
                INVALID_QUOTE.to_vec(),
            ),
            Error::<Test>::BadQuote
        );

        assert_eq!(Staking::threshold_server(bob), None);
        assert_eq!(Staking::threshold_to_stash(joining_server_info.tss_account), None);

        // Next we test that a valid attestation gets us into a candidate state.
        assert_ok!(Staking::validate(
            RuntimeOrigin::signed(alice),
            pallet_staking::ValidatorPrefs::default(),
            joining_server_info.clone(),
            VALID_QUOTE.to_vec(),
        ));

        let server_info = ServerInfo::<AccountId> {
            tss_account: joining_server_info.tss_account,
            x25519_public_key: joining_server_info.x25519_public_key,
            endpoint: joining_server_info.endpoint,
            provisioning_certification_key: [0; 33].to_vec().try_into().unwrap(),
        };
        assert_eq!(Staking::threshold_to_stash(bob), Some(alice));
        assert_eq!(Staking::threshold_server(alice), Some(server_info));
    })
}

#[test]
fn it_stops_unbonded_when_signer_or_next_signer() {
    new_test_ext().execute_with(|| {
        Signers::<Test>::put(vec![7]);
        start_active_era(1);

        // test nominating flow
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(9),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));
        assert_ok!(FrameStaking::nominate(RuntimeOrigin::signed(9), vec![7]));
        assert_noop!(
            Staking::unbond(RuntimeOrigin::signed(9), 100u64),
            Error::<Test>::NoUnnominatingWhenSigner
        );

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(7),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        assert_noop!(
            Staking::unbond(RuntimeOrigin::signed(7), 0),
            Error::<Test>::NoUnbondingWhenSigner
        );

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(8),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        NextSigners::<Test>::put(NextSignerInfo { next_signers: vec![8], confirmations: vec![] });
        assert_noop!(
            Staking::unbond(RuntimeOrigin::signed(8), 0),
            Error::<Test>::NoUnbondingWhenNextSigner
        );

        // test nominating flow
        assert_ok!(FrameStaking::nominate(RuntimeOrigin::signed(9), vec![8]));
        assert_noop!(
            Staking::unbond(RuntimeOrigin::signed(9), 100u64),
            Error::<Test>::NoUnnominatingWhenNextSigner
        );
    });
}

#[test]
fn it_stops_chill_when_signer_or_next_signer() {
    new_test_ext().execute_with(|| {
        Signers::<Test>::put(vec![7]);
        start_active_era(1);

        // test nominating flow
        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(9),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));
        assert_ok!(FrameStaking::nominate(RuntimeOrigin::signed(9), vec![7]));
        assert_noop!(
            Staking::chill(RuntimeOrigin::signed(9)),
            Error::<Test>::NoUnnominatingWhenSigner
        );

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(7),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        assert_noop!(
            Staking::chill(RuntimeOrigin::signed(7)),
            Error::<Test>::NoUnbondingWhenSigner
        );

        assert_ok!(FrameStaking::bond(
            RuntimeOrigin::signed(8),
            100u64,
            pallet_staking::RewardDestination::Account(1),
        ));

        NextSigners::<Test>::put(NextSignerInfo { next_signers: vec![8], confirmations: vec![] });

        assert_noop!(
            Staking::chill(RuntimeOrigin::signed(8)),
            Error::<Test>::NoUnbondingWhenNextSigner
        );
        // test nominating flow
        assert_ok!(FrameStaking::nominate(RuntimeOrigin::signed(9), vec![8]));
        assert_noop!(
            Staking::chill(RuntimeOrigin::signed(9)),
            Error::<Test>::NoUnnominatingWhenNextSigner
        );
    });
}

#[test]
fn cannot_report_outside_of_signer_set() {
    new_test_ext().execute_with(|| {
        // These mappings come from the mock GenesisConfig
        let (alice_validator, alice_tss) = (5, 7);
        let (_bob_validator, bob_tss) = (6, 8);

        let (_not_validator, not_tss) = (33, 33);

        // We only want Alice to be part of the signing committee for the test.
        Signers::<Test>::put(vec![alice_validator]);

        // A TSS which doesn't have a `ValidatorId` cannot report another peer
        assert_noop!(
            Staking::report_unstable_peer(RuntimeOrigin::signed(not_tss), bob_tss),
            Error::<Test>::NoThresholdKey
        );

        // A validator which isn't part of the signing committee cannot report another peer
        assert_noop!(
            Staking::report_unstable_peer(RuntimeOrigin::signed(bob_tss), alice_tss),
            Error::<Test>::NotSigner
        );

        // An offender that does not have a `ValidatorId` cannot be reported
        assert_noop!(
            Staking::report_unstable_peer(RuntimeOrigin::signed(alice_tss), not_tss),
            Error::<Test>::NoThresholdKey
        );

        // An offender which isn't part of the signing committee cannot be reported
        assert_noop!(
            Staking::report_unstable_peer(RuntimeOrigin::signed(alice_tss), bob_tss),
            Error::<Test>::NotSigner
        );
    })
}

#[test]
fn can_report_unstable_peer() {
    new_test_ext().execute_with(|| {
        // These mappings come from the mock GenesisConfig
        let (alice_validator, alice_tss) = (5, 7);
        let (bob_validator, bob_tss) = (6, 8);

        Signers::<Test>::put(vec![alice_validator, bob_validator]);

        // The TSS accounts are used for reports. We expect the accompanying validator to be
        // reported though.
        assert_ok!(Staking::report_unstable_peer(RuntimeOrigin::signed(alice_tss), bob_tss));

        assert_eq!(<pallet_slashing::Pallet<Test>>::failed_registrations(bob_validator), 1);
    })
}
