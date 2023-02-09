use entropy_shared::{Constraints, Message, SigRequest};
use frame_support::{assert_noop, assert_ok, traits::OnInitialize};
use pallet_constraints::{ActiveArchitectures, AllowedToModifyConstraints};
use pallet_staking_extension::ServerInfo;

use crate::{mock::*, Error, Failures, Registered, RegisteringDetails, Responsibility};

const NULL_ARR: [u8; 32] = [0; 32];
pub const SIG_HASH: &[u8; 64] = b"d188f0d99145e7ddbd0f1e46e7fd406db927441584571c623aff1d1652e14b06";

#[test]
fn it_preps_transaction() {
    new_test_ext().execute_with(|| {
        Registered::<Test>::insert(1, true);
        let ip_addresses: Vec<Vec<u8>> = vec![vec![10], vec![11]];
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        let message = Message {
            account: vec![1, 0, 0, 0, 0, 0, 0, 0],
            sig_request: sig_request.clone(),
            ip_addresses,
        };

        assert_ok!(Relayer::prep_transaction(RuntimeOrigin::signed(1), sig_request.clone()));

        assert_eq!(Relayer::messages(0), vec![message]);

        // handle gracefully if all validators in a subgroup in syncing state
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(1, false);
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(5, false);
        assert_noop!(
            Relayer::prep_transaction(RuntimeOrigin::signed(1), sig_request),
            Error::<Test>::NoSyncedValidators
        );
    });
}

#[test]
fn it_emits_a_signature_request_event() {
    new_test_ext().execute_with(|| {
        System::set_block_number(2);
        Registered::<Test>::insert(1, true);
        let ip_addresses: Vec<Vec<u8>> = vec![vec![10], vec![50]];
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        let message = Message {
            account: vec![1, 0, 0, 0, 0, 0, 0, 0],
            sig_request: sig_request.clone(),
            ip_addresses,
        };

        assert_ok!(Relayer::prep_transaction(RuntimeOrigin::signed(1), sig_request));

        System::assert_last_event(RuntimeEvent::Relayer(crate::Event::SignatureRequested(message)));
    });
}

#[test]
fn it_tests_get_validator_rotation() {
    new_test_ext().execute_with(|| {
        let result_1 = Relayer::get_validator_rotation(0, 0).unwrap();
        let result_2 = Relayer::get_validator_rotation(1, 0).unwrap();
        assert_eq!(result_1.0, 1);
        assert_eq!(result_2.0, 2);

        let result_3 = Relayer::get_validator_rotation(0, 1).unwrap();
        let result_4 = Relayer::get_validator_rotation(1, 1).unwrap();
        assert_eq!(result_3.0, 5);
        assert_eq!(result_4.0, 6);

        let result_5 = Relayer::get_validator_rotation(0, 100).unwrap();
        let result_6 = Relayer::get_validator_rotation(1, 100).unwrap();
        assert_eq!(result_5.0, 1);
        assert_eq!(result_6.0, 6);

        let result_7 = Relayer::get_validator_rotation(0, 101).unwrap();
        let result_8 = Relayer::get_validator_rotation(1, 101).unwrap();
        assert_eq!(result_7.0, 5);
        assert_eq!(result_8.0, 7);

        pallet_staking_extension::IsValidatorSynced::<Test>::insert(7, false);

        let result_9 = Relayer::get_validator_rotation(1, 101).unwrap();
        assert_eq!(result_9.0, 6);

        // really big number does not crash
        let result_10 = Relayer::get_validator_rotation(0, 1000000000000000000).unwrap();
        assert_eq!(result_10.0, 1);
    });
}

#[test]
fn it_registers_a_user() {
    new_test_ext().execute_with(|| {
        assert_ok!(Relayer::register(
            RuntimeOrigin::signed(1),
            2 as <Test as frame_system::Config>::AccountId,
            None
        ));

        assert!(Relayer::registering(1).unwrap().is_registering);
    });
}

#[test]
fn it_confirms_registers_a_user_then_swap() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Relayer::confirm_register(RuntimeOrigin::signed(1), 1, 0),
            Error::<Test>::NoThresholdKey
        );

        pallet_staking_extension::ThresholdToStash::<Test>::insert(1, 1);

        assert_noop!(
            Relayer::confirm_register(RuntimeOrigin::signed(1), 1, 0),
            Error::<Test>::NotRegistering
        );

        assert_ok!(Relayer::register(
            RuntimeOrigin::signed(1),
            2 as <Test as frame_system::Config>::AccountId,
            Some(Constraints::default()),
        ));

        assert_noop!(
            Relayer::confirm_register(RuntimeOrigin::signed(1), 1, 3),
            Error::<Test>::InvalidSubgroup
        );

        pallet_staking_extension::ThresholdToStash::<Test>::insert(2, 2);

        assert_noop!(
            Relayer::confirm_register(RuntimeOrigin::signed(2), 1, 0),
            Error::<Test>::NotInSigningGroup
        );

        assert_eq!(Relayer::registered(1), None);

        assert_ok!(Relayer::confirm_register(RuntimeOrigin::signed(1), 1, 0));

        assert_noop!(
            Relayer::confirm_register(RuntimeOrigin::signed(1), 1, 0),
            Error::<Test>::AlreadyConfirmed
        );

        let registering_info = RegisteringDetails::<Test> {
            is_registering: true,
            constraint_account: 2 as <Test as frame_system::Config>::AccountId,
            is_swapping: false,
            confirmations: vec![0],
            constraints: Some(Constraints::default()),
        };

        assert_eq!(Relayer::registering(1), Some(registering_info));

        assert_ok!(Relayer::confirm_register(RuntimeOrigin::signed(2), 1, 1));

        assert_eq!(Relayer::registering(1), None);
        assert!(Relayer::registered(1).unwrap());

        // make sure constraint and sig req keys are set
        assert!(AllowedToModifyConstraints::<Test>::contains_key(2, 1));
        assert!(ActiveArchitectures::<Test>::iter_key_prefix(1).count() == 0);

        // test swapping keys
        assert_noop!(Relayer::swap_keys(RuntimeOrigin::signed(2)), Error::<Test>::NotRegistered);

        let swapping_info = RegisteringDetails::<Test> {
            is_registering: true,
            constraint_account: 1 as <Test as frame_system::Config>::AccountId,
            is_swapping: true,
            confirmations: vec![],
            constraints: None,
        };
        assert_ok!(Relayer::swap_keys(RuntimeOrigin::signed(1)));

        assert_eq!(Relayer::registering(1), Some(swapping_info));
    });
}

#[test]
fn it_confirms_done() {
    new_test_ext().execute_with(|| {
        Responsibility::<Test>::insert(5, 2);
        let failures = vec![0u32, 3u32];
        pallet_staking_extension::ThresholdServers::<Test>::insert(
            2,
            ServerInfo { tss_account: 1, x25519_public_key: NULL_ARR, endpoint: vec![20] },
        );
        assert_ok!(Relayer::confirm_done(RuntimeOrigin::signed(1), 5, failures.clone()));
        assert_eq!(Relayer::failures(5), Some(failures.clone()));

        assert_noop!(
            Relayer::confirm_done(RuntimeOrigin::signed(1), 5, failures.clone()),
            Error::<Test>::AlreadySubmitted
        );
        assert_noop!(
            Relayer::confirm_done(RuntimeOrigin::signed(1), 6, failures.clone()),
            Error::<Test>::NoResponsibility
        );
        Responsibility::<Test>::insert(6, 3);
        assert_noop!(
            Relayer::confirm_done(RuntimeOrigin::signed(2), 6, failures.clone()),
            Error::<Test>::NoThresholdKey
        );
        pallet_staking_extension::ThresholdServers::<Test>::insert(
            2,
            ServerInfo { tss_account: 5, x25519_public_key: NULL_ARR, endpoint: vec![20] },
        );
        assert_noop!(
            Relayer::confirm_done(RuntimeOrigin::signed(2), 5, failures),
            Error::<Test>::NotYourResponsibility
        );
    });
}

#[test]
fn it_doesnt_allow_double_registering() {
    new_test_ext().execute_with(|| {
        // register a user
        assert_ok!(Relayer::register(RuntimeOrigin::signed(1), 2, None));

        // error if they try to submit another request, even with a different constraint key
        assert_noop!(
            Relayer::register(RuntimeOrigin::signed(1), 2, None),
            Error::<Test>::AlreadySubmitted
        );
    });
}

#[test]
fn moves_active_to_pending() {
    new_test_ext().execute_with(|| {
        // no failures pings unresponsive
        System::set_block_number(3);
        Responsibility::<Test>::insert(3, 1);
        Relayer::on_initialize(5);
        assert_eq!(Relayer::unresponsive(1), 1);
        let failures = vec![0u32, 3u32];
        Failures::<Test>::insert(2, failures.clone());
        Failures::<Test>::insert(5, failures.clone());

        let ip_addresses: Vec<Vec<u8>> = vec![vec![20], vec![11]];
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        let message = Message {
            account: vec![1, 0, 0, 0, 0, 0, 0, 0],
            sig_request: sig_request.clone(),
            ip_addresses,
        };
        Registered::<Test>::insert(1, true);
        assert_ok!(Relayer::prep_transaction(RuntimeOrigin::signed(1), sig_request));
        assert_eq!(Relayer::messages(3), vec![message.clone()]);

        // prunes old failure remove messages put into pending
        assert_eq!(Relayer::failures(2), Some(failures.clone()));
        Relayer::on_initialize(5);
        assert_eq!(Relayer::failures(2), None);
        assert_eq!(Relayer::messages(3), vec![]);
        assert_eq!(Relayer::pending(3), vec![message]);
        assert_eq!(Relayer::unresponsive(1), 0);
        // pending pruned
        Responsibility::<Test>::insert(4, 1);
        Failures::<Test>::insert(3, failures);
        Relayer::on_initialize(6);
        assert_eq!(Relayer::pending(3), vec![]);
        assert_eq!(Relayer::failures(3), None);
    });
}

#[test]
fn notes_responsibility() {
    new_test_ext().execute_with(|| {
        Responsibility::<Test>::insert(2, 1);
        Relayer::note_responsibility(5);
        assert_eq!(Relayer::responsibility(4), Some(11));
        assert_eq!(Relayer::responsibility(2), None);
    });
}
