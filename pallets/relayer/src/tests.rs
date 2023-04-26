use entropy_shared::{Constraints, Message, SigRequest, ValidatorInfo};
use frame_support::{assert_noop, assert_ok};
use pallet_constraints::{ActiveArchitectures, AllowedToModifyConstraints};

use crate::{mock::*, Error, Registered, RegisteringDetails};

pub const SIG_HASH: &[u8; 64] = b"d188f0d99145e7ddbd0f1e46e7fd406db927441584571c623aff1d1652e14b06";

#[test]
fn it_preps_transaction() {
    new_test_ext().execute_with(|| {
        Registered::<Test>::insert(1, true);
        let ip_addresses: Vec<Vec<u8>> = vec![vec![20], vec![50]];
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        let message = Message {
            account: vec![1, 0, 0, 0, 0, 0, 0, 0],
            sig_request: sig_request.clone(),
            validators_info: vec![
                ValidatorInfo { ip_address: ip_addresses[0].clone(), x25519_public_key: [0; 32] },
                ValidatorInfo { ip_address: ip_addresses[1].clone(), x25519_public_key: [0; 32] },
            ],
        };

        assert_ok!(Relayer::prep_transaction(RuntimeOrigin::signed(1), sig_request.clone()));

        assert_eq!(Relayer::messages(0), vec![message]);

        // handle gracefully if all validators in a subgroup in syncing state
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(7, false);
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(5, false);
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(1, false);
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(6, false);
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(2, false);

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
        let ip_addresses: Vec<Vec<u8>> = vec![vec![20], vec![50]];
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        let message = Message {
            account: vec![1, 0, 0, 0, 0, 0, 0, 0],
            sig_request: sig_request.clone(),
            validators_info: vec![
                ValidatorInfo { ip_address: ip_addresses[0].clone(), x25519_public_key: [0; 32] },
                ValidatorInfo { ip_address: ip_addresses[1].clone(), x25519_public_key: [0; 32] },
            ],
        };

        assert_ok!(Relayer::prep_transaction(RuntimeOrigin::signed(1), sig_request));

        System::assert_last_event(RuntimeEvent::Relayer(crate::Event::SignatureRequested(message)));
    });
}

#[test]
fn it_tests_get_validator_rotation() {
    new_test_ext().execute_with(|| {
        let result_1 = Relayer::get_validator_rotation(&mut vec![1u64, 2u64], 0).unwrap();
        assert_eq!(result_1.0, 1);
        // properly handles not enough members in group
        let result_2 = Relayer::get_validator_rotation(&mut vec![1u64, 5u64], 2).unwrap();
        assert_eq!(result_2.0, 5);

        // properly handles not syncing
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(1, false);
        let result_3 = Relayer::get_validator_rotation(&mut vec![1u64, 2u64], 0).unwrap();
        assert_eq!(result_3.0, 2);

        // properly handles not staking and not enough members in groups
        pallet_staking_extension::IsValidatorSynced::<Test>::insert(5, false);
        let result_4 = Relayer::get_validator_rotation(&mut vec![2u64, 5u64], 2).unwrap();
        assert_eq!(result_4.0, 2);
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
