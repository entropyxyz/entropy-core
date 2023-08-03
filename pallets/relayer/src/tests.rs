use codec::Encode;
use entropy_shared::{Constraints, KeyVisibility};
use frame_support::{assert_noop, assert_ok};
use pallet_constraints::{ActiveArchitectures, AllowedToModifyConstraints};

use crate::{mock::*, Error, RegisteringDetails};

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
            KeyVisibility::Public,
            None
        ));

        assert!(Relayer::registering(1).unwrap().is_registering);
        assert_eq!(Relayer::dkg(0), vec![1u64.encode()]);
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
            KeyVisibility::Private,
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
            key_visibility: KeyVisibility::Private,
        };

        assert_eq!(Relayer::registering(1), Some(registering_info));

        assert_ok!(Relayer::confirm_register(RuntimeOrigin::signed(2), 1, 1));

        assert_eq!(Relayer::registering(1), None);
        assert_eq!(Relayer::registered(1).unwrap(), KeyVisibility::Private);

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
            key_visibility: KeyVisibility::Private,
        };
        assert_ok!(Relayer::swap_keys(RuntimeOrigin::signed(1)));

        assert_eq!(Relayer::registering(1), Some(swapping_info));
    });
}

#[test]
fn it_doesnt_allow_double_registering() {
    new_test_ext().execute_with(|| {
        // register a user
        assert_ok!(Relayer::register(
            RuntimeOrigin::signed(1),
            2,
            KeyVisibility::Permissioned,
            None
        ));

        // error if they try to submit another request, even with a different constraint key
        assert_noop!(
            Relayer::register(RuntimeOrigin::signed(1), 2, KeyVisibility::Permissioned, None),
            Error::<Test>::AlreadySubmitted
        );
    });
}
