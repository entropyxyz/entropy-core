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

#[allow(unused)]
use pallet_registry::Call as RegistryCall;

use entropy_shared::{ValidatorInfo, VERIFICATION_KEY_LENGTH};
use frame_support::{assert_noop, assert_ok, BoundedVec};
use pallet_programs::ProgramInfo;
use pallet_staking_extension::{JumpStartDetails, JumpStartProgress, JumpStartStatus, ServerInfo};
use sp_runtime::traits::Hash;

use crate as pallet_registry;
use crate::{mock::*, Error, ModifiableKeys, ProgramInstance, Registered, RegisteredInfo};

const NULL_ARR: [u8; 32] = [0; 32];

fn setup_programs(
) -> BoundedVec<ProgramInstance<Test>, <Test as pallet_registry::Config>::MaxProgramHashes> {
    let alice = 1u64;
    let empty_program = vec![];
    let program_hash = <Test as frame_system::Config>::Hashing::hash(&empty_program);
    let programs_info = BoundedVec::try_from(vec![ProgramInstance {
        program_pointer: program_hash,
        program_config: vec![],
    }])
    .unwrap();
    pallet_programs::Programs::<Test>::insert(
        program_hash,
        ProgramInfo {
            bytecode: empty_program.clone(),
            configuration_schema: empty_program.clone(),
            auxiliary_data_schema: empty_program.clone(),
            oracle_data_pointers: BoundedVec::try_from(vec![empty_program.clone()].to_vec())
                .unwrap(),
            deployer: alice,
            ref_counter: 0,
            version_number: 0,
        },
    );

    programs_info
}

#[test]
fn it_tests_get_validators_info() {
    new_test_ext().execute_with(|| {
        let result_1 = Registry::get_validators_info().unwrap();
        let server_info_1 = ServerInfo {
            tss_account: 3,
            x25519_public_key: NULL_ARR,
            endpoint: vec![10],
            tdx_quote: Vec::new(),
        };
        let server_info_2 = ServerInfo {
            tss_account: 4,
            x25519_public_key: NULL_ARR,
            endpoint: vec![11],
            tdx_quote: Vec::new(),
        };
        let server_info_3 = ServerInfo {
            tss_account: 7,
            x25519_public_key: NULL_ARR,
            endpoint: vec![20],
            tdx_quote: Vec::new(),
        };

        assert_eq!(result_1, vec![server_info_1, server_info_2, server_info_3]);
    });
}

#[test]
fn it_registers_a_user() {
    new_test_ext().execute_with(|| {
        use k256::ecdsa::VerifyingKey as SynedrionVerifyingKey;
        use synedrion::DeriveChildKey;

        let (alice, bob, _charlie) = (1u64, 2, 3);

        // Setup: Ensure programs exist and a valid verifying key is available
        let programs_info = setup_programs();

        let network_verifying_key = entropy_shared::DAVE_VERIFYING_KEY;
        pallet_staking_extension::JumpStartProgress::<Test>::set(JumpStartDetails {
            jump_start_status: JumpStartStatus::Done,
            confirmations: vec![],
            verifying_key: Some(BoundedVec::try_from(network_verifying_key.to_vec()).unwrap()),
            parent_key_threshold: 0,
        });

        // Test: Run through registration
        assert_ok!(Registry::register(RuntimeOrigin::signed(alice), bob, programs_info.clone(),));

        // Validate: Our expected verifying key is registered correctly
        let network_verifying_key =
            SynedrionVerifyingKey::try_from(network_verifying_key.as_slice()).unwrap();

        let derivation_path = "m/0/0".parse().unwrap();
        let expected_verifying_key =
            network_verifying_key.derive_verifying_key_bip32(&derivation_path).unwrap();
        let expected_verifying_key =
            BoundedVec::try_from(expected_verifying_key.to_encoded_point(true).as_bytes().to_vec())
                .unwrap();

        let registered_info = Registry::registered(expected_verifying_key.clone());
        assert!(registered_info.is_some());
        assert_eq!(registered_info.unwrap().program_modification_account, bob);
    });
}

#[test]
fn it_increases_program_reference_count_on_register() {
    new_test_ext().execute_with(|| {
        let (alice, bob, _charlie) = (1u64, 2, 3);

        // Setup: Ensure programs exist and a valid verifying key is available
        let programs_info = setup_programs();
        let empty_program = vec![];
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&empty_program);

        let network_verifying_key = entropy_shared::DAVE_VERIFYING_KEY;
        pallet_staking_extension::JumpStartProgress::<Test>::set(JumpStartDetails {
            jump_start_status: JumpStartStatus::Done,
            confirmations: vec![],
            verifying_key: Some(BoundedVec::try_from(network_verifying_key.to_vec()).unwrap()),
            parent_key_threshold: 0,
        });

        // Test: Run through registration
        assert_ok!(Registry::register(RuntimeOrigin::signed(alice), bob, programs_info.clone(),));

        // Validate: We expect that the program reference count has gone up
        assert_eq!(
            pallet_programs::Programs::<Test>::get(program_hash).unwrap().ref_counter,
            1,
            "The reference counter was not incremented during registration."
        );
    })
}

#[test]
fn it_registers_different_users_with_the_same_sig_req_account() {
    new_test_ext().execute_with(|| {
        use k256::ecdsa::VerifyingKey as SynedrionVerifyingKey;
        use synedrion::DeriveChildKey;

        let (alice, bob, _charlie) = (1u64, 2, 3);

        // Setup: Ensure programs exist and a valid verifying key is available
        let programs_info = setup_programs();

        let network_verifying_key = entropy_shared::DAVE_VERIFYING_KEY;
        JumpStartProgress::<Test>::set(JumpStartDetails {
            jump_start_status: JumpStartStatus::Done,
            confirmations: vec![],
            verifying_key: Some(BoundedVec::try_from(network_verifying_key.to_vec()).unwrap()),
            parent_key_threshold: 0,
        });

        // Test: Run through registration twice using the same signature request account. We should
        // get different verifying keys.
        assert_ok!(Registry::register(RuntimeOrigin::signed(alice), bob, programs_info.clone(),));

        assert_ok!(Registry::register(RuntimeOrigin::signed(alice), bob, programs_info.clone(),));

        // Validate: We expect two different verifying keys to be registered
        let network_verifying_key =
            SynedrionVerifyingKey::try_from(network_verifying_key.as_slice()).unwrap();

        let derivation_path = "m/0/0".parse().unwrap();
        let first_expected_verifying_key =
            network_verifying_key.derive_verifying_key_bip32(&derivation_path).unwrap();
        let first_expected_verifying_key = BoundedVec::try_from(
            first_expected_verifying_key.to_encoded_point(true).as_bytes().to_vec(),
        )
        .unwrap();

        let derivation_path = "m/0/1".parse().unwrap();
        let second_expected_verifying_key =
            network_verifying_key.derive_verifying_key_bip32(&derivation_path).unwrap();
        let second_expected_verifying_key = BoundedVec::try_from(
            second_expected_verifying_key.to_encoded_point(true).as_bytes().to_vec(),
        )
        .unwrap();

        // Knowing that the two keys are indeed different, we still expect both registration
        // requests to have succeeded.
        assert!(first_expected_verifying_key != second_expected_verifying_key);
        assert!(Registry::registered(first_expected_verifying_key).is_some());
        assert!(Registry::registered(second_expected_verifying_key).is_some());
    });
}

#[test]
fn it_fails_registration_if_no_program_is_set() {
    new_test_ext().execute_with(|| {
        let (alice, bob) = (1, 2);

        // Note that we also don't write any programs into storage here.
        let programs_info = BoundedVec::try_from(vec![]).unwrap();

        // Test: Run through registration, this should fail
        assert_noop!(
            Registry::register(RuntimeOrigin::signed(alice), bob, programs_info,),
            Error::<Test>::NoProgramSet
        );
    })
}

#[test]
fn it_fails_registration_if_an_empty_program_is_set() {
    new_test_ext().execute_with(|| {
        let (alice, bob) = (1, 2);

        // Note that we also don't write any programs into storage here.
        let non_existent_program = vec![];
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&non_existent_program);
        let programs_info = BoundedVec::try_from(vec![ProgramInstance {
            program_pointer: program_hash,
            program_config: vec![],
        }])
        .unwrap();

        // Test: Run through registration, this should fail
        assert_noop!(
            Registry::register(RuntimeOrigin::signed(alice), bob, programs_info,),
            Error::<Test>::NoProgramSet
        );
    })
}

#[test]
fn it_fails_registration_if_no_jump_start_has_happened() {
    new_test_ext().execute_with(|| {
        let (alice, bob) = (1u64, 2);

        // Setup: Ensure programs exist
        let programs_info = setup_programs();

        // This should be the default status, but let's be explicit about it anyways
        pallet_staking_extension::JumpStartProgress::<Test>::set(JumpStartDetails {
            jump_start_status: JumpStartStatus::Ready,
            confirmations: vec![],
            verifying_key: None,
            parent_key_threshold: 0,
        });

        // Test: Run through registration, this should fail
        assert_noop!(
            Registry::register(RuntimeOrigin::signed(alice), bob, programs_info,),
            Error::<Test>::JumpStartNotCompleted
        );
    })
}

#[test]
fn it_fails_registration_with_too_many_modifiable_keys() {
    new_test_ext().execute_with(|| {
        let (alice, bob) = (1u64, 2);

        // Setup: Ensure programs exist and a valid verifying key is available
        let programs_info = setup_programs();

        let network_verifying_key = entropy_shared::DAVE_VERIFYING_KEY;
        pallet_staking_extension::JumpStartProgress::<Test>::set(JumpStartDetails {
            jump_start_status: JumpStartStatus::Done,
            confirmations: vec![],
            verifying_key: Some(BoundedVec::try_from(network_verifying_key.to_vec()).unwrap()),
            parent_key_threshold: 0,
        });

        // Now we prep our state to make sure that the limit of verifying keys for an account is hit
        let mut managed_verifying_keys = vec![];
        for _ in 0..pallet_registry::MAX_MODIFIABLE_KEYS {
            managed_verifying_keys
                .push(BoundedVec::try_from(entropy_shared::DAVE_VERIFYING_KEY.to_vec()).unwrap());
        }

        let modifiable_keys = BoundedVec::try_from(managed_verifying_keys).unwrap();
        pallet_registry::ModifiableKeys::<Test>::insert(bob, &modifiable_keys);

        // Test: Run through registration, this should fail
        assert_noop!(
            Registry::register(RuntimeOrigin::signed(alice), bob, programs_info,),
            Error::<Test>::TooManyModifiableKeys
        );
    })
}

#[test]
fn it_jumps_the_network() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            Staking::jump_start_progress(),
            JumpStartDetails {
                jump_start_status: JumpStartStatus::Ready,
                confirmations: vec![],
                verifying_key: None,
                parent_key_threshold: 0,
            },
            "Checks default status of jump start detail"
        );
        assert_ok!(Registry::jump_start_network(RuntimeOrigin::signed(1)));
        assert_eq!(
            Registry::jumpstart_dkg(0),
            // From the mock genesis config
            vec![
                ValidatorInfo {
                    x25519_public_key: [0; 32],
                    ip_address: vec![20],
                    tss_account: vec![7, 0, 0, 0, 0, 0, 0, 0]
                },
                ValidatorInfo {
                    x25519_public_key: [0; 32],
                    ip_address: vec![10],
                    tss_account: vec![3, 0, 0, 0, 0, 0, 0, 0]
                },
                ValidatorInfo {
                    x25519_public_key: [0; 32],
                    ip_address: vec![11],
                    tss_account: vec![4, 0, 0, 0, 0, 0, 0, 0]
                },
            ],
            "ensures a dkg message for the jump start network is prepped"
        );
        assert_eq!(
            Staking::jump_start_progress(),
            JumpStartDetails {
                jump_start_status: JumpStartStatus::InProgress(0),
                confirmations: vec![],
                verifying_key: None,
                parent_key_threshold: 2,
            },
            "Checks that jump start is in progress"
        );

        assert_noop!(
            Registry::jump_start_network(RuntimeOrigin::signed(1)),
            Error::<Test>::JumpStartProgressNotReady
        );

        System::set_block_number(100);

        assert_ok!(Registry::jump_start_network(RuntimeOrigin::signed(1)));
        assert_eq!(
            Staking::jump_start_progress(),
            JumpStartDetails {
                jump_start_status: JumpStartStatus::InProgress(100),
                confirmations: vec![],
                verifying_key: None,
                parent_key_threshold: 2,
            },
            "ensures jump start is called again if too many blocks passed"
        );
    });
}

#[test]
fn it_tests_jump_start_result() {
    new_test_ext().execute_with(|| {
        let expected_verifying_key = BoundedVec::default();

        assert_noop!(
            Registry::confirm_jump_start(RuntimeOrigin::signed(1), expected_verifying_key.clone()),
            Error::<Test>::NoThresholdKey
        );

        pallet_staking_extension::ThresholdToStash::<Test>::insert(1, 1);
        pallet_staking_extension::ThresholdToStash::<Test>::insert(7, 7);
        assert_noop!(
            Registry::confirm_jump_start(RuntimeOrigin::signed(1), expected_verifying_key.clone()),
            Error::<Test>::JumpStartNotInProgress
        );

        // trigger jump start
        assert_ok!(Registry::jump_start_network(RuntimeOrigin::signed(1)));
        assert_noop!(
            Registry::confirm_jump_start(RuntimeOrigin::signed(1), expected_verifying_key.clone()),
            Error::<Test>::NotValidator
        );

        assert_ok!(Registry::confirm_jump_start(
            RuntimeOrigin::signed(7),
            expected_verifying_key.clone()
        ));
        assert_eq!(
            Staking::jump_start_progress(),
            JumpStartDetails {
                jump_start_status: JumpStartStatus::InProgress(0),
                confirmations: vec![7],
                verifying_key: Some(expected_verifying_key.clone()),
                parent_key_threshold: 2,
            },
            "Jump start recieves a confirmation"
        );
        assert_noop!(
            Registry::confirm_jump_start(RuntimeOrigin::signed(7), expected_verifying_key.clone()),
            Error::<Test>::AlreadyConfirmed
        );

        let bad_verifying_key =
            BoundedVec::try_from(vec![0; VERIFICATION_KEY_LENGTH as usize]).unwrap();
        assert_noop!(
            Registry::confirm_jump_start(RuntimeOrigin::signed(7), bad_verifying_key.clone()),
            Error::<Test>::MismatchedVerifyingKey
        );

        pallet_staking_extension::ThresholdToStash::<Test>::insert(3, 3);
        pallet_staking_extension::ThresholdToStash::<Test>::insert(4, 4);
        assert_ok!(Registry::confirm_jump_start(
            RuntimeOrigin::signed(3),
            expected_verifying_key.clone()
        ));
        assert_ok!(Registry::confirm_jump_start(
            RuntimeOrigin::signed(4),
            expected_verifying_key.clone()
        ));
        assert_eq!(
            Staking::jump_start_progress(),
            JumpStartDetails {
                jump_start_status: JumpStartStatus::Done,
                confirmations: vec![],
                verifying_key: Some(expected_verifying_key),
                parent_key_threshold: 2,
            },
            "Jump start in done status after all confirmations"
        );
        assert_eq!(
            pallet_staking_extension::Signers::<Test>::get(),
            vec![7, 3, 4],
            "Jumpstart sets inital signers"
        );
    });
}

#[test]
fn it_checks_ordering_of_block_numbers_in_a_storage_map() {
    new_test_ext().execute_with(|| {
        let validator = ValidatorInfo {
            x25519_public_key: [0; 32],
            ip_address: vec![20],
            tss_account: vec![0, 0, 0, 0, 0, 0, 0, 0],
        };
        pallet_registry::JumpstartDkg::<Test>::set(0, vec![validator.clone()]);
        pallet_registry::JumpstartDkg::<Test>::set(1, vec![validator.clone()]);
        pallet_registry::JumpstartDkg::<Test>::set(2, vec![validator.clone()]);
        pallet_registry::JumpstartDkg::<Test>::set(3, vec![validator.clone()]);
        pallet_registry::JumpstartDkg::<Test>::set(4, vec![validator]);
        let last_entry = pallet_registry::JumpstartDkg::<Test>::iter()
            .max_by(|(k1, _v1), (k2, _v2)| k1.cmp(k2))
            .unwrap();
        assert_eq!(last_entry.0, 4);
    })
}

#[test]
fn it_changes_a_program_instance() {
    new_test_ext().execute_with(|| {
        let empty_program = vec![];
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&empty_program);
        let programs_info = BoundedVec::try_from(vec![ProgramInstance {
            program_pointer: program_hash,
            program_config: vec![],
        }])
        .unwrap();

        pallet_programs::Programs::<Test>::insert(
            program_hash,
            ProgramInfo {
                bytecode: empty_program.clone(),
                configuration_schema: empty_program.clone(),
                auxiliary_data_schema: empty_program.clone(),
                oracle_data_pointers: BoundedVec::try_from(vec![empty_program.clone()].to_vec())
                    .unwrap(),
                deployer: 1,
                ref_counter: 1,
                version_number: 0,
            },
        );

        let new_program = vec![10];
        let new_program_hash = <Test as frame_system::Config>::Hashing::hash(&new_program);
        let new_programs_info = BoundedVec::try_from(vec![ProgramInstance {
            program_pointer: new_program_hash,
            program_config: vec![],
        }])
        .unwrap();

        pallet_programs::Programs::<Test>::insert(
            new_program_hash,
            ProgramInfo {
                bytecode: new_program,
                configuration_schema: empty_program.clone(),
                auxiliary_data_schema: empty_program.clone(),
                oracle_data_pointers: BoundedVec::try_from(vec![empty_program.clone()].to_vec())
                    .unwrap(),
                deployer: 1,
                ref_counter: 1,
                version_number: 0,
            },
        );

        let expected_verifying_key = BoundedVec::default();

        let mut registered_info = RegisteredInfo {
            programs_data: programs_info,
            program_modification_account: 2,
            derivation_path: vec![0],
            version_number: 1,
        };

        Registered::<Test>::insert(expected_verifying_key.clone(), &registered_info);
        assert_eq!(Registry::registered(expected_verifying_key.clone()).unwrap(), registered_info);

        assert_ok!(Registry::change_program_instance(
            RuntimeOrigin::signed(2),
            expected_verifying_key.clone(),
            new_programs_info.clone(),
        ));

        registered_info.programs_data = new_programs_info;
        assert_eq!(Registry::registered(expected_verifying_key.clone()).unwrap(), registered_info);
        assert_eq!(
            pallet_programs::Programs::<Test>::get(program_hash).unwrap().ref_counter,
            0,
            "ref counter is decremented"
        );
        assert_eq!(
            pallet_programs::Programs::<Test>::get(new_program_hash).unwrap().ref_counter,
            2,
            "ref counter is incremented"
        );

        let unreigistered_program = vec![13];
        let unreigistered_program_hash =
            <Test as frame_system::Config>::Hashing::hash(&unreigistered_program);
        let unregistered_programs_info = BoundedVec::try_from(vec![
            ProgramInstance { program_pointer: new_program_hash, program_config: vec![] },
            ProgramInstance { program_pointer: unreigistered_program_hash, program_config: vec![] },
        ])
        .unwrap();

        assert_noop!(
            Registry::change_program_instance(
                RuntimeOrigin::signed(2),
                expected_verifying_key.clone(),
                unregistered_programs_info.clone(),
            ),
            Error::<Test>::NoProgramSet
        );

        assert_noop!(
            Registry::change_program_instance(
                RuntimeOrigin::signed(2),
                expected_verifying_key.clone(),
                BoundedVec::try_from(vec![]).unwrap(),
            ),
            Error::<Test>::NoProgramSet
        );
    });
}

#[test]
fn it_changes_a_program_mod_account() {
    new_test_ext().execute_with(|| {
        // Setup: Ensure programs exist and a verifying key is available
        let programs_info = setup_programs();
        let expected_verifying_key = BoundedVec::default();

        let mut registered_info = RegisteredInfo {
            programs_data: programs_info,
            program_modification_account: 2,
            derivation_path: vec![0],
            version_number: 1,
        };

        Registered::<Test>::insert(expected_verifying_key.clone(), &registered_info);
        assert_eq!(Registry::registered(expected_verifying_key.clone()).unwrap(), registered_info);

        // Idk why this state could happen but still test to make sure it fails with a noop if ModifiableKeys not set
        assert_noop!(
            Registry::change_program_modification_account(
                RuntimeOrigin::signed(2),
                expected_verifying_key.clone(),
                3
            ),
            Error::<Test>::NotAuthorized
        );

        ModifiableKeys::<Test>::insert(
            2,
            BoundedVec::try_from(vec![expected_verifying_key.clone()]).unwrap(),
        );
        assert_eq!(Registry::modifiable_keys(2), vec![expected_verifying_key.clone()]);

        assert_ok!(Registry::change_program_modification_account(
            RuntimeOrigin::signed(2),
            expected_verifying_key.clone(),
            3
        ));

        assert_eq!(
            Registry::modifiable_keys(3),
            vec![expected_verifying_key.clone()],
            "account 3 now has control of the account"
        );

        registered_info.program_modification_account = 3;
        assert_eq!(
            Registry::registered(expected_verifying_key.clone()).unwrap(),
            registered_info,
            "account 3 now in registered info"
        );
        assert_eq!(Registry::modifiable_keys(2), vec![], "account 2 no longer has control");

        // account 2 no longer in control, fails
        assert_noop!(
            Registry::change_program_modification_account(
                RuntimeOrigin::signed(2),
                expected_verifying_key.clone(),
                3
            ),
            Error::<Test>::NotAuthorized
        );
    })
}
