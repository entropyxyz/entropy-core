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

use codec::Encode;
use entropy_shared::{KeyVisibility, VERIFICATION_KEY_LENGTH};
use frame_support::{
    assert_noop, assert_ok,
    dispatch::{GetDispatchInfo, Pays},
    traits::Currency,
    BoundedVec,
};
use pallet_programs::ProgramInfo;
use pallet_registry::Call as RegistryCall;
use sp_core::H256;
use sp_runtime::{
    traits::{Hash, SignedExtension},
    transaction_validity::{TransactionValidity, ValidTransaction},
};

use crate as pallet_registry;
use crate::{
    mock::*, Error, JumpStartDetails, JumpStartStatus, ModifiableKeys, ProgramInstance, Registered,
    RegisteredInfo, RegisteringDetails, ValidateConfirmRegistered,
};

#[test]
fn it_tests_get_validator_rotation() {
    new_test_ext().execute_with(|| {
        let result_1 = Registry::get_validator_rotation(0, 0).unwrap();
        let result_2 = Registry::get_validator_rotation(1, 0).unwrap();
        assert_eq!(result_1, 1);
        assert_eq!(result_2, 2);

        let result_3 = Registry::get_validator_rotation(0, 1).unwrap();
        let result_4 = Registry::get_validator_rotation(1, 1).unwrap();
        assert_eq!(result_3, 5);
        assert_eq!(result_4, 6);

        let result_5 = Registry::get_validator_rotation(0, 100).unwrap();
        let result_6 = Registry::get_validator_rotation(1, 100).unwrap();
        assert_eq!(result_5, 1);
        assert_eq!(result_6, 6);

        let result_7 = Registry::get_validator_rotation(0, 101).unwrap();
        let result_8 = Registry::get_validator_rotation(1, 101).unwrap();
        assert_eq!(result_7, 5);
        assert_eq!(result_8, 7);

        pallet_staking_extension::IsValidatorSynced::<Test>::insert(7, false);

        let result_9 = Registry::get_validator_rotation(1, 101).unwrap();
        assert_eq!(result_9, 6);

        // really big number does not crash
        let result_10 = Registry::get_validator_rotation(0, 1000000000000000000).unwrap();
        assert_eq!(result_10, 1);
    });
}

#[test]
fn registration_committee_selection_works() {
    new_test_ext().execute_with(|| {
        let (alice, bob) = (1, 2);

        // In genesis we have Alice and Bob assigned to signing groups 1 and 2, respectively, where
        // subgroup 1 has two members and subgroup 2 has three members.
        //
        // As such, we expect Alice to be part of a signing committee on every two blocks and Bob to
        // be part of a signing committee every three blocks.
        for block_number in 0..25 {
            let block_number = block_number as u64;

            if block_number % 2 == 0 {
                assert!(Registry::is_in_committee(&alice, block_number).unwrap());
            } else {
                assert!(!Registry::is_in_committee(&alice, block_number).unwrap());
            }

            if block_number % 3 == 0 {
                assert!(Registry::is_in_committee(&bob, block_number).unwrap());
            } else {
                assert!(!Registry::is_in_committee(&bob, block_number).unwrap());
            }
        }
    })
}

#[test]
fn non_authority_cannot_be_part_of_registration_committee() {
    new_test_ext().execute_with(|| {
        let not_an_authority = 99;
        assert!(Registry::is_in_committee(&not_an_authority, 0).is_err());
    });
}

#[test]
fn it_registers_a_user() {
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 0,
            },
        );

        assert_ok!(Registry::register(
            RuntimeOrigin::signed(1),
            2 as <Test as frame_system::Config>::AccountId,
            KeyVisibility::Public,
            programs_info,
        ));
        assert_eq!(Registry::dkg(0), vec![1u64.encode()]);
        assert_eq!(
            pallet_programs::Programs::<Test>::get(program_hash).unwrap().ref_counter,
            1,
            "ref counter is incremented"
        );
    });
}

#[test]
fn it_jumps_the_network() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            Registry::jump_start_progress(),
            JumpStartDetails { jump_start_status: JumpStartStatus::Ready, confirmations: vec![] },
            "Checks default status of jump start detail"
        );
        assert_ok!(Registry::jump_start_network(RuntimeOrigin::signed(1)));
        assert_eq!(
            Registry::dkg(0),
            vec![H256::zero().encode()],
            "ensures a dkg message for the jump start network is prepped"
        );
        assert_eq!(
            Registry::jump_start_progress(),
            JumpStartDetails {
                jump_start_status: JumpStartStatus::InProgress(0),
                confirmations: vec![]
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
            Registry::jump_start_progress(),
            JumpStartDetails {
                jump_start_status: JumpStartStatus::InProgress(100),
                confirmations: vec![]
            },
            "ensures jump start is called again if too many blocks passed"
        );
    });
}

#[test]
fn it_tests_jump_start_result() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Registry::jump_start_results(RuntimeOrigin::signed(1), 0,),
            Error::<Test>::NoThresholdKey
        );
        pallet_staking_extension::ThresholdToStash::<Test>::insert(1, 1);
        assert_noop!(
            Registry::jump_start_results(RuntimeOrigin::signed(1), 3,),
            Error::<Test>::NotInSigningGroup
        );

        assert_noop!(
            Registry::jump_start_results(RuntimeOrigin::signed(1), 0,),
            Error::<Test>::JumpStartNotInProgress
        );
        // trigger jump start
        assert_ok!(Registry::jump_start_network(RuntimeOrigin::signed(1)));

        assert_ok!(Registry::jump_start_results(RuntimeOrigin::signed(1), 0,));
        assert_eq!(
            Registry::jump_start_progress(),
            JumpStartDetails {
                jump_start_status: JumpStartStatus::InProgress(0),
                confirmations: vec![0]
            },
            "Jump start recieves a confirmation"
        );
        assert_noop!(
            Registry::jump_start_results(RuntimeOrigin::signed(1), 0,),
            Error::<Test>::AlreadyConfirmed
        );

        pallet_staking_extension::ThresholdToStash::<Test>::insert(2, 2);
        assert_ok!(Registry::jump_start_results(RuntimeOrigin::signed(2), 1,));
        assert_eq!(
            Registry::jump_start_progress(),
            JumpStartDetails { jump_start_status: JumpStartStatus::Done, confirmations: vec![] },
            "Jump start in done status after all confirmations"
        );
    });
}

#[test]
fn it_confirms_registers_a_user() {
    new_test_ext().execute_with(|| {
        let expected_verifying_key =
            BoundedVec::try_from(vec![0; VERIFICATION_KEY_LENGTH as usize]).unwrap();
        assert_noop!(
            Registry::confirm_register(
                RuntimeOrigin::signed(1),
                1,
                0,
                expected_verifying_key.clone()
            ),
            Error::<Test>::NoThresholdKey
        );

        pallet_staking_extension::ThresholdToStash::<Test>::insert(1, 1);

        assert_noop!(
            Registry::confirm_register(
                RuntimeOrigin::signed(1),
                1,
                0,
                expected_verifying_key.clone()
            ),
            Error::<Test>::NotRegistering
        );

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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 0,
            },
        );

        assert_ok!(Registry::register(
            RuntimeOrigin::signed(1),
            2 as <Test as frame_system::Config>::AccountId,
            KeyVisibility::Private([0; 32]),
            programs_info.clone(),
        ));
        assert_noop!(
            Registry::confirm_register(
                RuntimeOrigin::signed(1),
                1,
                3,
                expected_verifying_key.clone()
            ),
            Error::<Test>::NotInSigningGroup
        );

        pallet_staking_extension::ThresholdToStash::<Test>::insert(2, 2);

        assert_noop!(
            Registry::confirm_register(
                RuntimeOrigin::signed(2),
                1,
                0,
                expected_verifying_key.clone()
            ),
            Error::<Test>::NotInSigningGroup
        );

        assert!(Registry::registered(expected_verifying_key.clone()).is_none());

        assert_ok!(Registry::confirm_register(
            RuntimeOrigin::signed(1),
            1,
            0,
            expected_verifying_key.clone()
        ));

        assert_noop!(
            Registry::confirm_register(
                RuntimeOrigin::signed(1),
                1,
                0,
                expected_verifying_key.clone()
            ),
            Error::<Test>::AlreadyConfirmed
        );

        let registering_info = RegisteringDetails::<Test> {
            confirmations: vec![0],
            programs_data: programs_info.clone(),
            key_visibility: KeyVisibility::Private([0; 32]),
            verifying_key: Some(expected_verifying_key.clone()),
            program_modification_account: 2,
            version_number: 1,
        };

        assert_eq!(Registry::registering(1), Some(registering_info));

        assert_ok!(Registry::confirm_register(
            RuntimeOrigin::signed(2),
            1,
            1,
            expected_verifying_key.clone()
        ));

        assert_eq!(Registry::registering(1), None);
        assert_eq!(
            Registry::registered(expected_verifying_key.clone()).unwrap(),
            RegisteredInfo {
                key_visibility: KeyVisibility::Private([0; 32]),
                programs_data: programs_info.clone(),
                program_modification_account: 2,
                version_number: 1,
            }
        );
        assert_eq!(
            Registry::modifiable_keys(2),
            vec![expected_verifying_key],
            "list of modifable keys exist"
        );
    });
}

#[test]
fn it_changes_a_program_pointer() {
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 1,
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 1,
            },
        );

        let expected_verifying_key = BoundedVec::default();

        let mut registered_info = RegisteredInfo {
            key_visibility: KeyVisibility::Public,
            programs_data: programs_info,
            program_modification_account: 2,
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 1,
            },
        );

        let expected_verifying_key = BoundedVec::default();

        let mut registered_info = RegisteredInfo {
            key_visibility: KeyVisibility::Public,
            programs_data: programs_info,
            program_modification_account: 2,
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

#[test]
fn it_fails_on_non_matching_verifying_keys() {
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 0,
            },
        );

        let expected_verifying_key =
            BoundedVec::try_from(vec![0; VERIFICATION_KEY_LENGTH as usize]).unwrap();
        let unexpected_verifying_key =
            BoundedVec::try_from(vec![1; VERIFICATION_KEY_LENGTH as usize]).unwrap();

        assert_ok!(Registry::register(
            RuntimeOrigin::signed(1),
            2 as <Test as frame_system::Config>::AccountId,
            KeyVisibility::Private([0; 32]),
            programs_info,
        ));
        pallet_staking_extension::ThresholdToStash::<Test>::insert(1, 1);
        pallet_staking_extension::ThresholdToStash::<Test>::insert(2, 2);

        assert_ok!(Registry::confirm_register(
            RuntimeOrigin::signed(1),
            1,
            0,
            expected_verifying_key.clone()
        ));

        // uses different verifying key
        assert_ok!(Registry::confirm_register(
            RuntimeOrigin::signed(2),
            1,
            1,
            unexpected_verifying_key.try_into().unwrap()
        ));

        // not registered or registering
        assert_eq!(Registry::registering(1), None);
        assert_eq!(Registry::registered(expected_verifying_key.clone()), None);
    })
}
#[test]
fn it_doesnt_allow_double_registering() {
    new_test_ext().execute_with(|| {
        // register a user
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 0,
            },
        );

        assert_ok!(Registry::register(
            RuntimeOrigin::signed(1),
            2,
            KeyVisibility::Public,
            programs_info.clone(),
        ));

        // error if they try to submit another request, even with a different program key
        assert_noop!(
            Registry::register(RuntimeOrigin::signed(1), 2, KeyVisibility::Public, programs_info),
            Error::<Test>::AlreadySubmitted
        );
    });
}

#[test]
fn it_fails_no_program() {
    new_test_ext().execute_with(|| {
        // register a user
        let non_existing_program = vec![10];
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&non_existing_program);
        let programs_info = BoundedVec::try_from(vec![ProgramInstance {
            program_pointer: program_hash,
            program_config: vec![],
        }])
        .unwrap();

        assert_noop!(
            Registry::register(RuntimeOrigin::signed(1), 2, KeyVisibility::Public, programs_info),
            Error::<Test>::NoProgramSet
        );
    });
}

#[test]
fn it_fails_empty_program_list() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Registry::register(
                RuntimeOrigin::signed(1),
                2,
                KeyVisibility::Public,
                BoundedVec::try_from(vec![]).unwrap(),
            ),
            Error::<Test>::NoProgramSet
        );
    });
}

#[test]
fn it_tests_prune_registration() {
    new_test_ext().execute_with(|| {
        let inital_program = vec![10];
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&inital_program);
        let programs_info = BoundedVec::try_from(vec![ProgramInstance {
            program_pointer: program_hash,
            program_config: vec![],
        }])
        .unwrap();

        pallet_programs::Programs::<Test>::insert(
            program_hash,
            ProgramInfo {
                bytecode: inital_program.clone(),
                configuration_schema: inital_program.clone(),
                auxiliary_data_schema: inital_program.clone(),
                oracle_data_pointer: inital_program.clone(),
                deployer: 1,
                ref_counter: 1,
            },
        );

        Balances::make_free_balance_be(&2, 100);
        // register a user
        assert_ok!(Registry::register(
            RuntimeOrigin::signed(1),
            2,
            KeyVisibility::Public,
            programs_info,
        ));
        assert_eq!(
            pallet_programs::Programs::<Test>::get(program_hash).unwrap().ref_counter,
            2,
            "ref counter is increment"
        );
        assert!(Registry::registering(1).is_some(), "Make sure there is registering state");
        assert_ok!(Registry::prune_registration(RuntimeOrigin::signed(1)));
        assert_eq!(Registry::registering(1), None, "Make sure registering is pruned");
        assert_eq!(
            pallet_programs::Programs::<Test>::get(program_hash).unwrap().ref_counter,
            1,
            "ref counter is decremented"
        );
    });
}
#[test]
fn it_provides_free_txs_confirm_done() {
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 0,
            },
        );

        let expected_verifying_key = BoundedVec::default();
        assert_ok!(Registry::register(
            RuntimeOrigin::signed(5),
            2 as <Test as frame_system::Config>::AccountId,
            KeyVisibility::Public,
            programs_info,
        ));
        let p = ValidateConfirmRegistered::<Test>::new();
        let c = RuntimeCall::Registry(RegistryCall::confirm_register {
            sig_req_account: 5,
            signing_subgroup: 0,
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&7, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(1)"]
fn it_provides_free_txs_confirm_done_fails_1() {
    new_test_ext().execute_with(|| {
        let expected_verifying_key = BoundedVec::default();
        let p = ValidateConfirmRegistered::<Test>::new();
        let c = RuntimeCall::Registry(RegistryCall::confirm_register {
            sig_req_account: 5,
            signing_subgroup: 0,
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&2, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(2)"]
fn it_provides_free_txs_confirm_done_fails_2() {
    new_test_ext().execute_with(|| {
        let expected_verifying_key = BoundedVec::default();
        let p = ValidateConfirmRegistered::<Test>::new();
        let c = RuntimeCall::Registry(RegistryCall::confirm_register {
            sig_req_account: 5,
            signing_subgroup: 0,
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&7, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}

// TODO fails 3
#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(3)"]
fn it_provides_free_txs_confirm_done_fails_3() {
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 0,
            },
        );

        let expected_verifying_key =
            BoundedVec::try_from(vec![0; VERIFICATION_KEY_LENGTH as usize]).unwrap();
        assert_ok!(Registry::register(
            RuntimeOrigin::signed(5),
            2 as <Test as frame_system::Config>::AccountId,
            KeyVisibility::Public,
            programs_info,
        ));

        assert_ok!(Registry::confirm_register(
            RuntimeOrigin::signed(7),
            5,
            0,
            expected_verifying_key.clone()
        ));
        let p = ValidateConfirmRegistered::<Test>::new();
        let c = RuntimeCall::Registry(RegistryCall::confirm_register {
            sig_req_account: 5,
            signing_subgroup: 0,
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&7, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(4)"]
fn it_provides_free_txs_confirm_done_fails_4() {
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 0,
            },
        );

        let expected_verifying_key = BoundedVec::default();
        assert_ok!(Registry::register(
            RuntimeOrigin::signed(5),
            2 as <Test as frame_system::Config>::AccountId,
            KeyVisibility::Public,
            programs_info,
        ));
        let p = ValidateConfirmRegistered::<Test>::new();
        let c = RuntimeCall::Registry(RegistryCall::confirm_register {
            sig_req_account: 5,
            signing_subgroup: 5,
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&7, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(5)"]
fn it_provides_free_txs_confirm_done_fails_5() {
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
                oracle_data_pointer: empty_program.clone(),
                deployer: 1,
                ref_counter: 0,
            },
        );

        let expected_verifying_key = BoundedVec::default();
        assert_ok!(Registry::register(
            RuntimeOrigin::signed(5),
            2 as <Test as frame_system::Config>::AccountId,
            KeyVisibility::Public,
            programs_info,
        ));
        let p = ValidateConfirmRegistered::<Test>::new();
        let c = RuntimeCall::Registry(RegistryCall::confirm_register {
            sig_req_account: 5,
            signing_subgroup: 0,
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&4, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}
