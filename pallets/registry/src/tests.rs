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
use pallet_staking_extension::ServerInfo;
use sp_runtime::{
    traits::{Hash, SignedExtension},
    transaction_validity::{TransactionValidity, ValidTransaction},
};

use crate as pallet_registry;
use crate::{
    mock::*, Error, ProgramInstance, Registered, RegisteredInfo, RegisteringDetails,
    ValidateConfirmRegistered,
};

const NULL_ARR: [u8; 32] = [0; 32];

#[test]
fn it_tests_get_validators_info() {
    new_test_ext().execute_with(|| {
        let result_1 = Registry::get_validators_info().unwrap();
        let server_info_1 =
            ServerInfo { tss_account: 3, x25519_public_key: NULL_ARR, endpoint: vec![10] };
        let server_info_2 =
            ServerInfo { tss_account: 4, x25519_public_key: NULL_ARR, endpoint: vec![11] };

        assert_eq!(result_1, vec![server_info_1, server_info_2]);
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
fn it_confirms_registers_a_user() {
    new_test_ext().execute_with(|| {
        let expected_verifying_key =
            BoundedVec::try_from(vec![0; VERIFICATION_KEY_LENGTH as usize]).unwrap();
        assert_noop!(
            Registry::confirm_register(RuntimeOrigin::signed(1), 1, expected_verifying_key.clone()),
            Error::<Test>::NoThresholdKey
        );

        pallet_staking_extension::ThresholdToStash::<Test>::insert(1, 1);

        assert_noop!(
            Registry::confirm_register(RuntimeOrigin::signed(1), 1, expected_verifying_key.clone()),
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

        pallet_staking_extension::ThresholdToStash::<Test>::insert(2, 2);

        assert!(Registry::registered(expected_verifying_key.clone()).is_none());

        assert_ok!(Registry::confirm_register(
            RuntimeOrigin::signed(1),
            1,
            expected_verifying_key.clone()
        ));

        assert_noop!(
            Registry::confirm_register(RuntimeOrigin::signed(1), 1, expected_verifying_key.clone()),
            Error::<Test>::AlreadyConfirmed
        );

        assert_noop!(
            Registry::confirm_register(RuntimeOrigin::signed(7), 1, expected_verifying_key.clone()),
            Error::<Test>::NotValidator
        );

        let registering_info = RegisteringDetails::<Test> {
            confirmations: vec![1],
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
            expected_verifying_key.clone()
        ));

        // uses different verifying key
        assert_ok!(Registry::confirm_register(
            RuntimeOrigin::signed(2),
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
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&3, &c, &di, 20);
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
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&7, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}

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
            RuntimeOrigin::signed(3),
            5,
            expected_verifying_key.clone()
        ));
        let p = ValidateConfirmRegistered::<Test>::new();
        let c = RuntimeCall::Registry(RegistryCall::confirm_register {
            sig_req_account: 5,
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&3, &c, &di, 20);
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
            verifying_key: expected_verifying_key,
        });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&7, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}
