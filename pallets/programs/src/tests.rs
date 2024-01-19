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

use frame_support::{assert_noop, assert_ok, traits::Currency};
use pallet_balances::Error as BalancesError;
use sp_runtime::traits::Hash;

use crate::{mock::*, Error, ProgramInfo, Programs};

/// consts used for testing
const PROGRAM_MODIFICATION_ACCOUNT: u64 = 1u64;

#[test]
fn set_program() {
    new_test_ext().execute_with(|| {
        let program = vec![10u8, 11u8];
        let program_2 = vec![12u8, 13u8];
        let configuration_interface = vec![14u8];
        let too_long = vec![1u8, 2u8, 3u8, 4u8, 5u8];
        let mut hash_input: Vec<u8> = vec![];
        hash_input.extend(&program);
        hash_input.extend(&configuration_interface);

        let program_hash = <Test as frame_system::Config>::Hashing::hash(&hash_input);
        // can't pay deposit
        assert_noop!(
            ProgramsPallet::set_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program.clone(),
                configuration_interface.clone()
            ),
            BalancesError::<Test>::InsufficientBalance
        );

        Balances::make_free_balance_be(&PROGRAM_MODIFICATION_ACCOUNT, 100);

        assert_ok!(ProgramsPallet::set_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            program.clone(),
            configuration_interface.clone()
        ));
        let program_result = ProgramInfo {
            bytecode: program.clone(),
            configuration_interface: configuration_interface.clone(),
            program_modification_account: PROGRAM_MODIFICATION_ACCOUNT,
            ref_counter: 0u128,
        };
        assert_eq!(
            ProgramsPallet::programs(program_hash).unwrap(),
            program_result,
            "Program gets set"
        );
        assert_eq!(
            ProgramsPallet::owned_programs(PROGRAM_MODIFICATION_ACCOUNT),
            vec![program_hash],
            "Program gets set to owner"
        );
        // deposit taken
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 85, "Deposit charged");

        // program is already set
        assert_noop!(
            ProgramsPallet::set_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program.clone(),
                configuration_interface.clone()
            ),
            Error::<Test>::ProgramAlreadySet
        );

        // Too many programs set
        assert_noop!(
            ProgramsPallet::set_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program_2.clone(),
                configuration_interface.clone()
            ),
            Error::<Test>::TooManyProgramsOwned
        );
        // program too long
        assert_noop!(
            ProgramsPallet::set_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                too_long,
                configuration_interface
            ),
            Error::<Test>::ProgramLengthExceeded
        );
    });
}

#[test]
fn remove_program() {
    new_test_ext().execute_with(|| {
        let program = vec![10u8, 11u8];
        let configuration_interface = vec![14u8];
        let mut hash_input: Vec<u8> = vec![];
        hash_input.extend(&program);
        hash_input.extend(&configuration_interface);
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&hash_input);

        // no program
        assert_noop!(
            ProgramsPallet::remove_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program_hash
            ),
            Error::<Test>::NoProgramDefined
        );

        // set a program
        Balances::make_free_balance_be(&PROGRAM_MODIFICATION_ACCOUNT, 100);
        assert_ok!(ProgramsPallet::set_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            program.clone(),
            configuration_interface.clone()
        ));
        assert_eq!(
            ProgramsPallet::owned_programs(PROGRAM_MODIFICATION_ACCOUNT),
            vec![program_hash],
            "Program gets set to owner"
        );
        assert!(ProgramsPallet::programs(program_hash).is_some(), "Program gets set");
        assert_eq!(
            ProgramsPallet::programs(program_hash).unwrap().bytecode,
            program,
            "Program bytecode gets set"
        );
        assert_eq!(
            ProgramsPallet::programs(program_hash).unwrap().program_modification_account,
            PROGRAM_MODIFICATION_ACCOUNT,
            "Program modification account gets set"
        );
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 85, "Deposit charged");

        // not authorized
        assert_noop!(
            ProgramsPallet::remove_program(RuntimeOrigin::signed(2), program_hash),
            Error::<Test>::NotAuthorized
        );

        assert_ok!(ProgramsPallet::remove_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            program_hash
        ));
        assert!(ProgramsPallet::programs(program_hash).is_none(), "Program removed");
        assert_eq!(
            ProgramsPallet::owned_programs(PROGRAM_MODIFICATION_ACCOUNT),
            vec![],
            "Program removed from owner"
        );
        // refunded
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 100, "User gets refunded");
    });
}

#[test]
fn remove_program_fails_ref_count() {
    new_test_ext().execute_with(|| {
        let program = vec![10u8, 11u8];
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&program);
        let configuration_interface = vec![14u8];

        Programs::<Test>::insert(
            program_hash,
            ProgramInfo {
                bytecode: program,
                configuration_interface,
                program_modification_account: PROGRAM_MODIFICATION_ACCOUNT,
                ref_counter: 1u128,
            },
        );

        assert_noop!(
            ProgramsPallet::remove_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program_hash
            ),
            Error::<Test>::ProgramInUse
        );
    });
}
