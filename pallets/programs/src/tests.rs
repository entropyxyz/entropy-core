use frame_support::{assert_noop, assert_ok, traits::Currency};
use pallet_balances::Error as BalancesError;
use sp_runtime::traits::Hash;

use crate::{mock::*, Error, ProgramInfo};

/// consts used for testing
const PROGRAM_MODIFICATION_ACCOUNT: u64 = 1u64;

#[test]
fn set_program() {
    new_test_ext().execute_with(|| {
        let program = vec![10u8, 11u8];
        let program_2 = vec![12u8, 13u8];
        let too_long = vec![1u8, 2u8, 3u8, 4u8, 5u8];
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&program);
        // can't pay deposit
        assert_noop!(
            ProgramsPallet::set_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program.clone()
            ),
            BalancesError::<Test>::InsufficientBalance
        );

        Balances::make_free_balance_be(&PROGRAM_MODIFICATION_ACCOUNT, 100);

        assert_ok!(ProgramsPallet::set_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            program.clone()
        ));
        let program_result = ProgramInfo {
            bytecode: program.clone(),
            program_modification_account: PROGRAM_MODIFICATION_ACCOUNT,
        };
        assert_eq!(
            ProgramsPallet::bytecode(program_hash).unwrap(),
            program_result,
            "Program gets set"
        );
        assert_eq!(
            ProgramsPallet::owned_programs(PROGRAM_MODIFICATION_ACCOUNT),
            vec![program_hash],
            "Program gets set to owner"
        );
        // deposit taken
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 90, "Deposit charged");

        // program is already set
        assert_noop!(
            ProgramsPallet::set_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program.clone()
            ),
            Error::<Test>::ProgramAlreadySet
        );

        // Too many programs set
        assert_noop!(
            ProgramsPallet::set_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program_2.clone()
            ),
            Error::<Test>::TooManyProgramsOwned
        );
        // program too long
        assert_noop!(
            ProgramsPallet::set_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                too_long,
            ),
            Error::<Test>::ProgramLengthExceeded
        );
    });
}

#[test]
fn remove_program() {
    new_test_ext().execute_with(|| {
        let program = vec![10u8, 11u8];
        let program_hash = <Test as frame_system::Config>::Hashing::hash(&program);

        // no program
        assert_noop!(
            ProgramsPallet::remove_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                program_hash.clone()
            ),
            Error::<Test>::NoProgramDefined
        );

        // set a program
        Balances::make_free_balance_be(&PROGRAM_MODIFICATION_ACCOUNT, 100);
        assert_ok!(ProgramsPallet::set_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            program.clone()
        ));
        assert_eq!(
            ProgramsPallet::owned_programs(PROGRAM_MODIFICATION_ACCOUNT),
            vec![program_hash],
            "Program gets set to owner"
        );
        assert!(ProgramsPallet::bytecode(program_hash).is_some(), "Program gets set");
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 90, "Deposit charged");

        // not authorized
        assert_noop!(
            ProgramsPallet::remove_program(RuntimeOrigin::signed(2), program_hash.clone()),
            Error::<Test>::NotAuthorized
        );

        assert_ok!(ProgramsPallet::remove_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            program_hash.clone()
        ));
        assert!(ProgramsPallet::bytecode(program_hash).is_none(), "Program removed");
        assert_eq!(
            ProgramsPallet::owned_programs(PROGRAM_MODIFICATION_ACCOUNT),
            vec![],
            "Program removed from owner"
        );
        // refunded
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 100, "User gets refunded");
    });
}
