use frame_support::{assert_noop, assert_ok, traits::Currency};
use pallet_balances::Error as BalancesError;

use crate::{mock::*, AllowedToModifyProgram, Error};

/// consts used for testing
const PROGRAM_MODIFICATION_ACCOUNT: u64 = 1u64;
const SIG_REQ_ACCOUNT: u64 = 2u64;

#[test]
fn set_programs() {
    new_test_ext().execute_with(|| {
        let empty_program = vec![];
        let program = vec![10u8, 11u8];
        let too_long = vec![1u8, 2u8, 3u8, 4u8, 5u8];

        // make sure no one can add a program without explicit permissions
        assert_noop!(
            ConstraintsPallet::update_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                SIG_REQ_ACCOUNT,
                program.clone(),
            ),
            Error::<Test>::NotAuthorized
        );

        AllowedToModifyProgram::<Test>::insert(PROGRAM_MODIFICATION_ACCOUNT, SIG_REQ_ACCOUNT, ());

        // can't pay deposit
        assert_noop!(
            ConstraintsPallet::update_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                SIG_REQ_ACCOUNT,
                program.clone(),
            ),
            BalancesError::<Test>::InsufficientBalance
        );

        Balances::make_free_balance_be(&PROGRAM_MODIFICATION_ACCOUNT, 100);

        // It's okay to have an empty program
        assert_ok!(ConstraintsPallet::update_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            SIG_REQ_ACCOUNT,
            empty_program.clone()
        ));

        assert_ok!(ConstraintsPallet::update_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            SIG_REQ_ACCOUNT,
            program.clone()
        ));

        assert_eq!(ConstraintsPallet::bytecode(SIG_REQ_ACCOUNT).unwrap(), program);
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 90);

        // deposit refunded partial
        assert_ok!(ConstraintsPallet::update_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            SIG_REQ_ACCOUNT,
            vec![10u8]
        ));
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 95);

        // deposit refunded full
        assert_ok!(ConstraintsPallet::update_program(
            RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
            SIG_REQ_ACCOUNT,
            vec![]
        ));
        assert_eq!(Balances::free_balance(PROGRAM_MODIFICATION_ACCOUNT), 100);

        assert_noop!(
            ConstraintsPallet::update_program(
                RuntimeOrigin::signed(PROGRAM_MODIFICATION_ACCOUNT),
                SIG_REQ_ACCOUNT,
                too_long,
            ),
            Error::<Test>::ProgramLengthExceeded
        );
    });
}
