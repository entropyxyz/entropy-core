use frame_support::{assert_noop, assert_ok, traits::Currency};
use pallet_balances::Error as BalancesError;

use crate::{mock::*, AllowedToModifyProgram, Error};

/// consts used for testing
const CONSTRAINT_ACCOUNT: u64 = 1u64;
const SIG_REQ_ACCOUNT: u64 = 2u64;

#[test]
fn set_constraints() {
    new_test_ext().execute_with(|| {
        let empty_constraint = vec![];
        let constraint = vec![10u8, 11u8];
        let too_long = vec![1u8, 2u8, 3u8, 4u8, 5u8];

        // make sure no one can add a constraint without explicit permissions
        assert_noop!(
            ConstraintsPallet::update_constraints(
                RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
                SIG_REQ_ACCOUNT,
                constraint.clone(),
            ),
            Error::<Test>::NotAuthorized
        );

        AllowedToModifyProgram::<Test>::insert(CONSTRAINT_ACCOUNT, SIG_REQ_ACCOUNT, ());

        // can't pay deposit
        assert_noop!(
            ConstraintsPallet::update_constraints(
                RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
                SIG_REQ_ACCOUNT,
                constraint.clone(),
            ),
            BalancesError::<Test>::InsufficientBalance
        );

        Balances::make_free_balance_be(&CONSTRAINT_ACCOUNT, 100);

        // It's okay to have an empty constraint
        assert_ok!(ConstraintsPallet::update_constraints(
            RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
            SIG_REQ_ACCOUNT,
            empty_constraint.clone()
        ));

        assert_ok!(ConstraintsPallet::update_constraints(
            RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
            SIG_REQ_ACCOUNT,
            constraint.clone()
        ));

        assert_eq!(ConstraintsPallet::bytecode(SIG_REQ_ACCOUNT).unwrap(), constraint);
        assert_eq!(Balances::free_balance(CONSTRAINT_ACCOUNT), 90);

        // deposit refunded partial
        assert_ok!(ConstraintsPallet::update_constraints(
            RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
            SIG_REQ_ACCOUNT,
            vec![10u8]
        ));
        assert_eq!(Balances::free_balance(CONSTRAINT_ACCOUNT), 95);

        // deposit refunded full
        assert_ok!(ConstraintsPallet::update_constraints(
            RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
            SIG_REQ_ACCOUNT,
            vec![]
        ));
        assert_eq!(Balances::free_balance(CONSTRAINT_ACCOUNT), 100);

        assert_noop!(
            ConstraintsPallet::update_constraints(
                RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
                SIG_REQ_ACCOUNT,
                too_long,
            ),
            Error::<Test>::ProgramLengthExceeded
        );
    });
}
