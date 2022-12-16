use frame_support::{assert_err, assert_noop, assert_ok};
use sp_core::H160;

use crate::{mock::*, Acl, Arch, Error, SigReqAccounts};

/// consts used for testing
const CONSTRAINT_ACCOUNT: u64 = 1u64;
const SIG_REQ_ACCOUNT: u64 = 2u64;

// Integration Test
#[test]
fn assert_permissions_are_restricted_properly() {
    new_test_ext().execute_with(|| {
        // a valid one-address allowlist
        let valid_acl = Acl::<H160>::try_from(vec![H160::default()]).unwrap();

        // make sure noone can add a constraint without explicit permissions
        assert_noop!(
            Constraints::update_acl(
                RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
                SIG_REQ_ACCOUNT,
                Arch::Evm,
                Some(valid_acl.clone()),
            ),
            Error::<Test>::NotAuthorized
        );

        // give permission to modify constraints and make sure the acl can be updated
        SigReqAccounts::<Test>::insert(&CONSTRAINT_ACCOUNT, &SIG_REQ_ACCOUNT, ());
        assert_ok!(Constraints::update_acl(
            RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
            SIG_REQ_ACCOUNT,
            Arch::Evm,
            Some(valid_acl.clone())
        ));
        assert_eq!(Constraints::acl(SIG_REQ_ACCOUNT, Arch::Evm), Ok(valid_acl.clone()));

        // make sure sig-req key can't modify or delete constraints
        assert_noop!(
            Constraints::update_acl(
                RuntimeOrigin::signed(SIG_REQ_ACCOUNT),
                SIG_REQ_ACCOUNT,
                Arch::Evm,
                Some(valid_acl.clone()),
            ),
            Error::<Test>::NotAuthorized
        );
        assert_noop!(
            Constraints::update_acl(
                RuntimeOrigin::signed(SIG_REQ_ACCOUNT),
                SIG_REQ_ACCOUNT,
                Arch::Evm,
                None
            ),
            Error::<Test>::NotAuthorized
        );

        // removing permissions should prevent modification
        SigReqAccounts::<Test>::remove(&CONSTRAINT_ACCOUNT, &SIG_REQ_ACCOUNT);
        assert_noop!(
            Constraints::update_acl(
                RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
                SIG_REQ_ACCOUNT,
                Arch::Evm,
                Some(valid_acl)
            ),
            Error::<Test>::NotAuthorized
        );
    });
}

#[test]
fn return_error_if_constraints_arent_set() {
    new_test_ext().execute_with(|| {
        // a valid one-address allowlist
        let valid_acl = Acl::<H160>::try_from(vec![H160::default()]).unwrap();

        // give permission to modify constraints
        SigReqAccounts::<Test>::insert(&CONSTRAINT_ACCOUNT, &SIG_REQ_ACCOUNT, ());

        // make sure acl is empty
        assert_err!(
            Constraints::acl(SIG_REQ_ACCOUNT, Arch::Evm),
            Error::<Test>::AccountDoesNotExist
        );

        // make sure we can update the ACL
        assert_ok!(Constraints::update_acl(
            RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
            SIG_REQ_ACCOUNT,
            Arch::Evm,
            Some(valid_acl.clone())
        ));

        // make sure acl updates
        assert_eq!(Constraints::acl(SIG_REQ_ACCOUNT, Arch::Evm), Ok(valid_acl));
    });
}
