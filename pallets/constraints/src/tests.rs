

use frame_support::{assert_err, assert_noop, assert_ok, BoundedVec};
use sp_core::{H160};

use crate::{mock::*, Acl, AclKind, Arch, Error, SigReqAccounts};

// Tests:
// adds whitelist and checks max whitelist and already whitelisted
// check max whitelist
// error if not registered
// make sure error if no permission

/// consts used for testing
const CONSTRAINT_ACCOUNT: u64 = 1u64;
const SIG_REQ_ACCOUNT: u64 = 2u64;
const UNUSED_ACCOUNT: u64 = 3u64;

// Integration Test
#[test]
fn assert_modification_permissions_work_as_expected() {
    new_test_ext().execute_with(|| {
        // a valid one-address allowlist
        let valid_acl = Acl {
            acl: BoundedVec::try_from(vec![H160::from([0u8; 20])]).unwrap(),
            acl_type: AclKind::Allow,
            allow_null_recipient: false,
        };
        // make sure noone can add a constraint without explicit permissions
        assert_noop!(
            Constraints::update_acl(
                RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
                SIG_REQ_ACCOUNT,
                Arch::EVM,
                Some(valid_acl.clone()),
            ),
            Error::<Test>::NotAuthorized
        );

        // give permission to modify constraints and make sure the acl can be updated
        SigReqAccounts::<Test>::insert(&CONSTRAINT_ACCOUNT, &SIG_REQ_ACCOUNT, ());
        assert_ok!(Constraints::update_acl(
            RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
            SIG_REQ_ACCOUNT,
            Arch::EVM,
            Some(valid_acl.clone())
        ));
        assert_eq!(Constraints::acl(SIG_REQ_ACCOUNT, Arch::EVM), Ok(valid_acl.clone()));

        // make sure sig-req key can't modify or delete constraints
        assert_noop!(
            Constraints::update_acl(
                RuntimeOrigin::signed(SIG_REQ_ACCOUNT),
                SIG_REQ_ACCOUNT,
                Arch::EVM,
                Some(valid_acl.clone()),
            ),
            Error::<Test>::NotAuthorized
        );
        assert_noop!(
            Constraints::update_acl(
                RuntimeOrigin::signed(SIG_REQ_ACCOUNT),
                SIG_REQ_ACCOUNT,
                Arch::EVM,
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
                Arch::EVM,
                Some(valid_acl)
            ),
            Error::<Test>::NotAuthorized
        );

        // assert_noop!(
        //     Constraints::update_acl(
        //         RuntimeOrigin::signed(1),
        //     ),
        //     Error::<Test>::MaxWhitelist
        // );
        //     assert_ok!(Constraints::add_whitelist_address(
        //         RuntimeOrigin::signed(1),
        //         [address_2.clone(), address_3.clone()].to_vec()
        //     ));
        //     assert_eq!(Constraints::address_whitelist(1), [address_2.clone(),
        // address_3.clone()]);     assert_noop!(
        //         Constraints::add_whitelist_address(
        //             RuntimeOrigin::signed(1),
        //             [address_2.clone()].to_vec()
        //         ),
        //         Error::<Test>::AlreadyWhitelisted
        //     );
        //     assert_ok!(Constraints::add_whitelist_address(
        //         RuntimeOrigin::signed(1),
        //         [address_4.clone()].to_vec()
        //     ));
        //     assert_eq!(Constraints::address_whitelist(1), [address_2, address_3, address_4]);
        //     assert_noop!(
        //         Constraints::add_whitelist_address(RuntimeOrigin::signed(1),
        // [address_5].to_vec()),         Error::<Test>::MaxWhitelist
        //     );
        //     assert_noop!(
        //         Constraints::add_whitelist_address(
        //             RuntimeOrigin::signed(1),
        //             [[1, 12, 21].to_vec()].to_vec()
        //         ),
        //         Error::<Test>::AddressTooLong
        //     );
    });
}

#[test]
fn assert_storage_updates_as_expected() {
    new_test_ext().execute_with(|| {
        // a valid one-address allowlist
        let valid_acl = Acl {
            acl: BoundedVec::try_from(vec![H160::from([0u8; 20])]).unwrap(),
            acl_type: AclKind::Allow,
            allow_null_recipient: false,
        };

        // give permission to modify constraints
        SigReqAccounts::<Test>::insert(&CONSTRAINT_ACCOUNT, &SIG_REQ_ACCOUNT, ());

        // make sure acl is empty
        assert_err!(
            Constraints::acl(SIG_REQ_ACCOUNT, Arch::EVM),
            Error::<Test>::AccountDoesNotExist
        );

        // make sure we can update the ACL
        assert_ok!(Constraints::update_acl(
            RuntimeOrigin::signed(CONSTRAINT_ACCOUNT),
            SIG_REQ_ACCOUNT,
            Arch::EVM,
            Some(valid_acl.clone())
        ));

        // make sure acl updates
        assert_eq!(Constraints::acl(SIG_REQ_ACCOUNT, Arch::EVM), Ok(valid_acl));
    });
}
