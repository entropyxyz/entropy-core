use frame_support::{
    assert_noop, assert_ok,
    traits::OnInitialize,
    weights::{GetDispatchInfo, Pays},
};
use pallet_relayer::Call as RelayerCall;
use sp_runtime::{
    traits::SignedExtension,
    transaction_validity::{TransactionValidity, ValidTransaction},
};
use substrate_common::{Message, SigRequest};

use crate as pallet_relayer;
use crate::{mock::*, Error, Failures, PrevalidateRelayer, RegisteringDetails, Responsibility};

const NULL_ARR: [u8; 32] = [0; 32];
pub const SIG_HASH: &[u8; 64] = b"d188f0d99145e7ddbd0f1e46e7fd406db927441584571c623aff1d1652e14b06";

#[test]
fn it_preps_transaction() {
    new_test_ext().execute_with(|| {
		let ip_addresses: Vec<Vec<u8>> = vec![vec![10], vec![11]];
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        let message =
            Message { account: vec![1, 0, 0, 0, 0, 0, 0, 0], sig_request: sig_request.clone(), ip_addresses };

        assert_ok!(Relayer::prep_transaction(Origin::signed(1), sig_request));

        assert_eq!(Relayer::messages(0), vec![message]);
    });
}

#[test]
fn it_registers_a_user() {
    new_test_ext().execute_with(|| {
        assert_ok!(Relayer::register(Origin::signed(1)));

        assert!(Relayer::registering(1).unwrap().is_registering);
    });
}

#[test]
fn it_confirms_registers_a_user() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Relayer::confirm_register(Origin::signed(1), 1, 0),
            Error::<Test>::NotRegistering
        );

        assert_ok!(Relayer::register(Origin::signed(1)));

        assert_noop!(
            Relayer::confirm_register(Origin::signed(1), 1, 3),
            Error::<Test>::InvalidSubgroup
        );

        assert_noop!(
            Relayer::confirm_register(Origin::signed(2), 1, 0),
            Error::<Test>::NotInSigningGroup
        );

        assert_eq!(Relayer::registered(1), None);

        assert_ok!(Relayer::confirm_register(Origin::signed(1), 1, 0));

        assert_noop!(
            Relayer::confirm_register(Origin::signed(1), 1, 0),
            Error::<Test>::AlreadyConfirmed
        );

        let registering_info = RegisteringDetails { is_registering: true, confirmations: vec![0] };

        assert_eq!(Relayer::registering(1), Some(registering_info));

        assert_ok!(Relayer::confirm_register(Origin::signed(2), 1, 1));

        assert_eq!(Relayer::registering(1), None);
        assert!(Relayer::registered(1).unwrap());
    });
}

#[test]
fn it_confirms_done() {
    new_test_ext().execute_with(|| {
        Responsibility::<Test>::insert(5, 2);
        let failures = vec![0u32, 3u32];
        pallet_staking_extension::ThresholdAccounts::<Test>::insert(2, (1, NULL_ARR));

        assert_ok!(Relayer::confirm_done(Origin::signed(1), 5, failures.clone()));
        assert_eq!(Relayer::failures(5), Some(failures.clone()));

        assert_noop!(
            Relayer::confirm_done(Origin::signed(1), 5, failures.clone()),
            Error::<Test>::AlreadySubmitted
        );
        assert_noop!(
            Relayer::confirm_done(Origin::signed(1), 6, failures.clone()),
            Error::<Test>::NoResponsibility
        );
        Responsibility::<Test>::insert(6, 3);
        assert_noop!(
            Relayer::confirm_done(Origin::signed(2), 6, failures.clone()),
            Error::<Test>::NoThresholdKey
        );
        pallet_staking_extension::ThresholdAccounts::<Test>::insert(2, (5, NULL_ARR));
        assert_noop!(
            Relayer::confirm_done(Origin::signed(2), 5, failures),
            Error::<Test>::NotYourResponsibility
        );
    });
}

#[test]
fn moves_active_to_pending() {
    new_test_ext().execute_with(|| {
        // no failures pings unresponsive
        System::set_block_number(3);
        Responsibility::<Test>::insert(3, 1);
        Relayer::on_initialize(5);
        assert_eq!(Relayer::unresponsive(1), 1);
        let failures = vec![0u32, 3u32];
        Failures::<Test>::insert(2, failures.clone());
        Failures::<Test>::insert(5, failures.clone());

		let ip_addresses: Vec<Vec<u8>> = vec![vec![10], vec![11]];
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        let message =
            Message { account: vec![1, 0, 0, 0, 0, 0, 0, 0], sig_request: sig_request.clone(), ip_addresses };

        assert_ok!(Relayer::prep_transaction(Origin::signed(1), sig_request));
        assert_eq!(Relayer::messages(3), vec![message.clone()]);

        // prunes old failure remove messages put into pending
        assert_eq!(Relayer::failures(2), Some(failures.clone()));
        Relayer::on_initialize(5);
        assert_eq!(Relayer::failures(2), None);
        assert_eq!(Relayer::messages(3), vec![]);
        assert_eq!(Relayer::pending(3), vec![message]);
        assert_eq!(Relayer::unresponsive(1), 0);
        // pending pruned
        Responsibility::<Test>::insert(4, 1);
        Failures::<Test>::insert(3, failures);
        Relayer::on_initialize(6);
        assert_eq!(Relayer::pending(3), vec![]);
        assert_eq!(Relayer::failures(3), None);
    });
}

#[test]
fn notes_responsibility() {
    new_test_ext().execute_with(|| {
        Responsibility::<Test>::insert(2, 1);
        Relayer::note_responsibility(5);
        assert_eq!(Relayer::responsibility(4), Some(11));
        assert_eq!(Relayer::responsibility(2), None);
    });
}

#[test]
fn it_provides_free_txs_prep_tx() {
    new_test_ext().execute_with(|| {
        assert_ok!(Relayer::register(Origin::signed(1)));
        assert_ok!(Relayer::confirm_register(Origin::signed(1), 1, 0));
        assert_ok!(Relayer::confirm_register(Origin::signed(2), 1, 1));

        let p = PrevalidateRelayer::<Test>::new();
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };

        let c = Call::Relayer(RelayerCall::prep_transaction { sig_request });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&1, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}

#[test]
fn it_fails_a_free_tx_prep_tx() {
    new_test_ext().execute_with(|| {
        let p = PrevalidateRelayer::<Test>::new();
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };

        let c = Call::Relayer(RelayerCall::prep_transaction { sig_request });
        let di = c.get_dispatch_info();
        let r = p.validate(&42, &c, &di, 20);
        assert!(r.is_err());
    });
}

#[test]
fn it_provides_free_txs_confirm_done() {
    new_test_ext().execute_with(|| {
        Responsibility::<Test>::insert(5, 1);
        pallet_staking_extension::ThresholdAccounts::<Test>::insert(1, (2, NULL_ARR));
        let p = PrevalidateRelayer::<Test>::new();
        let c = Call::Relayer(RelayerCall::confirm_done { block_number: 5, failures: vec![] });
        let di = c.get_dispatch_info();
        assert_eq!(di.pays_fee, Pays::No);
        let r = p.validate(&2, &c, &di, 20);
        assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(1)"]
fn it_fails_a_free_tx_confirm_done_err_1() {
    new_test_ext().execute_with(|| {
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };

        let p = PrevalidateRelayer::<Test>::new();
        let c = Call::Relayer(RelayerCall::prep_transaction { sig_request });
        let di = c.get_dispatch_info();
        let r = p.validate(&1, &c, &di, 20);
        r.unwrap()
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(2)"]
fn it_fails_a_free_tx_confirm_done_err_2() {
    new_test_ext().execute_with(|| {
        let p = PrevalidateRelayer::<Test>::new();
        let c = Call::Relayer(RelayerCall::confirm_done { block_number: 5, failures: vec![] });
        let di = c.get_dispatch_info();
        let r = p.validate(&1, &c, &di, 20);
        r.unwrap()
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(3)"]
fn it_fails_a_free_tx_confirm_done_err_3() {
    new_test_ext().execute_with(|| {
        Responsibility::<Test>::insert(5, 1);
        let p = PrevalidateRelayer::<Test>::new();
        let c = Call::Relayer(RelayerCall::confirm_done { block_number: 5, failures: vec![] });
        let di = c.get_dispatch_info();
        let r = p.validate(&42, &c, &di, 20);
        r.unwrap()
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(4)"]
fn it_fails_a_free_tx_confirm_done_err_4() {
    new_test_ext().execute_with(|| {
        Responsibility::<Test>::insert(5, 1);
        pallet_staking_extension::ThresholdAccounts::<Test>::insert(1, (2, NULL_ARR));
        Failures::<Test>::insert(5, vec![1]);
        let p = PrevalidateRelayer::<Test>::new();
        let c = Call::Relayer(RelayerCall::confirm_done { block_number: 5, failures: vec![] });
        let di = c.get_dispatch_info();
        let r = p.validate(&1, &c, &di, 20);
        r.unwrap()
    });
}

#[test]
#[should_panic = "TransactionValidityError::Invalid(InvalidTransaction::Custom(5)"]
fn it_fails_a_free_tx_confirm_done_err_5() {
    new_test_ext().execute_with(|| {
        Responsibility::<Test>::insert(5, 1);
        pallet_staking_extension::ThresholdAccounts::<Test>::insert(1, (2, NULL_ARR));
        Failures::<Test>::insert(5, vec![1]);
        let p = PrevalidateRelayer::<Test>::new();
        let c = Call::Relayer(RelayerCall::confirm_done { block_number: 5, failures: vec![] });
        let di = c.get_dispatch_info();
        let r = p.validate(&2, &c, &di, 20);
        r.unwrap()
    });
}
