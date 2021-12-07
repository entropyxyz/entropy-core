use crate as pallet_relayer;
use crate::{mock::*, Message, PrevalidateRelayer, Error, Responsibility, Failures};
use frame_support::{
	assert_ok, assert_noop,
	weights::{GetDispatchInfo, Pays},
};
use pallet_relayer::Call as RelayerCall;
use sp_runtime::{
	traits::SignedExtension,
	transaction_validity::{TransactionValidity, ValidTransaction},
};

#[test]
fn it_preps_transaction() {
	new_test_ext().execute_with(|| {
		assert_ok!(Relayer::prep_transaction(Origin::signed(1), 42, 42));

		let message = Message { data_1: 42, data_2: 42 };

		assert_eq!(Relayer::messages(0), vec![message]);
	});
}

#[test]
fn it_confirms_done() {
	new_test_ext().execute_with(|| {
		Responsibility::<Test>::insert(5, 1);
		let failures = vec![0u32, 3u32];

		assert_ok!(Relayer::confirm_done(Origin::signed(1), 5, failures.clone()));
		assert_eq!(Relayer::failures(5), Some(failures.clone()));

		assert_noop!(Relayer::confirm_done(Origin::signed(1), 5, failures.clone()), Error::<Test>::AlreadySubmitted);
		assert_noop!(Relayer::confirm_done(Origin::signed(1), 6, failures.clone()), Error::<Test>::NoResponsibility);
		assert_noop!(Relayer::confirm_done(Origin::signed(2), 5, failures.clone()), Error::<Test>::NotYourResponsibility);

	});
}

#[test]
fn it_provides_free_txs_prep_tx() {
	new_test_ext().execute_with(|| {
		let p = PrevalidateRelayer::<Test>::new();
		let c = Call::Relayer(RelayerCall::prep_transaction { data_1: 42, data_2: 42 });
		let di = c.get_dispatch_info();
		assert_eq!(di.pays_fee, Pays::No);
		let r = p.validate(&42, &c, &di, 20);
		assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
	});
}

#[test]
fn it_fails_a_free_tx_prep_tx() {
	new_test_ext().execute_with(|| {
		let p = PrevalidateRelayer::<Test>::new();
		let c = Call::Relayer(RelayerCall::prep_transaction { data_1: 43, data_2: 42 });
		let di = c.get_dispatch_info();
		let r = p.validate(&42, &c, &di, 20);
		assert!(r.is_err());
	});
}

#[test]
fn it_provides_free_txs_confirm_done() {
	new_test_ext().execute_with(|| {
		Responsibility::<Test>::insert(5, 1);
		let p = PrevalidateRelayer::<Test>::new();
		let c = Call::Relayer(RelayerCall::confirm_done { block_number: 5, failures: vec![] });
		let di = c.get_dispatch_info();
		assert_eq!(di.pays_fee, Pays::No);
		let r = p.validate(&1, &c, &di, 20);
		assert_eq!(r, TransactionValidity::Ok(ValidTransaction::default()));
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
		Failures::<Test>::insert(5, vec![1]);
		let p = PrevalidateRelayer::<Test>::new();
		let c = Call::Relayer(RelayerCall::confirm_done { block_number: 5, failures: vec![] });
		let di = c.get_dispatch_info();
		let r = p.validate(&1, &c, &di, 20);
		r.unwrap()
	});
}

