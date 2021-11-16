use crate as pallet_relayer;
use crate::{mock::*, Message, PrevalidateRelayer};
use frame_support::{
	assert_ok,
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

		assert_eq!(Relayer::messages(), vec![message]);
	});
}

#[test]
fn it_provides_free_txs() {
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
fn it_fails_a_free_tx() {
	new_test_ext().execute_with(|| {
		let p = PrevalidateRelayer::<Test>::new();
		let c = Call::Relayer(RelayerCall::prep_transaction { data_1: 43, data_2: 42 });
		let di = c.get_dispatch_info();
		let r = p.validate(&42, &c, &di, 20);
		assert!(r.is_err());
	});
}
