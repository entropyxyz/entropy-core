use crate::mock::*;
use frame_support::{assert_ok, traits::Currency};
use pallet_relayer::SigRequest;
use parking_lot::RwLock;
use sp_core::offchain::{testing, OffchainDbExt, OffchainWorkerExt, TransactionPoolExt};
use sp_io::TestExternalities;
use std::sync::Arc;
use sp_keystore::{testing::KeyStore, KeystoreExt, SyncCryptoStore};

#[test]
fn knows_how_to_mock_several_http_calls() {
	let (mut t, _) = offchain_worker_env(|state| {
		state.expect_request(testing::PendingRequest {
			method: "POST".into(),
			uri: "http://localhost:3001/sign".into(),
			headers: [("Content-Type".into(), "application/x-parity-scale-codec".into())].to_vec(),
			sent: true,
			response: Some([].to_vec()),
			body: [32, 11, 0, 0, 0, 0, 0, 0, 0, 8, 4, 20, 4, 0, 132, 0, 6, 196, 28, 36, 60, 116, 41, 76, 197, 21, 40, 124, 17, 142, 128, 189, 115, 168, 219, 199, 151, 158, 208, 8, 177, 131, 105, 116, 42, 17, 129, 26].to_vec(),
			..Default::default()
		});

		state.expect_request(testing::PendingRequest {
			method: "POST".into(),
			uri: "http://localhost:3001/sign".into(),
			headers: [("Content-Type".into(), "application/x-parity-scale-codec".into())].to_vec(),
			sent: true,
			response: Some([].to_vec()),
			body: [32, 11, 0, 0, 0, 0, 0, 0, 0, 8, 4, 20, 44, 4, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 132, 0, 6, 196, 28, 36, 60, 116, 41, 76, 197, 21, 40, 124, 17, 142, 128, 189, 115, 168, 219, 199, 151, 158, 208, 8, 177, 131, 105, 116, 42, 17, 129, 26]
				.to_vec(),
			..Default::default()
		});
	});

	t.execute_with(|| {
		Balances::make_free_balance_be(&2, 100);
		// handles no endpoint
		let _data1 = Propagation::post(1).unwrap();

		assert_ok!(FrameStaking::bond(
			Origin::signed(2),
			11,
			100u64,
			pallet_staking::RewardDestination::Account(1),
		));

		assert_ok!(Staking::validate(
			Origin::signed(11),
			pallet_staking::ValidatorPrefs::default(),
			vec![20]
		));
		System::set_block_number(2);
		// no messages
		let data2 = Propagation::post(2).unwrap();

		System::set_block_number(3);
		let sig_request = SigRequest { sig_id: 1u16, nonce: 1u32, signature: 1u32 };

		assert_ok!(Relayer::prep_transaction(Origin::signed(1), sig_request));
		// full send
		let data3 = Propagation::post(4).unwrap();

		assert_eq!(data2, ());
		assert_eq!(data3, ());
	})
}

fn offchain_worker_env(
	state_updater: fn(&mut testing::OffchainState),
) -> (TestExternalities, Arc<RwLock<testing::PoolState>>) {
	const PHRASE: &str =
		"news slush supreme milk chapter athlete soap sausage put clutch what kitten";

	let (offchain, offchain_state) = testing::TestOffchainExt::new();
	let (pool, pool_state) = testing::TestTransactionPoolExt::new();
	let keystore = KeyStore::new();
	SyncCryptoStore::sr25519_generate_new(
		&keystore,
		sp_application_crypto::key_types::BABE,
		Some(&format!("{}/hunter1", PHRASE)),
	)
	.unwrap();

	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainDbExt::new(offchain.clone()));
	t.register_extension(OffchainWorkerExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));
	t.register_extension(KeystoreExt(Arc::new(keystore)));

	state_updater(&mut offchain_state.write());

	(t, pool_state)
}
