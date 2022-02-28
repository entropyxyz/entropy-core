use crate::mock::*;
use frame_support::assert_ok;
use pallet_relayer::SigRequest;
use parking_lot::RwLock;
use sp_core::offchain::{testing, OffchainDbExt, OffchainWorkerExt, TransactionPoolExt};
use sp_io::TestExternalities;
use std::sync::Arc;

#[test]
fn knows_how_to_mock_several_http_calls() {
	let (mut t, _) = offchain_worker_env(|state| {
		state.expect_request(testing::PendingRequest {
			method: "POST".into(),
			uri: "http://localhost:3001/sign".into(),
			headers: [("Content-Type".into(), "application/x-parity-scale-codec".into())].to_vec(),
			sent: true,
			response: Some([].to_vec()),
			body: [0].to_vec(),
			..Default::default()
		});

		state.expect_request(testing::PendingRequest {
			method: "POST".into(),
			uri: "http://localhost:3001/sign".into(),
			headers: [("Content-Type".into(), "application/x-parity-scale-codec".into())].to_vec(),
			sent: true,
			response: Some([].to_vec()),
			body: [4, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0].to_vec(),
			..Default::default()
		});
	});

	t.execute_with(|| {
		let data1 = Propagation::post(2).unwrap();

		System::set_block_number(2);
		let sig_request = SigRequest { sig_id: 1u16, nonce: 1u32, signature: 1u32 };

		assert_ok!(Relayer::prep_transaction(Origin::signed(1), sig_request));
		let data2 = Propagation::post(3).unwrap();

		assert_eq!(data1, ());
		assert_eq!(data2, ());
	})
}

fn offchain_worker_env(
	state_updater: fn(&mut testing::OffchainState),
) -> (TestExternalities, Arc<RwLock<testing::PoolState>>) {
	// const PHRASE: &str =
	// 	"news slush supreme milk chapter athlete soap sausage put clutch what kitten";

	let (offchain, offchain_state) = testing::TestOffchainExt::new();
	let (pool, pool_state) = testing::TestTransactionPoolExt::new();
	// let keystore = KeyStore::new();
	// SyncCryptoStore::sr25519_generate_new(
	// 	&keystore,
	// 	crate::crypto::Public::ID,
	// 	Some(&format!("{}/hunter1", PHRASE)),
	// )
	// .unwrap();

	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainDbExt::new(offchain.clone()));
	t.register_extension(OffchainWorkerExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));
	// t.register_extension(KeystoreExt(Arc::new(keystore)));

	state_updater(&mut offchain_state.write());

	(t, pool_state)
}
