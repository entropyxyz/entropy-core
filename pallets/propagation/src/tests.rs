use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok};
use sp_core::offchain::{testing, OffchainDbExt, OffchainWorkerExt, TransactionPoolExt};
// use sp_keystore::{testing::KeyStore, KeystoreExt, SyncCryptoStore};
use parking_lot::RwLock;
use sp_io::TestExternalities;
use std::sync::Arc;

#[test]
fn parse_price_works() {
	let test_data = vec![("{\"demo\":6536}", Some(6536)), ("{\"2\":6536}", None)];

	for (json, expected) in test_data {
		assert_eq!(expected, Propagation::parse_price(json));
	}
}

#[test]
fn knows_how_to_mock_several_http_calls() {
	let (mut t, _) = offchain_worker_env(|state| {
		state.expect_request(testing::PendingRequest {
			method: "GET".into(),
			uri: "http://localhost:3001".into(),
			response: Some(br#"{"demo": 100}"#.to_vec()),
			sent: true,
			..Default::default()
		});

		state.expect_request(testing::PendingRequest {
			method: "GET".into(),
			uri: "http://localhost:3001".into(),
			response: Some(br#"{"demo": 200}"#.to_vec()),
			sent: true,
			..Default::default()
		});

		state.expect_request(testing::PendingRequest {
			method: "GET".into(),
			uri: "http://localhost:3001".into(),
			response: Some(br#"{"demo": 300}"#.to_vec()),
			sent: true,
			..Default::default()
		});
	});

	t.execute_with(|| {
		let data1 = Propagation::get().unwrap();
		let data2 = Propagation::get().unwrap();
		let data3 = Propagation::get().unwrap();

		assert_eq!(data1, 100);
		assert_eq!(data2, 200);
		assert_eq!(data3, 300);
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
