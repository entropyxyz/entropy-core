use crate::{mock::*, BlockAuthor};
use frame_support::{assert_ok, traits::OnInitialize};
use pallet_relayer::SigRequest;
use parking_lot::RwLock;
use sp_core::offchain::{testing, OffchainDbExt, OffchainWorkerExt, TransactionPoolExt};
use sp_io::TestExternalities;
use sp_keystore::{testing::KeyStore, KeystoreExt, SyncCryptoStore};
use std::sync::Arc;

#[test]
fn knows_how_to_mock_several_http_calls() {
	let mut t = offchain_worker_env(|state| {
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
			body: [8, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0].to_vec(),
			..Default::default()
		});
	});

	t.execute_with(|| {
		let data1 = Propagation::post(1).unwrap();

		System::set_block_number(3);
		let sig_request = SigRequest { sig_id: 1u16, nonce: 1u32, signature: 1u32 };

		assert_ok!(Relayer::prep_transaction(Origin::signed(1), sig_request.clone()));
		assert_ok!(Relayer::prep_transaction(Origin::signed(1), sig_request));
		// full send
		let data2 = Propagation::post(4).unwrap();

		assert_eq!(data1, ());
		assert_eq!(data2, ());
	})
}

#[test]
fn notes_block_author() {
	new_test_ext().execute_with(|| {
		Propagation::on_initialize(1);
		assert_eq!(Propagation::get_block_author(1), Some(11));

		Propagation::on_initialize(21);
		assert_eq!(Propagation::get_block_author(1), None);
		assert_eq!(Propagation::get_block_author(21), Some(11));
	});
}

fn offchain_worker_env(
	state_updater: fn(&mut testing::OffchainState),
) -> TestExternalities {
	// const PHRASE: &str =
	// 	"news slush supreme milk chapter athlete soap sausage put clutch what kitten";

	let (offchain, offchain_state) = testing::TestOffchainExt::new();
	let (pool, _pool_state) = testing::TestTransactionPoolExt::new();
	let keystore = KeyStore::new();
	// SyncCryptoStore::sr25519_generate_new(
	// 	&keystore,
	// 	sp_application_crypto::key_types::BABE,
	// 	Some(&format!("{}/hunter1", PHRASE)),
	// )
	// .unwrap();

	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainDbExt::new(offchain.clone()));
	t.register_extension(OffchainWorkerExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));
	t.register_extension(KeystoreExt(Arc::new(keystore)));

	state_updater(&mut offchain_state.write());

	t
}
