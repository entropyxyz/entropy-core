use std::sync::Arc;

use entropy_shared::KeyVisibility;
use frame_support::assert_ok;
use sp_core::offchain::{testing, OffchainDbExt, OffchainWorkerExt, TransactionPoolExt};
use sp_io::TestExternalities;
use sp_keystore::{testing::MemoryKeystore, KeystoreExt};

use crate::mock::*;

#[test]
fn knows_how_to_mock_several_http_calls() {
    let mut t = offchain_worker_env(|state| {
        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/user/new".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [0, 0, 0, 0, 0].to_vec(),
            ..Default::default()
        });

        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/user/new".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [3, 0, 0, 0, 8, 32, 1, 0, 0, 0, 0, 0, 0, 0, 32, 2, 0, 0, 0, 0, 0, 0, 0].to_vec(),
            ..Default::default()
        });
    });

    t.execute_with(|| {
        Propagation::post(1).unwrap();

        System::set_block_number(3);
        assert_ok!(Relayer::register(RuntimeOrigin::signed(1), 2, KeyVisibility::Public, None));
        assert_ok!(Relayer::register(RuntimeOrigin::signed(2), 3, KeyVisibility::Public, None));
        // full send
        Propagation::post(4).unwrap();
    })
}

fn offchain_worker_env(state_updater: fn(&mut testing::OffchainState)) -> TestExternalities {
    // const PHRASE: &str =
    // 	"news slush supreme milk chapter athlete soap sausage put clutch what kitten";

    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, _pool_state) = testing::TestTransactionPoolExt::new();
    let keystore = MemoryKeystore::new();
    // SyncCryptoStore::sr25519_generate_new(
    // 	&keystore,
    // 	sp_application_crypto::key_types::BABE,
    // 	Some(&format!("{}/hunter1", PHRASE)),
    // )
    // .unwrap();

    let mut t = new_test_ext();
    t.register_extension(OffchainDbExt::new(offchain.clone()));
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));

    state_updater(&mut offchain_state.write());

    t
}
