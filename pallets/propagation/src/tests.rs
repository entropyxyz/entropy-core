use std::sync::Arc;

use entropy_shared::SigRequest;
use frame_support::assert_ok;
use pallet_relayer::Registered;
use sp_core::offchain::{testing, OffchainDbExt, OffchainWorkerExt, TransactionPoolExt};
use sp_io::TestExternalities;
use sp_keystore::{testing::KeyStore, KeystoreExt};

use crate::mock::*;

pub const SIG_HASH: &[u8; 64] = b"d188f0d99145e7ddbd0f1e46e7fd406db927441584571c623aff1d1652e14b06";

#[test]
fn knows_how_to_mock_several_http_calls() {
    let mut t = offchain_worker_env(|state| {
        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/signer/new_party".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [0, 0, 0, 0, 0].to_vec(),
            ..Default::default()
        });

        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/signer/new_party".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [
                8, 1, 1, 100, 49, 56, 56, 102, 48, 100, 57, 57, 49, 52, 53, 101, 55, 100, 100, 98,
                100, 48, 102, 49, 101, 52, 54, 101, 55, 102, 100, 52, 48, 54, 100, 98, 57, 50, 55,
                52, 52, 49, 53, 56, 52, 53, 55, 49, 99, 54, 50, 51, 97, 102, 102, 49, 100, 49, 54,
                53, 50, 101, 49, 52, 98, 48, 54, 32, 1, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
                20, 32, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 40, 32, 8, 0, 0, 0, 0, 0, 0, 0, 1,
                1, 100, 49, 56, 56, 102, 48, 100, 57, 57, 49, 52, 53, 101, 55, 100, 100, 98, 100,
                48, 102, 49, 101, 52, 54, 101, 55, 102, 100, 52, 48, 54, 100, 98, 57, 50, 55, 52,
                52, 49, 53, 56, 52, 53, 55, 49, 99, 54, 50, 51, 97, 102, 102, 49, 100, 49, 54, 53,
                50, 101, 49, 52, 98, 48, 54, 32, 1, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 20, 32,
                7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 40, 32, 8, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0,
            ]
            .to_vec(),
            ..Default::default()
        });
    });

    t.execute_with(|| {
        Propagation::post(1).unwrap();

        System::set_block_number(3);
        let sig_request = SigRequest { sig_hash: SIG_HASH.to_vec() };
        Registered::<Test>::insert(1, true);

        assert_ok!(Relayer::prep_transaction(RuntimeOrigin::signed(1), sig_request.clone()));
        assert_ok!(Relayer::prep_transaction(RuntimeOrigin::signed(1), sig_request));
        // full send
        Propagation::post(4).unwrap();
    })
}

fn offchain_worker_env(state_updater: fn(&mut testing::OffchainState)) -> TestExternalities {
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

    let mut t = new_test_ext();
    t.register_extension(OffchainDbExt::new(offchain.clone()));
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));

    state_updater(&mut offchain_state.write());

    t
}
