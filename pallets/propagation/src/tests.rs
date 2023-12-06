use std::sync::Arc;

use codec::Encode;
use entropy_shared::{KeyVisibility, ValidatorInfo};
use frame_support::{assert_ok, traits::OnInitialize};
use pallet_programs::ProgramInfo;
use pallet_staking_extension::RefreshInfo;
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
            body: [
                0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 10, 32, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
                11, 32, 4, 0, 0, 0, 0, 0, 0, 0,
            ]
            .to_vec(),
            ..Default::default()
        });
        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/user/new".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [
                3, 0, 0, 0, 8, 32, 1, 0, 0, 0, 0, 0, 0, 0, 32, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 4, 20, 32, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 40, 32, 8, 0, 0, 0, 0, 0, 0,
                0,
            ]
            .to_vec(),
            ..Default::default()
        });
        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/signer/proactive_refresh".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [
                4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 20, 16, 116, 101, 115, 116, 20, 16, 116, 101, 115, 116, 0, 0, 0, 0,
            ]
            .to_vec(),
            ..Default::default()
        });
    });

    t.execute_with(|| {
        Propagation::post_dkg(1).unwrap();

        System::set_block_number(3);
        pallet_programs::Bytecode::<Test>::insert(
            <Test as frame_system::Config>::Hash::default(),
            ProgramInfo { bytecode: vec![], program_modification_account: 1 },
        );
        assert_ok!(Relayer::register(
            RuntimeOrigin::signed(1),
            2,
            KeyVisibility::Public,
            <Test as frame_system::Config>::Hash::default(),
        ));
        assert_ok!(Relayer::register(
            RuntimeOrigin::signed(2),
            3,
            KeyVisibility::Public,
            <Test as frame_system::Config>::Hash::default(),
        ));
        // full send
        Propagation::post_dkg(4).unwrap();
        // test pruning
        assert_eq!(Relayer::dkg(3).len(), 2);
        Propagation::on_initialize(5);
        assert_eq!(Relayer::dkg(3).len(), 0);

        Propagation::post_proactive_refresh(6).unwrap();
        let ocw_message = RefreshInfo {
            validators_info: vec![ValidatorInfo {
                x25519_public_key: [0u8; 32],
                ip_address: "test".encode(),
                tss_account: "test".encode(),
            }],
            refreshes_done: 0,
        };
        pallet_staking_extension::ProactiveRefresh::<Test>::put(ocw_message);
        Propagation::post_proactive_refresh(6).unwrap();
        Propagation::on_initialize(6);
        assert_eq!(Staking::proactive_refresh(), RefreshInfo::default());
    })
}

fn offchain_worker_env(state_updater: fn(&mut testing::OffchainState)) -> TestExternalities {
    let (offchain, offchain_state) = testing::TestOffchainExt::new();
    let (pool, _pool_state) = testing::TestTransactionPoolExt::new();
    let keystore = MemoryKeystore::new();

    let mut t = new_test_ext();
    t.register_extension(OffchainDbExt::new(offchain.clone()));
    t.register_extension(OffchainWorkerExt::new(offchain));
    t.register_extension(TransactionPoolExt::new(pool));
    t.register_extension(KeystoreExt(Arc::new(keystore)));

    state_updater(&mut offchain_state.write());

    t
}
