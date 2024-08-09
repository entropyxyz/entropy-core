// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::sync::Arc;

use codec::Encode;
use entropy_shared::ValidatorInfo;
use frame_support::{assert_ok, traits::OnInitialize, BoundedVec};
use pallet_programs::ProgramInfo;
use pallet_registry::ProgramInstance;
use pallet_staking_extension::{RefreshInfo, ReshareInfo};
use sp_core::offchain::{testing, OffchainDbExt, OffchainWorkerExt, TransactionPoolExt};
use sp_io::TestExternalities;
use sp_keystore::{testing::MemoryKeystore, KeystoreExt};

use crate::mock::*;

#[test]
fn knows_how_to_mock_several_http_calls() {
    let mut t = offchain_worker_env(|state| {
        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/generate_network_key".into(),
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
            uri: "http://localhost:3001/generate_network_key".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [
                3, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 10, 32, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
                11, 32, 4, 0, 0, 0, 0, 0, 0, 0,
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
                5, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 16, 116, 101, 115, 116, 20, 16, 116, 101, 115, 116,
                8, 16, 1, 0, 0, 0, 16, 2, 0, 0, 0,
            ]
            .to_vec(),
            ..Default::default()
        });
        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/validator/reshare".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [32, 1, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0].to_vec(),
            ..Default::default()
        });
    });

    t.execute_with(|| {
        Propagation::post_dkg(1).unwrap();

        System::set_block_number(3);
        pallet_programs::Programs::<Test>::insert(
            <Test as frame_system::Config>::Hash::default(),
            ProgramInfo {
                bytecode: vec![],
                configuration_schema: vec![],
                auxiliary_data_schema: vec![],
                oracle_data_pointer: vec![],
                deployer: 1,
                ref_counter: 0,
            },
        );

        let programs_info = BoundedVec::try_from(vec![ProgramInstance {
            program_pointer: <Test as frame_system::Config>::Hash::default(),
            program_config: vec![],
        }])
        .unwrap();
        assert_ok!(Registry::register(RuntimeOrigin::signed(1), 2, programs_info.clone(),));
        assert_ok!(Registry::register(RuntimeOrigin::signed(2), 3, programs_info,));

        // full send
        Propagation::post_dkg(4).unwrap();

        // test pruning
        assert_eq!(Registry::dkg(3).len(), 2);
        Propagation::on_initialize(5);
        assert_eq!(Registry::dkg(3).len(), 0);

        Propagation::post_proactive_refresh(6).unwrap();
        let ocw_message = RefreshInfo {
            validators_info: vec![ValidatorInfo {
                x25519_public_key: [0u8; 32],
                ip_address: "test".encode(),
                tss_account: "test".encode(),
            }],
            proactive_refresh_keys: vec![1.encode(), 2.encode()],
        };
        pallet_staking_extension::ProactiveRefresh::<Test>::put(ocw_message);
        Propagation::post_proactive_refresh(6).unwrap();
        Propagation::on_initialize(6);
        assert_eq!(Staking::proactive_refresh(), RefreshInfo::default());

        // doesn't trigger no reshare block
        Propagation::post_reshare(7).unwrap();
        pallet_staking_extension::ReshareData::<Test>::put(ReshareInfo {
            block_number: 7,
            new_signer: 1u64.encode(),
        });
        // now triggers
        Propagation::post_reshare(7).unwrap();
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
