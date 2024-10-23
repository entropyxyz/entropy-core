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
use frame_support::traits::OnInitialize;
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
                0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 16, 116, 101, 115, 116, 20, 16, 116, 101, 115, 116,
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
        state.expect_request(testing::PendingRequest {
            method: "POST".into(),
            uri: "http://localhost:3001/rotate_network_key".into(),
            sent: true,
            response: Some([].to_vec()),
            body: [10, 0, 0, 0].to_vec(),
            ..Default::default()
        });
    });

    t.execute_with(|| {
        let validators_info = vec![ValidatorInfo {
            x25519_public_key: [0u8; 32],
            ip_address: "test".encode(),
            tss_account: "test".encode(),
        }];
        pallet_registry::JumpstartDkg::<Test>::insert(0, validators_info.clone());

        Propagation::post_dkg(1).unwrap();

        Propagation::post_proactive_refresh(6).unwrap();
        let ocw_message =
            RefreshInfo { validators_info, proactive_refresh_keys: vec![1.encode(), 2.encode()] };
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

        pallet_staking_extension::RotateKeyshares::<Test>::put(10);
        Propagation::post_rotate_network_key(10).unwrap();
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
