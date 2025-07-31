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

use entropy_shared::attestation::QuoteContext;
use frame_benchmarking::v2::*;
use frame_system::{EventRecord, RawOrigin};
use rand::{rngs::StdRng, SeedableRng};
use sp_std::vec;

use super::*;
#[allow(unused)]
use crate::Pallet as Forest;

const NULL_ARR: [u8; 32] = [0; 32];

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

#[benchmarks(where T: pallet_attestation::Config)]
mod benchmarks {
    use super::*;
    #[benchmark]
    fn add_tree() {
        let caller: T::AccountId = whitelisted_caller();
        let x25519_public_key = NULL_ARR;
        let nonce = [0; 32];
        let endpoint = vec![];

        <pallet_attestation::GlobalNonces<T>>::put(vec![nonce]);

        let tdx_quote = prepare_attestation_for_validate::<T>(
            caller.clone(),
            x25519_public_key,
            QuoteContext::ForestAddTree,
        );

        let server_info = ForestServerInfo { x25519_public_key, endpoint, tdx_quote };

        #[extrinsic_call]
        _(RawOrigin::Signed(caller.clone()), server_info.clone(), nonce);

        let _tree_info = Trees::<T>::get(caller.clone()).unwrap();

        assert_last_event::<T>(Event::<T>::TreeAdded { tree_account: caller, server_info }.into());
    }
    impl_benchmark_test_suite!(Forest, crate::mock::new_test_ext(), crate::mock::Test);
}

// TODO deduplicate from staking extension pallet benchmarking
/// Sets up a mock quote and requests an attestation in preparation for calling the `validate`
/// extrinsic
fn prepare_attestation_for_validate<T: Config>(
    account: T::AccountId,
    x25519_public_key: [u8; 32],
    quote_context: QuoteContext,
) -> Vec<u8> {
    let nonce = NULL_ARR;
    let quote = {
        let pck = signing_key_from_seed(NULL_ARR);
        /// This is a randomly generated secret p256 ECDSA key - for mocking attestation
        const ATTESTATION_KEY: [u8; 32] = [
            167, 184, 203, 130, 240, 249, 191, 129, 206, 9, 200, 29, 99, 197, 64, 81, 135, 166, 59,
            73, 31, 27, 206, 207, 69, 248, 56, 195, 64, 92, 109, 46,
        ];

        let attestation_key = tdx_quote::SigningKey::from_bytes(&ATTESTATION_KEY.into()).unwrap();

        let input_data = entropy_shared::attestation::QuoteInputData::new(
            &account,
            x25519_public_key,
            nonce,
            quote_context,
        );
        let pck_encoded = tdx_quote::encode_verifying_key(pck.verifying_key()).unwrap();
        tdx_quote::Quote::mock(attestation_key.clone(), pck, input_data.0, pck_encoded.to_vec())
            .as_bytes()
            .to_vec()
    };

    // We need to tell the attestation handler that we want a quote. This will let the system to
    // know to expect one back.
    T::AttestationHandler::request_quote(&account, nonce);
    quote
}

fn signing_key_from_seed(input: [u8; 32]) -> tdx_quote::SigningKey {
    let mut pck_seeder = StdRng::from_seed(input);
    tdx_quote::SigningKey::random(&mut pck_seeder)
}
