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

use entropy_shared::QuoteInputData;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_support::BoundedVec;
use frame_system::{EventRecord, RawOrigin};
use pallet_staking_extension::{ServerInfo, ThresholdServers, ThresholdToStash};

use super::*;
#[allow(unused)]
use crate::Pallet as AttestationPallet;

/// This is a randomly generated secret p256 ECDSA key - for mocking attestation
const ATTESTATION_KEY: [u8; 32] = [
    167, 184, 203, 130, 240, 249, 191, 129, 206, 9, 200, 29, 99, 197, 64, 81, 135, 166, 59, 73, 31,
    27, 206, 207, 69, 248, 56, 195, 64, 92, 109, 46,
];

/// This is a randomly generated secret p256 ECDSA key - for mocking the provisioning certification
/// key
const PCK: [u8; 32] = [
    117, 153, 212, 7, 220, 16, 181, 32, 110, 138, 4, 68, 208, 37, 104, 54, 1, 110, 232, 207, 100,
    168, 16, 99, 66, 83, 21, 178, 81, 155, 132, 37,
];

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

benchmarks! {
  attest {
    let attestee: T::AccountId = whitelisted_caller();
    let nonce = [0; 32];

    let attestation_key = tdx_quote::SigningKey::from_bytes(&ATTESTATION_KEY.into()).unwrap();
    let pck = tdx_quote::SigningKey::from_bytes(&PCK.into()).unwrap();
    let pck_encoded = tdx_quote::encode_verifying_key(pck.verifying_key()).unwrap();

    let input_data = QuoteInputData::new(
        &attestee, // TSS Account ID
        [0; 32], // x25519 public key
        nonce,
        1, // Block number
    );
    let quote = tdx_quote::Quote::mock(attestation_key.clone(), pck, input_data.0).as_bytes().to_vec();

    // Insert a pending attestation so that this quote is expected
    <PendingAttestations<T>>::insert(attestee.clone(), nonce);

    let stash_account = <T as pallet_session::Config>::ValidatorId::try_from(attestee.clone())
        .or(Err(()))
        .unwrap();

    <ThresholdToStash<T>>::insert(attestee.clone(), stash_account.clone());
    <ThresholdServers<T>>::insert(stash_account.clone(), ServerInfo {
        tss_account: attestee.clone(),
        x25519_public_key: [0; 32],
        endpoint: b"http://localhost:3001".to_vec(),
        provisioning_certification_key: BoundedVec::from(pck_encoded.to_vec()),
    });

  }: _(RawOrigin::Signed(attestee.clone()), quote.clone())
  verify {
    assert_last_event::<T>(
        Event::<T>::AttestationMade.into()
    );
    // Check that there is no longer a pending attestation
    assert!(!<PendingAttestations<T>>::contains_key(attestee));
  }
}

impl_benchmark_test_suite!(AttestationPallet, crate::mock::new_test_ext(), crate::mock::Test);
