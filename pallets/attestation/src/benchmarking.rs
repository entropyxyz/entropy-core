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

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};

use super::*;
#[allow(unused)]
use crate::Pallet as AttestationPallet;

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
    let quote = [0; 32].to_vec();
  }: _(RawOrigin::Signed(attestee.clone()), quote.clone())
  verify {
    assert_last_event::<T>(
        Event::<T>::AttestationMade.into()
    );

    // Check that there is no longer a pending attestation
    assert!(!<PendingAttestations<T>>::contains_key(attestee));
  }

  request_attestation {
    let attestee: T::AccountId = whitelisted_caller();
  }: _(RawOrigin::Signed(attestee.clone()))
  verify {
    // We're expecting a pending attestation queued up
    assert!(<PendingAttestations<T>>::contains_key(attestee));
  }
}

impl_benchmark_test_suite!(AttestationPallet, crate::mock::new_test_ext(), crate::mock::Test);
