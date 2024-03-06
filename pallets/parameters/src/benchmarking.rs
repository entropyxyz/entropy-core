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
use frame_support::assert_ok;
use frame_system::EventRecord;
use sp_std::{vec, vec::Vec};

use super::*;
#[allow(unused)]
use crate::Pallet as Parameters;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

benchmarks! {
  change_request_limit {
    let origin = T::UpdateOrigin::try_successful_origin().unwrap();

  }: {
    assert_ok!(
      <Parameters<T>>::change_request_limit(origin, 15)
    );
  }
  verify {
    assert_last_event::<T>(Event::RequestLimitChanged{ request_limit: 15}.into());
  }
  impl_benchmark_test_suite!(Parameters, crate::mock::ExtBuilder::default().build(), crate::mock::Runtime);
}

use frame_benchmarking::benchmarks;
use frame_support::assert_ok;
use frame_system::EventRecord;

use super::*;
#[allow(unused)]
use crate::Pallet as Parameters;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

benchmarks! {
  change_request_limit {
    let origin = T::UpdateOrigin::try_successful_origin().unwrap();

  }: {
    assert_ok!(
      <Parameters<T>>::change_request_limit(origin, 15)
    );
  }
  verify {
    assert_last_event::<T>(Event::RequestLimitChanged{ request_limit: 15}.into());
  }

  impl_benchmark_test_suite!(Parameters, crate::mock::ExtBuilder::default().build(), crate::mock::Runtime);
}
