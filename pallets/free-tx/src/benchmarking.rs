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

//! Benchmarking setup for pallet-free-tx
#![cfg(feature = "runtime-benchmarks")]

use frame_benchmarking::{benchmarks, whitelisted_caller};
use frame_support::{assert_ok, traits::EnsureOrigin};
use frame_system::RawOrigin;
use sp_std::prelude::Box;

use super::*;
#[allow(unused)]
use crate::Pallet as FreeTx;

benchmarks! {

  // TODO JH: include both battery and zap consumption paths as each will have different weights
  call_using_electricity {
    let caller: T::AccountId = whitelisted_caller();

    <ElectricalAccount<T>>::insert(
      caller.clone(),
      ElectricalPanel {
          batteries: 1,
          zaps: 0,
          used: ElectricityMeter { latest_era: 0, count: 0 },
      },
  );

    let call: <T as Config>::RuntimeCall = frame_system::Call::<T>::remark { remark: b"entropy rocks".to_vec() }.into();
  }: _(RawOrigin::Signed(caller.clone()), Box::new(call))
  verify {
    assert!(<ElectricalAccount<T>>::get(caller).unwrap().used.count == 1);
  }
  set_individual_electricity_era_limit {
    let origin = T::UpdateOrigin::try_successful_origin().unwrap();
    let cells = 5 as Cells;
  }: {
    assert_ok!(
      <FreeTx<T>>::set_individual_electricity_era_limit(origin, Some(cells))
    );
  }
  verify {
    assert_eq!(MaxUserElectricityUsagePerEra::<T>::get().unwrap(), cells as Cells);
  }
  set_battery_count {
    let origin = T::UpdateOrigin::try_successful_origin().unwrap();
    let whitelisted_caller: T::AccountId = whitelisted_caller();
    let cells = 5 as Cells;
  }: {
    assert_ok!(
      <FreeTx<T>>::set_battery_count(origin, whitelisted_caller.clone(), cells)
    );
  }
  verify {
    assert_eq!(ElectricalAccount::<T>::get(whitelisted_caller).unwrap().batteries, cells as Cells);
  }
  give_zaps{
    let origin = T::UpdateOrigin::try_successful_origin().unwrap();
    let whitelisted_caller: T::AccountId = whitelisted_caller();
    let cells = 5 as Cells;
  }: {
    assert_ok!(
      <FreeTx<T>>::give_zaps(origin, whitelisted_caller.clone(), cells)
    );
  }
  verify {
    assert_eq!(ElectricalAccount::<T>::get(whitelisted_caller).unwrap().zaps, cells as Cells);
  }
}
