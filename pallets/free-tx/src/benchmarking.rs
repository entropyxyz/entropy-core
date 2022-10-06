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

    let call: <T as Config>::Call = frame_system::Call::<T>::remark { remark: b"entropy rocks".to_vec() }.into();
  }: _(RawOrigin::Signed(caller.clone()), Box::new(call))
  verify {
    assert!(<ElectricalAccount<T>>::get(caller).unwrap().used.count == 1);
  }
  set_individual_electricity_era_limit {
    let origin = T::UpdateOrigin::successful_origin();
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
    let origin = T::UpdateOrigin::successful_origin();
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
    let origin = T::UpdateOrigin::successful_origin();
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
