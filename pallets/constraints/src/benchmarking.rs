//! Benchmarking setup for pallet-propgation

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};

use super::*;
#[allow(unused)]
use crate::Pallet as ConstraintsPallet;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

benchmarks! {

  update_constraints {
    // number of addresses in the ACL
    let a in 0 .. 24;

    let constraint_account: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

    let initial_constraints = Constraints::default();

    // give permission to update constraints for Arch::Generic
    <AllowedToModifyConstraints<T>>::insert(constraint_account.clone(), sig_req_account.clone(), ());
  }: _(RawOrigin::Signed(constraint_account.clone()), sig_req_account.clone(), initial_constraints.clone())
  verify {
    assert_last_event::<T>(Event::<T>::ConstraintsUpdated(constraint_account, initial_constraints).into());
  }

}

impl_benchmark_test_suite!(ConstraintsPallet, crate::mock::new_test_ext(), crate::mock::Test);
