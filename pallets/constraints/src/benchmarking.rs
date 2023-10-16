//! Benchmarking setup for pallet-propgation

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller, Vec};
use frame_support::traits::{Currency, Get};
use frame_system::{EventRecord, RawOrigin};
use sp_runtime::Saturating;

use super::*;
use crate::pallet::{Acl, Constraints};
#[allow(unused)]
use crate::Pallet as ConstraintsPallet;

type CurrencyOf<T> = <T as Config>::Currency;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

benchmarks! {

  update_constraints {
    let constraint = vec![10];
    let constraint_account: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

    let value = CurrencyOf::<T>::minimum_balance().saturating_mul(1_000_000_000u32.into());
    let _ = CurrencyOf::<T>::make_free_balance_be(&constraint_account, value);

    <AllowedToModifyConstraints<T>>::insert(constraint_account.clone(), sig_req_account.clone(), ());
  }: _(RawOrigin::Signed(constraint_account.clone()), sig_req_account, constraint.clone())
  verify {
    assert_last_event::<T>(Event::<T>::ConstraintsUpdated(constraint_account, constraint).into());
  }
}

impl_benchmark_test_suite!(ConstraintsPallet, crate::mock::new_test_ext(), crate::mock::Test);
