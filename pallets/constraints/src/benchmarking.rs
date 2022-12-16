//! Benchmarking setup for pallet-propgation

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, vec, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};
use substrate_common::Arch;

use super::*;
#[allow(unused)]
use crate::Pallet as Constraints;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

benchmarks! {

  update_acl {
    // number of addresses in the ACL
    let a in 0 .. 24;

    let constraint_account: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

    let addresses = vec![H160::default(); a as usize];
    let initial_acl = Acl::<H160>::try_from(addresses.clone()).unwrap();

    // give permission to update constraints for Arch::Generic
    <SigReqAccounts<T>>::insert(constraint_account.clone(), sig_req_account.clone(), ());
  }: _(RawOrigin::Signed(constraint_account.clone()), sig_req_account.clone(), Arch::Generic, Some(initial_acl.clone()))
  verify {
    assert_last_event::<T>(Event::<T>::AclUpdated(constraint_account, Arch::Generic).into());
  }

}

impl_benchmark_test_suite!(Constraints, crate::mock::new_test_ext(), crate::mock::Test);
