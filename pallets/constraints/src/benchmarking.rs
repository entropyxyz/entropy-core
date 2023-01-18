//! Benchmarking setup for pallet-propgation

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::{EventRecord, RawOrigin};

use super::*;
use crate::pallet::{Acl, Constraints, H160, H256};
#[allow(unused)]
use crate::Pallet as ConstraintsPallet;
use sp_std::vec::Vec;

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
    let a in 0 .. 20;
    let b in 0 .. 20;

    let constraint_account: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

    // create a new constraints from above ACL counts
    let mut evm_acl = Acl::<H160>::default();
    let mut btc_acl = Acl::<H256>::default();

    evm_acl.addresses = (0..a).map(|_| H160::default()).collect::<Vec<_>>();
    btc_acl.addresses = (0..b).map(|_| H256::default()).collect::<Vec<_>>();

    let mut initial_constraints = Constraints::default();
    initial_constraints.evm_acl = Some(evm_acl);
    initial_constraints.btc_acl = Some(btc_acl);

    // give permission to update constraints for Arch::Generic
    <AllowedToModifyConstraints<T>>::insert(constraint_account.clone(), sig_req_account.clone(), ());
  }: _(RawOrigin::Signed(constraint_account.clone()), sig_req_account.clone(), initial_constraints.clone())
  verify {
    assert_last_event::<T>(Event::<T>::ConstraintsUpdated(constraint_account, initial_constraints).into());
  }

}

impl_benchmark_test_suite!(ConstraintsPallet, crate::mock::new_test_ext(), crate::mock::Test);
