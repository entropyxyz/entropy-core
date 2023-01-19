//! Benchmarking setup for pallet-propgation

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_support::traits::Get;
use frame_system::{EventRecord, RawOrigin};
#[allow(unused)]
use sp_std::vec::Vec;

use super::*;
use crate::pallet::{Acl, Constraints, H160, H256};
#[allow(unused)]
use crate::Pallet as ConstraintsPallet;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

/// Generates a set of constraints fit to the specified storage complexity parameters
pub fn generate_benchmarking_constraints<T: Config>(
    evm_acl_len: u32,
    btc_acl_len: u32,
) -> Constraints {
    let mut evm_acl = Acl::<H160>::default();
    let mut btc_acl = Acl::<H256>::default();

    evm_acl.addresses = (0..evm_acl_len).map(|_| H160::default()).collect::<Vec<_>>();
    btc_acl.addresses = (0..btc_acl_len).map(|_| H256::default()).collect::<Vec<_>>();

    Constraints { evm_acl: Some(evm_acl), btc_acl: Some(btc_acl) }
}

benchmarks! {

  update_constraints {
    // number of addresses in the ACL
    let a in 0 .. <T as crate::Config>::MaxAclLength::get();
    let b in 0 .. <T as crate::Config>::MaxAclLength::get();
    let constraints = generate_benchmarking_constraints::<T>(a, b);

    let constraint_account: T::AccountId = whitelisted_caller();
    let sig_req_account: T::AccountId = whitelisted_caller();

    <AllowedToModifyConstraints<T>>::insert(constraint_account.clone(), sig_req_account.clone(), ());
  }: _(RawOrigin::Signed(constraint_account.clone()), sig_req_account.clone(), constraints.clone())
  verify {
    assert_last_event::<T>(Event::<T>::ConstraintsUpdated(constraint_account, constraints).into());
  }

}

impl_benchmark_test_suite!(ConstraintsPallet, crate::mock::new_test_ext(), crate::mock::Test);
