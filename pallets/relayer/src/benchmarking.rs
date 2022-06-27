//! Benchmarking setup for pallet-propgation

use super::*;

#[allow(unused)]
use crate::Pallet as Relayer;
use frame_benchmarking::{benchmarks, impl_benchmark_test_suite, whitelisted_caller};
use frame_system::{RawOrigin, EventRecord};

fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
	let events = frame_system::Pallet::<T>::events();
	let system_event: <T as frame_system::Config>::Event = generic_event.into();
	// compare to the last event record
	let EventRecord { event, .. } = &events[events.len() - 1];
	assert_eq!(event, &system_event);
}

benchmarks! {
	prep_transaction {
		let caller: T::AccountId = whitelisted_caller();
		<Registered<T>>::insert(caller.clone(), true);
		let sig_request = SigRequest { sig_id: 1u16, nonce: 1u32, signature: 1u32 };

	}: _(RawOrigin::Signed(caller.clone()), sig_request)
	verify {
		assert_last_event::<T>(Event::TransactionPropagated(caller).into());
	}

}

impl_benchmark_test_suite!(Relayer, crate::mock::new_test_ext(), crate::mock::Test);
