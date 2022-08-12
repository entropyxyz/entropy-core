use frame_benchmarking::benchmarks;
use frame_support::assert_ok;
use frame_system::EventRecord;

use super::*;
#[allow(unused)] use crate::Pallet as TransactionPause;

fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
  let events = frame_system::Pallet::<T>::events();
  let system_event: <T as frame_system::Config>::Event = generic_event.into();
  // compare to the last event record
  let EventRecord { event, .. } = &events[events.len() - 1];
  assert_eq!(event, &system_event);
}

benchmarks! {
  pause_transaction {
    let origin = T::UpdateOrigin::successful_origin();

  }: {
    assert_ok!(
      <TransactionPause<T>>::pause_transaction(origin, b"Balances".to_vec(), b"transfer".to_vec())
    );
  }
  verify {
    assert_last_event::<T>(Event::TransactionPaused{ pallet_name_bytes: b"Balances".to_vec(), function_name_bytes: b"transfer".to_vec()}.into());
  }

  unpause_transaction {
    let origin = T::UpdateOrigin::successful_origin();
    <TransactionPause<T>>::pause_transaction(origin.clone(), b"Balances".to_vec(), b"transfer".to_vec())?;
  }: {
    assert_ok!(
      <TransactionPause<T>>::unpause_transaction(origin, b"Balances".to_vec(), b"transfer".to_vec())
    );
  }
  verify {
    assert_last_event::<T>(Event::TransactionUnpaused{ pallet_name_bytes: b"Balances".to_vec(), function_name_bytes: b"transfer".to_vec()}.into());
  }

  impl_benchmark_test_suite!(TransactionPause, crate::mock::ExtBuilder::default().build(), crate::mock::Runtime);
}
