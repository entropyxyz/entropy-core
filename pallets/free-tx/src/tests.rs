use frame_support::{assert_err, assert_ok};
use mock::{
  start_active_era, Call, Event as TestEvent, ExtBuilder, FreeTx, Origin, System, SystemCall, Test,
};
use sp_runtime::{DispatchError, ModuleError};

use super::*;

#[test]
fn try_free_call_works() {
  ExtBuilder::default().build_and_execute(|| {
    // must be in an era for free calls to be enabled
    start_active_era(1);
    // enable free calls (1 free call per era)
    FreeCallsPerEra::<Test>::put(1 as FreeCallCount);

    // Dispatch a free call
    let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
    assert_ok!(FreeTx::try_free_call(Origin::signed(1), call));

    // Make sure the free call succeeded and event was emitted without an error
    System::assert_has_event(TestEvent::FreeTx(Event::FreeCallIssued(1, Ok(()))));
  });
}

#[test]
fn try_free_call_errors_when_child_call_errors() {
  ExtBuilder::default().build_and_execute(|| {
    // must be in an era for free calls to be enabled
    start_active_era(1);
    // enable free calls (1 free call per era)
    FreeCallsPerEra::<Test>::put(1 as FreeCallCount);

    // this call will throw an error
    let call = Box::new(Call::System(SystemCall::kill_storage {
      keys: vec![b"this call will fail".to_vec()],
    }));
    let expected_error = DispatchError::BadOrigin;

    // Make sure try_free_call returns child call error to user
    assert_err!(FreeTx::try_free_call(Origin::signed(1), call), expected_error);

    // Make sure emitted event also contains the child error
    System::assert_has_event(TestEvent::FreeTx(Event::FreeCallIssued(1, Err(expected_error))));
  });
}

#[test]
fn try_free_call_errors_when_no_free_calls_left() {
  ExtBuilder::default().build_and_execute(|| {
    // must be in an era for free calls to be enabled
    start_active_era(1);
    // enable free calls (1 free call per era)
    FreeCallsPerEra::<Test>::put(1 as FreeCallCount);

    // user gets 1 free call by default, lets use it
    let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
    assert_ok!(FreeTx::try_free_call(Origin::signed(1), call));

    // Make sure the child call worked
    System::assert_last_event(TestEvent::FreeTx(Event::FreeCallIssued(1, Ok(()))));

    // try to do another free call when user has no free calls left
    let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));

    // make sure it fails bc no free calls left
    let expected_error = DispatchError::Module(ModuleError {
      index:   8,
      error:   [1, 0, 0, 0],
      message: Some("NoFreeCallsAvailable"),
    });
    assert_err!(FreeTx::try_free_call(Origin::signed(1), call), expected_error);
  });
}

#[test]
fn try_free_call_still_consumes_a_free_call_on_child_fail() {
  ExtBuilder::default().build_and_execute(|| {
    // must be in an era for free calls to be enabled
    start_active_era(1);
    // enable free calls (1 free call per era)
    FreeCallsPerEra::<Test>::put(1 as FreeCallCount);

    // user gets 1 free call by default
    assert_eq!(FreeTx::free_calls_remaining(&1u64), 1 as FreeCallCount);

    // choose a child call that will fail
    let call = Box::new(Call::System(SystemCall::kill_storage {
      keys: vec![b"this call will fail".to_vec()],
    }));

    // Make sure try_free_call fails only bc child fails, not because user has no free calls left
    let expected_child_error = DispatchError::BadOrigin;
    assert_err!(FreeTx::try_free_call(Origin::signed(1), call), expected_child_error);

    // make sure free call was still consumed
    assert_eq!(FreeTx::free_calls_remaining(&1u64), 0 as FreeCallCount);
  });
}

#[test]
fn free_calls_refresh_every_era() {
  ExtBuilder::default().build_and_execute(|| {
    // must be in an era for free calls to be enabled
    start_active_era(1);

    // enable free calls via extrinsic
    let _ = FreeTx::set_free_calls_per_era(Origin::root(), 5);
    assert_eq!(FreeTx::free_calls_remaining(&1u64), 5 as FreeCallCount);

    // make a call that works, check call is used
    let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
    assert_ok!(FreeTx::try_free_call(Origin::signed(1), call));
    assert_eq!(FreeTx::free_calls_remaining(&1u64), 4 as FreeCallCount);

    // start a new era
    start_active_era(2);

    // make sure call count is refreshed
    assert_eq!(FreeTx::free_calls_remaining(&1u64), 5 as FreeCallCount);
  });
}

#[test]
fn free_calls_disabled_by_default() {
  ExtBuilder::default().build_and_execute(|| {
    // must be in an era for free calls to be enabled
    start_active_era(1);

    // make sure we have no free calls
    assert_eq!(FreeTx::free_calls_remaining(&1u64), 0 as FreeCallCount);

    // make sure it fails bc free calls are disabled
    let call = Box::new(Call::System(SystemCall::remark { remark: b"entropy rocks2".to_vec() }));
    let expected_error = DispatchError::Module(ModuleError {
      index:   8,
      error:   [0, 0, 0, 0],
      message: Some("FreeCallsDisabled"),
    });
    assert_err!(FreeTx::try_free_call(Origin::signed(1), call), expected_error);
  });
}
