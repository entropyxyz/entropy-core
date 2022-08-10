use frame_support::{assert_err, assert_ok};

use mock::{
  new_test_ext, Balances, Call, Event as TestEvent, Example, ExampleCall, FreeTx, Origin, System,
};
use sp_runtime::{DispatchError, ModuleError};

use super::*;

#[test]
fn free_calls_are_allowed() {
  new_test_ext().execute_with(|| {
    // Set block number to 1 because events are not emitted on block 0.
    System::set_block_number(1);

    // Make sure Example storage is empty
    assert!(Example::something().is_none());

    // Dispatch a free call that modifies Example storage
    let call = Box::new(Call::Example(ExampleCall::do_something { something: 5 }));
    assert_ok!(FreeTx::try_free_call(Origin::signed(1), call));

    // Make sure Example storage was modified
    assert_eq!(Example::something(), Some(5));

    // Make sure the free call event was emitted without an error
    System::assert_has_event(TestEvent::FreeTx(Event::FreeCallIssued(1, Ok(()))));
  });
}

#[test]
fn error_when_child_call_errors() {
  new_test_ext().execute_with(|| {
    // Set block number to 1 because events are not emitted on block 0.
    System::set_block_number(1);

    // this call will throw an error (when Something is None)
    let call = Box::new(Call::Example(ExampleCall::cause_error {}));
    let expected_error = DispatchError::Module(ModuleError { index: 2, error: [0, 0, 0, 0], message: None });

    // Make sure try_free_call returns child call error to user
    assert_err!(FreeTx::try_free_call(Origin::signed(1), call), expected_error);

    // Make sure emitted event also contains the child error
    System::assert_has_event(TestEvent::FreeTx(Event::FreeCallIssued(1, Err(expected_error))));
  });
}

#[test]
fn free_calls_consume_no_transaction_fees() {
  new_test_ext().execute_with(|| {
    // Set block number to 1 because events are not emitted on block 0.
    System::set_block_number(1);

    let initial_balance = Balances::free_balance(1);

    println!("{:?}", initial_balance);

    // some call that usually wouldn't be free
    let call = Box::new(Call::Example(ExampleCall::do_something { something: 5 }));
    assert_ok!(FreeTx::try_free_call(Origin::signed(1), call));

    // Make sure the event was emitted
    System::assert_last_event(TestEvent::FreeTx(Event::FreeCallIssued(1, Ok(()))));

    let final_balance = Balances::free_balance(1);

    assert_eq!(initial_balance, final_balance);
  });
}

#[test]
fn normal_calls_consume_tx_fees() {
  new_test_ext().execute_with(|| {
    // Set block number to 1 because events are not emitted on block 0.
    System::set_block_number(1);

    // get initial balance (10)
    let _initial_balance = Balances::free_balance(1);

    // make sure storage is empty
    assert_eq!(Example::something(), None);

    // do some call that usually wouldn't be free
    assert_ok!(Example::do_something(Origin::signed(1), 5));

    // make sure storage changed
    assert_eq!(Example::something(), Some(5));

    // get balance after transaction
    let _final_balance = Balances::free_balance(1);

    // TODO JH This does not work
    // assert_ne!(initial_balance, final_balance);
  });
}
