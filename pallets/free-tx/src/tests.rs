use frame_support::{assert_noop, assert_ok};
use mock::{
    start_active_era, ExtBuilder, FreeTx, RuntimeCall, RuntimeEvent as TestEvent, RuntimeOrigin,
    System, SystemCall, Test,
};
use sp_runtime::{DispatchError, ModuleError};

use super::*;

#[test]
fn call_using_electricity_works() {
    ExtBuilder::default().build_and_execute(|| {
        // must be in an era for free calls to be enabled
        start_active_era(1);
        // enable free calls (1 free call per era)
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 1,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );

        // Dispatch a free call
        let call =
            Box::new(RuntimeCall::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call));

        // Make sure the free call succeeded and event was emitted without an error
        System::assert_has_event(TestEvent::FreeTx(Event::ElectricitySpent(1, Ok(()))));
    });
}

#[test]
fn call_using_electricity_errors_when_child_call_errors() {
    ExtBuilder::default().build_and_execute(|| {
        // must be in an era for free calls to be enabled
        start_active_era(1);

        // enable free calls (1 free call per era)
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 1,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        // this call will throw an error
        let call = Box::new(RuntimeCall::System(SystemCall::kill_storage {
            keys: vec![b"this call will fail".to_vec()],
        }));
        let expected_error = DispatchError::BadOrigin;

        // Make sure call_using_electricity returns child call error to user
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call));

        // Make sure emitted event also contains the child error
        System::assert_has_event(TestEvent::FreeTx(Event::ElectricitySpent(
            1,
            Err(expected_error),
        )));
    });
}

#[test]
fn call_using_electricity_errors_when_no_cells_available() {
    ExtBuilder::default().build_and_execute(|| {
        // must be in an era for free calls to be enabled
        start_active_era(1);
        // enable free calls (1 free call per era)
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 1,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        // user gets 1 free call by default, lets use it
        let call =
            Box::new(RuntimeCall::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call));

        // Make sure the child call worked
        System::assert_last_event(TestEvent::FreeTx(Event::ElectricitySpent(1, Ok(()))));

        // try to do another free call when user has no free calls left
        let call =
            Box::new(RuntimeCall::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));

        // make sure it fails bc no free calls left
        let expected_error = DispatchError::Module(ModuleError {
            index: 8,
            error: [1, 0, 0, 0],
            message: Some("NoCellsAvailable"),
        });
        assert_noop!(
            FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call),
            expected_error
        );
    });
}

#[test]
fn call_using_electricity_still_uses_electricity_on_child_fail() {
    ExtBuilder::default().build_and_execute(|| {
        // must be in an era for free calls to be enabled
        start_active_era(1);
        // give one rechargable
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 1,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        // user gets 1 free call by default
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 1 as Cells);

        // choose a child call that will fail
        let call = Box::new(RuntimeCall::System(SystemCall::kill_storage {
            keys: vec![b"this call will fail".to_vec()],
        }));

        // Make sure call_using_electricity fails only bc child fails, not because user has no free
        // calls left
        let expected_child_error = DispatchError::BadOrigin;

        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call));

        System::assert_has_event(TestEvent::FreeTx(Event::ElectricitySpent(
            1,
            Err(expected_child_error),
        )));

        // make sure free call was still consumed
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 0 as Cells);
    });
}

#[test]
fn batteries_refresh_every_era() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // enable electricity
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 5,
                zaps: 0,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 5 as Cells);

        // make a call that works, check call is used
        let call =
            Box::new(RuntimeCall::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call));
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 4 as Cells);

        // start a new era
        start_active_era(2);

        // make sure call count is refreshed
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 5 as Cells);
    });
}

#[test]
fn one_time_cells_are_consumed_and_not_recharged() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // give some cells
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 0,
                zaps: 5,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 5 as Cells);

        // make a call that works, check call is used
        let call =
            Box::new(RuntimeCall::System(SystemCall::remark { remark: b"entropy rocks".to_vec() }));
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call));
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 4 as Cells);

        // start a new era
        start_active_era(2);

        // make sure call count is refreshed
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 4 as Cells);
    });
}

#[test]
fn user_has_no_free_cells_by_default() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // make sure we have no free calls
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 0 as Cells);

        // make sure it fails bc cells are disabled
        let call = Box::new(RuntimeCall::System(SystemCall::remark {
            remark: b"entropy rocks2".to_vec(),
        }));
        let expected_error = DispatchError::Module(ModuleError {
            index: 8,
            error: [1, 0, 0, 0],
            message: Some("NoCellsAvailable"),
        });
        assert_noop!(
            FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call),
            expected_error
        );
    });
}

// electricity limit works in middle of era
#[test]
fn set_individual_electricity_era_limit_works() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // give 5 batteries
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 0,
                zaps: 3,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 3 as Cells);

        // disable electricity
        FreeTx::set_individual_electricity_era_limit(RuntimeOrigin::signed(1), Some(0)).unwrap();

        // make sure call fails bc electricity is disabled
        let call = Box::new(RuntimeCall::System(SystemCall::remark {
            remark: b"entropy rocks2".to_vec(),
        }));
        assert_noop!(
            FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()),
            DispatchError::Module(ModuleError {
                index: 8,
                error: [0, 0, 0, 0],
                message: Some("ElectricityIsDisabled"),
            })
        );

        // enable electricity usage at 2 cells per user
        FreeTx::set_individual_electricity_era_limit(RuntimeOrigin::signed(1), Some(2)).unwrap();
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 2 as Cells);

        // have user use two cells, then make sure they get an error
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()));
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()));
        assert_noop!(
            FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()),
            DispatchError::Module(ModuleError {
                index: 8,
                error: [2, 0, 0, 0],
                message: Some("ElectricityEraLimitReached"),
            })
        );

        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 0 as Cells);

        // start a new era
        start_active_era(2);

        // cap is 2, but user shuold only have 1 zap left
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 1 as Cells);
    });
}

// one-time cells aren't touched until no more batteries are available
#[test]
fn zaps_arent_used_until_all_batteries_are_used() {
    ExtBuilder::default().build_and_execute(|| {
        start_active_era(1);

        // give some electricity
        ElectricalAccount::<Test>::insert(
            1,
            ElectricalPanel {
                batteries: 2,
                zaps: 5,
                used: ElectricityMeter { latest_era: 0, count: 0 },
            },
        );
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 7 as Cells);

        // use two cells
        let call = Box::new(RuntimeCall::System(SystemCall::remark {
            remark: b"entropy rocks2".to_vec(),
        }));
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()));
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()));

        // make sure user hasn't used any zaps
        let mut expected_balance = ElectricalPanel {
            batteries: 2,
            zaps: 5,
            used: ElectricityMeter { latest_era: 1, count: 2 },
        };
        assert_eq!(ElectricalAccount::<Test>::get(1).unwrap(), expected_balance);

        // doing another call will though:
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()));
        expected_balance.zaps -= 1;
        expected_balance.used.count += 1;
        assert_eq!(ElectricalAccount::<Test>::get(1).unwrap(), expected_balance);
    });
}

// users with no cells get errors
#[test]
fn users_with_no_cells_get_errors() {
    ExtBuilder::default().build_and_execute(|| {
        let call = Box::new(RuntimeCall::System(SystemCall::remark {
            remark: b"entropy rocks2".to_vec(),
        }));
        let no_cells_available_error = DispatchError::Module(ModuleError {
            index: 8,
            error: [1, 0, 0, 0],
            message: Some("NoCellsAvailable"),
        });

        // users by default have no electricity
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 0 as Cells);
        assert_noop!(
            FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()),
            no_cells_available_error
        );

        // give user one zap
        FreeTx::give_zaps(RuntimeOrigin::signed(1), 1, 1).unwrap();

        // make sure after a user uses all their cells, they get an error
        assert_eq!(FreeTx::cells_usable_this_era(&1u64), 1 as Cells);
        assert_ok!(FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()));
        assert_noop!(
            FreeTx::call_using_electricity(RuntimeOrigin::signed(1), call.clone()),
            no_cells_available_error
        );
    });
}
