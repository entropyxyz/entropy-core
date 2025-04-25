// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use frame_benchmarking::v2::*;
use frame_system::EventRecord;

use super::*;
#[allow(unused)]
use crate::Pallet as TransactionPause;

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
    let events = frame_system::Pallet::<T>::events();
    let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len() - 1];
    assert_eq!(event, &system_event);
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn pause_transaction() {
        let origin = T::UpdateOrigin::try_successful_origin().unwrap();

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, b"Balances".to_vec(), b"transfer".to_vec());

        assert_last_event::<T>(
            Event::TransactionPaused {
                pallet_name_bytes: b"Balances".to_vec(),
                function_name_bytes: b"transfer".to_vec(),
            }
            .into(),
        );
    }

    #[benchmark]
    fn unpause_transaction() {
        let origin = T::UpdateOrigin::try_successful_origin().unwrap();
        <TransactionPause<T>>::pause_transaction(
            origin.clone(),
            b"Balances".to_vec(),
            b"transfer".to_vec(),
        )
        .unwrap();

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, b"Balances".to_vec(), b"transfer".to_vec());

        assert_last_event::<T>(
            Event::TransactionUnpaused {
                pallet_name_bytes: b"Balances".to_vec(),
                function_name_bytes: b"transfer".to_vec(),
            }
            .into(),
        );
    }

    impl_benchmark_test_suite!(
        TransactionPause,
        crate::mock::ExtBuilder::default().build(),
        crate::mock::Runtime
    );
}
